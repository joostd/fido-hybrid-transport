#!/usr/bin/python

# FIDO CDA Authenticator using CTAP hybrid transport
# https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hybrid

import sys
import os
import json
import datetime
import asyncio
import threading
import hmac
import hashlib
import secrets
import ssl
import struct

from cbor2 import loads, dumps

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, load_pem_private_key,
)

from websockets import serve

# BLE
import dbus
import dbus.exceptions
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

from cable_noise import (
    NoiseHandshake, KeyPair, generate_keypair,
    deserialize_public_key_compressed, serialize_public_key,
    pad_message, unpad_message,
    PATTERN_KN_PSK0,
)

### FIDO URIs ###

# Chunk-width table matching the client's base10 encoder (CTAP 2.3 §11.5).
# Maps digit-string width -> byte-chunk size; greedy-largest-first decode.
_DIGIT_WIDTH_TO_CHUNK_SIZE = {17: 7, 15: 6, 13: 5, 10: 4, 8: 3, 5: 2, 3: 1}
_WIDTHS_DESC = sorted(_DIGIT_WIDTH_TO_CHUNK_SIZE, reverse=True)


def fido_decode(s):
    assert s.startswith('FIDO:/'), f"not a FIDO URI: {s!r}"
    digits = s[len('FIDO:/'):]
    out = bytearray()
    pos = 0
    while pos < len(digits):
        remaining = len(digits) - pos
        for w in _WIDTHS_DESC:
            if w <= remaining:
                chunk_size = _DIGIT_WIDTH_TO_CHUNK_SIZE[w]
                out += int(digits[pos:pos + w]).to_bytes(chunk_size, 'little')
                pos += w
                break
        else:
            raise ValueError(f"leftover {remaining} digit(s) don't match any chunk width")
    return loads(bytes(out))


### Key Derivation ###

keyPurposeEIDKey   = bytes.fromhex('01000000')
keyPurposeTunnelID = bytes.fromhex('02000000')
keyPurposePSK      = bytes.fromhex('03000000')


def derive(secret, salt=b'', purpose=None, length=64):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=purpose)
    return hkdf.derive(secret)


### BLE Encryption ###

def encrypt_eid(eidKey, plaintext):
    """Encrypt 16-byte EID plaintext: AES-256-ECB + 4-byte HMAC-SHA256 tag."""
    aesKey = eidKey[:32]
    hmacKey = eidKey[32:]
    cipher = Cipher(algorithms.AES(aesKey), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = hmac.new(hmacKey, ciphertext, hashlib.sha256).digest()[:4]
    return ciphertext + tag


### BLE Advertisement ###

ADAPTER_NAME = "hci0"
BLUEZ_SERVICE_NAME = "org.bluez"
BLUEZ_NAMESPACE = "/org/bluez/"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"
ADVERTISEMENT_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisement1"
ADVERTISING_MANAGER_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisingManager1"
FIDO_UUID = '0000fff9-0000-1000-8000-00805f9b34fb'


class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'


class Advertisement(dbus.service.Object):
    PATH_BASE = '/org/bluez/ldsg/advertisement'

    def __init__(self, bus, index, advertising_type, service_data=None):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = None
        self.manufacturer_data = None
        self.solicit_uuids = None
        self.service_data = service_data
        self.local_name = None
        self.include_tx_power = False
        self.data = None
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        properties = dict()
        properties['Type'] = self.ad_type
        if self.service_uuids is not None:
            properties['ServiceUUIDs'] = dbus.Array(self.service_uuids, signature='s')
        if self.solicit_uuids is not None:
            properties['SolicitUUIDs'] = dbus.Array(self.solicit_uuids, signature='s')
        if self.manufacturer_data is not None:
            properties['ManufacturerData'] = dbus.Dictionary(self.manufacturer_data, signature='qv')
        if self.service_data is not None:
            properties['ServiceData'] = dbus.Dictionary(self.service_data, signature='sv')
        if self.local_name is not None:
            properties['LocalName'] = dbus.String(self.local_name)
        if self.include_tx_power:
            properties['Includes'] = dbus.Array(["tx-power"], signature='s')
        if self.data is not None:
            properties['Data'] = dbus.Dictionary(self.data, signature='yv')
        print(properties)
        return {ADVERTISING_MANAGER_INTERFACE: properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROPERTIES, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != ADVERTISEMENT_INTERFACE:
            raise InvalidArgsException()
        return self.get_properties()[ADVERTISING_MANAGER_INTERFACE]

    @dbus.service.method(ADVERTISING_MANAGER_INTERFACE, in_signature='', out_signature='')
    def Release(self):
        print('%s: Released' % self.path)


def register_ad_cb():
    print('Advertisement registered OK')


def register_ad_error_cb(error):
    print('Error: Failed to register advertisement: ' + str(error))
    mainloop.quit()


def start_advertising():
    global adv, adv_mgr_interface
    print("Registering advertisement", adv.get_path())
    adv_mgr_interface.RegisterAdvertisement(
        adv.get_path(), {},
        reply_handler=register_ad_cb,
        error_handler=register_ad_error_cb,
    )


### CTAP command handlers ###

CTAP_GET_INFO        = 0x04
CTAP_GET_ASSERTION   = 0x02
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_STATUS_OK       = 0x00
CTAP_ERR_INVALID_COMMAND = 0x01
CTAP_ERR_NO_CREDENTIALS  = 0x2E
CTAP_ERR_NOT_ALLOWED     = 0x30
CTAP_FRAME_CTAP          = 0x01
CTAP_FRAME_SHUTDOWN      = 0x00

AAGUID = bytes.fromhex('aaf6ecbd9da0e23f57350e03e6667ea1')

CREDENTIAL_STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'credentials.json')


def _serialize_user(user):
    out = dict(user)
    if isinstance(out.get('id'), (bytes, bytearray)):
        out['id'] = out['id'].hex()
    return out


def _deserialize_user(user):
    out = dict(user)
    if 'id' in out:
        out['id'] = bytes.fromhex(out['id'])
    return out


def _load_credential_store():
    if not os.path.exists(CREDENTIAL_STORE_PATH):
        return {}
    with open(CREDENTIAL_STORE_PATH) as f:
        data = json.load(f)
    store = {}
    for rp_id, creds in data.items():
        store[rp_id] = []
        for c in creds:
            store[rp_id].append({
                'credentialId': bytes.fromhex(c['credentialId']),
                'privateKey':   load_pem_private_key(c['privateKey'].encode(), password=None),
                'user':         _deserialize_user(c['user']),
                'signCount':    c['signCount'],
            })
    return store


def _save_credential_store():
    data = {}
    for rp_id, creds in credential_store.items():
        data[rp_id] = []
        for c in creds:
            data[rp_id].append({
                'credentialId': c['credentialId'].hex(),
                'privateKey':   c['privateKey'].private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
                ).decode(),
                'user':         _serialize_user(c['user']),
                'signCount':    c['signCount'],
            })
    with open(CREDENTIAL_STORE_PATH, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Credential store saved ({sum(len(v) for v in data.values())} credential(s))")


# rpId -> list of {credentialId, privateKey, user, signCount}
credential_store = _load_credential_store()


def _build_auth_data(rp_id, flags, sign_count, attested_cred_data=b''):
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    return rp_id_hash + bytes([flags]) + struct.pack('>I', sign_count) + attested_cred_data


def handle_get_info():
    info = {
        1: ['FIDO_2_0', 'FIDO_2_1'],
        2: [],
        3: AAGUID,
        4: {'rk': False, 'up': True, 'uv': False},
        5: 1024,
        9: ['hybrid'],
    }
    return bytes([CTAP_STATUS_OK]) + dumps(info, canonical=True)


def handle_make_credential(request_cbor):
    req = loads(request_cbor)
    print(f"  MakeCredential: {req}")

    client_data_hash    = req[1]
    rp                  = req[2]
    user                = req[3]
    pub_key_cred_params = req[4]

    if not any(p.get('alg') == -7 for p in pub_key_cred_params):
        return bytes([CTAP_ERR_INVALID_COMMAND])

    rp_id       = rp['id']
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_nums    = private_key.public_key().public_numbers()
    cred_id     = secrets.token_bytes(32)

    credential_store.setdefault(rp_id, []).append({
        'credentialId': cred_id,
        'privateKey':   private_key,
        'user':         user,
        'signCount':    0,
    })
    _save_credential_store()

    cose_key = dumps({
        1: 2, 3: -7, -1: 1,
        -2: pub_nums.x.to_bytes(32, 'big'),
        -3: pub_nums.y.to_bytes(32, 'big'),
    }, canonical=True)
    attested_cred_data = AAGUID + struct.pack('>H', len(cred_id)) + cred_id + cose_key

    flags     = 0x01 | 0x40  # UP | AT
    auth_data = _build_auth_data(rp_id, flags, 0, attested_cred_data)

    response = {1: 'none', 2: auth_data, 3: {}}
    return bytes([CTAP_STATUS_OK]) + dumps(response, canonical=True)


def handle_get_assertion(request_cbor):
    req = loads(request_cbor)
    print(f"  GetAssertion: {req}")

    rp_id            = req[1]
    client_data_hash = req[2]
    allow_list       = req.get(3) or []

    creds = credential_store.get(rp_id, [])
    if allow_list:
        allowed_ids = {bytes(d['id']) for d in allow_list}
        creds = [c for c in creds if c['credentialId'] in allowed_ids]
    if not creds:
        return bytes([CTAP_ERR_NO_CREDENTIALS])

    cred = creds[0]
    cred['signCount'] += 1
    _save_credential_store()

    auth_data = _build_auth_data(rp_id, 0x01, cred['signCount'])  # UP
    signature = cred['privateKey'].sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

    response = {
        1: {'type': 'public-key', 'id': cred['credentialId']},
        2: auth_data,
        3: signature,
        4: cred['user'],
    }
    return bytes([CTAP_STATUS_OK]) + dumps(response, canonical=True)


def dispatch_ctap(request: bytes) -> bytes:
    if not request:
        return bytes([CTAP_ERR_INVALID_COMMAND])
    cmd  = request[0]
    body = request[1:]
    if cmd == CTAP_GET_INFO:
        return handle_get_info()
    if cmd == CTAP_GET_ASSERTION:
        return handle_get_assertion(body)
    if cmd == CTAP_MAKE_CREDENTIAL:
        return handle_make_credential(body)
    print(f"  Unknown CTAP command 0x{cmd:02x}")
    return bytes([CTAP_ERR_INVALID_COMMAND])


### Tunnel / WebSocket handler ###

def _channel_encrypt(cipher, plaintext: bytes) -> bytes:
    return cipher.encrypt_with_ad(b"", pad_message(plaintext))


def _channel_decrypt(cipher, ciphertext: bytes) -> bytes:
    return unpad_message(cipher.decrypt_with_ad(b"", ciphertext))


async def handler(websocket):
    print(f"Connection from path: {websocket.request.path}")

    # Build a fresh handshake state for this connection.
    # The client's static key (from the QR) is pre-shared (KNpsk0 prologue).
    hs = NoiseHandshake(
        pattern=PATTERN_KN_PSK0,
        role="responder",
        remote_static_public=client_pubkey_uncompressed,
        psk=psk,
    )

    # -> psk, e  (initiator's first message)
    msg1 = await websocket.recv()
    print(f"Received handshake msg1 ({len(msg1)} bytes): {msg1.hex()}")
    hs.read_message(msg1)

    # <- e, ee, se  (responder's reply)
    msg2 = hs.write_message()
    print(f"Sending handshake msg2 ({len(msg2)} bytes): {msg2.hex()}")
    await websocket.send(msg2)

    result = hs.finish()
    print("Noise handshake complete.")

    send_cipher    = result.send_cipher
    receive_cipher = result.receive_cipher

    # Post-handshake mandatory message: send our cached authenticatorGetInfo
    # response as a bare CBOR wrapper map {1: cbor_encoded_info_bytes}.
    # The client reads this BEFORE sending any CTAP requests (CTAP 2.3
    # sctn-hybrid "readPostHandshakeMessage"); it does NOT have a type byte.
    info_response = handle_get_info()
    # info_response is b'\x00' + cbor(info_map); strip the status byte --
    # the embedded bytes are just the raw cbor(info_map).
    info_cbor = info_response[1:]
    post_handshake = dumps({1: info_cbor}, canonical=True)
    await websocket.send(_channel_encrypt(send_cipher, post_handshake))
    print("Sent post-handshake cached getInfo.")

    # CTAP request/response loop.
    # Each frame: decrypt -> unpad -> [type_byte(0x01)] || ctap_request
    #             encrypt  <- pad  <- [type_byte(0x01)] || ctap_response
    while True:
        try:
            raw = await websocket.recv()
        except Exception as exc:
            print(f"Connection closed: {exc}")
            break

        try:
            plaintext = _channel_decrypt(receive_cipher, raw)
        except Exception as exc:
            print(f"Decryption failed: {exc}")
            break

        if not plaintext:
            print("Empty frame -- ignoring")
            continue

        frame_type = plaintext[0]
        payload    = plaintext[1:]

        if frame_type == CTAP_FRAME_SHUTDOWN:
            print("Client sent Shutdown frame -- closing.")
            break

        if frame_type != CTAP_FRAME_CTAP:
            print(f"Unexpected frame type 0x{frame_type:02x} -- ignoring")
            continue

        print(f"CTAP request ({len(payload)} bytes): cmd=0x{payload[0]:02x}" if payload else "CTAP request (empty)")
        ctap_response = dispatch_ctap(payload)
        print(f"CTAP response ({len(ctap_response)} bytes): status=0x{ctap_response[0]:02x}")

        response_frame = bytes([CTAP_FRAME_CTAP]) + ctap_response
        await websocket.send(_channel_encrypt(send_cipher, response_frame))
        break

    print("Session complete -- exiting.")
    mainloop.quit()


async def main():
    ssl_cert = "fullchain.pem"
    ssl_key  = "privkey.pem"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    server = await serve(handler, host="0.0.0.0", port=443,
                         subprotocols=["fido.cable"], ssl=ssl_context)
    await server.wait_closed()


def run_asyncio():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
    loop.run_forever()


### Setup ###

if os.getuid() != 0:
    print("Need root!")
    sys.exit(1)

if len(sys.argv) < 2:
    print("Usage: main.py <FIDO-URI>")
    sys.exit(1)

fido_uri = sys.argv[1]

decoded = fido_decode(fido_uri)
print(f"Decoded FIDO URI: {decoded}")

try:
    compressed_pubkey = decoded[0]  # 33-byte compressed P-256 public key
    print(f"Client static pubkey (compressed):   {compressed_pubkey.hex()}")

    # Decompress to 65-byte uncompressed form -- required for DH and the
    # caBLE Noise prologue (which mixes the uncompressed encoding).
    client_pubkey_obj = deserialize_public_key_compressed(compressed_pubkey)
    client_pubkey_uncompressed = serialize_public_key(client_pubkey_obj)
    print(f"Client static pubkey (uncompressed): {client_pubkey_uncompressed.hex()}")

    qrSecret = decoded[1]  # 16-byte QR secret
    print(f"QR secret: {qrSecret.hex()}")

    timestamp = decoded[3]
    print(f"Timestamp: {datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")

    cmd = decoded[5]  # 'ga' or 'mc'
    print(f"Request type: {cmd}")
    # Both 'ga' and 'mc' are handled at the CTAP dispatch layer -- no assertion here.

except KeyError as exc:
    print(f"Missing required FIDO URI field: {exc}")
    sys.exit(1)

# Derive EID key and construct BLE advertisement plaintext.
eidKey = derive(qrSecret, purpose=keyPurposeEIDKey)
print(f"EID key: {eidKey.hex()}")

flags      = b'\x00'
nonce      = secrets.token_bytes(10)
routingID  = secrets.token_bytes(3)
# tunnel_serviceID: 2-byte little-endian domain index.
# 0x0005 = custom domain (cable.pyzci7hxyjsvc.org) used by this Pi server.
tunnel_serviceID = b'\x05\x01'

eid_plaintext = flags + nonce + routingID + tunnel_serviceID
print(f"EID plaintext: {eid_plaintext.hex()}")

serviceData = encrypt_eid(eidKey, eid_plaintext)
print(f"EID encrypted: {serviceData.hex()}")

# Derive PSK from QR secret salted with the EID plaintext (CTAP 2.3 §11.5
# "derive(qrSecret, eid, keyPurposePSK)").
psk = derive(qrSecret, salt=eid_plaintext, purpose=keyPurposePSK, length=32)
print(f"PSK: {psk.hex()}")

# Start WebSocket tunnel server in a background thread.
threading.Thread(target=run_asyncio, daemon=True).start()

### BLE advertising ###

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()

adapter_path = BLUEZ_NAMESPACE + ADAPTER_NAME
print(f"BLE adapter: {adapter_path}")
adv_mgr_interface = dbus.Interface(
    bus.get_object(BLUEZ_SERVICE_NAME, adapter_path),
    ADVERTISING_MANAGER_INTERFACE,
)

serviceDict = {FIDO_UUID: dbus.Array(serviceData, signature='y')}
adv = Advertisement(bus, 0, 'broadcast', dbus.Dictionary(serviceDict, signature='sv'))
start_advertising()

try:
    mainloop = GLib.MainLoop()
    mainloop.run()
except KeyboardInterrupt:
    print("Shutting down...")
    mainloop.quit()
