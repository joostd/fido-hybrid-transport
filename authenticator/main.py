#!/usr/bin/python

# FIDO CDA Authenticator using CTAP hybrid transport
# https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hybrid

import sys
import os
import json
import argparse
import datetime
import asyncio
import threading
import hmac
import hashlib
import logging
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

import websockets
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

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap import CtapError

from ctap_usb import select_usb_device

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
        logging.debug(properties)
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
        logging.info('%s: Released', self.path)


def register_ad_cb():
    logging.info('Advertisement registered OK')


def register_ad_error_cb(error):
    logging.error('Failed to register advertisement: %s', error)
    mainloop.quit()


def start_advertising():
    global adv, adv_mgr_interface
    logging.info("Registering advertisement %s", adv.get_path())
    adv_mgr_interface.RegisterAdvertisement(
        adv.get_path(), {},
        reply_handler=register_ad_cb,
        error_handler=register_ad_error_cb,
    )


### CTAP command handlers ###

CTAP_GET_INFO                = 0x04
CTAP_GET_ASSERTION           = 0x02
CTAP_MAKE_CREDENTIAL         = 0x01
CTAP_SELECTION               = 0x0B
CTAP_STATUS_OK               = 0x00
CTAP_ERR_INVALID_COMMAND     = 0x01
CTAP_ERR_CREDENTIAL_EXCLUDED = 0x19
CTAP_ERR_NO_CREDENTIALS      = 0x2E
CTAP_ERR_NOT_ALLOWED         = 0x30
CTAP_FRAME_CTAP              = 0x01
CTAP_FRAME_SHUTDOWN          = 0x00

CTAP_COMMAND_NAMES = {
    CTAP_MAKE_CREDENTIAL: "authenticatorMakeCredential",
    CTAP_GET_ASSERTION:   "authenticatorGetAssertion",
    CTAP_GET_INFO:        "authenticatorGetInfo",
    CTAP_SELECTION:       "authenticatorSelection",
}

CTAP_STATUS_NAMES = {
    CTAP_STATUS_OK:               "CTAP2_OK",
    CTAP_ERR_INVALID_COMMAND:     "CTAP1_ERR_INVALID_COMMAND",
    CTAP_ERR_CREDENTIAL_EXCLUDED: "CTAP2_ERR_CREDENTIAL_EXCLUDED",
    CTAP_ERR_NO_CREDENTIALS:      "CTAP2_ERR_NO_CREDENTIALS",
    CTAP_ERR_NOT_ALLOWED:         "CTAP2_ERR_NOT_ALLOWED",
}

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
    logging.info("Credential store saved (%d credential(s))", sum(len(v) for v in data.values()))


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
        # uv: true -- per the hybrid/caBLE convention, user verification is
        # performed "outside" CTAP (the user already unlocked this device to
        # establish the connection), so platforms expect uv: true without a
        # pinUvAuthProtocol/clientPin. Without it, Chrome skips getAssertion
        # for requests with userVerification: required.
        4: {'rk': True, 'up': True, 'uv': True},
        #5: 1024,
        9: ['hybrid'],
    }
    return bytes([CTAP_STATUS_OK]) + dumps(info, canonical=True)


def handle_make_credential(request_cbor):
    req = loads(request_cbor)

    client_data_hash    = req[1]
    rp                  = req[2]
    user                = req[3]
    pub_key_cred_params = req[4]
    exclude_list        = req.get(5) or []

    if not any(p.get('alg') == -7 for p in pub_key_cred_params):
        return bytes([CTAP_ERR_INVALID_COMMAND])

    rp_id = rp['id']

    excluded_ids = {bytes(d['id']) for d in exclude_list}
    if any(c['credentialId'] in excluded_ids for c in credential_store.get(rp_id, [])):
        return bytes([CTAP_ERR_CREDENTIAL_EXCLUDED])

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

    flags     = 0x01 | 0x04 | 0x40  # UP | UV | AT
    auth_data = _build_auth_data(rp_id, flags, 0, attested_cred_data)

    response = {1: 'none', 2: auth_data, 3: {}}
    return bytes([CTAP_STATUS_OK]) + dumps(response, canonical=True)


def handle_get_assertion(request_cbor):
    req = loads(request_cbor)

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

    auth_data = _build_auth_data(rp_id, 0x01 | 0x04, cred['signCount'])  # UP | UV
    signature = cred['privateKey'].sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

    response = {
        1: {'type': 'public-key', 'id': cred['credentialId']},
        2: auth_data,
        3: signature,
        4: cred['user'],
    }
    return bytes([CTAP_STATUS_OK]) + dumps(response, canonical=True)


def handle_selection():
    return bytes([CTAP_STATUS_OK])


# Set during startup if --usb is passed; when set, dispatch_ctap relays all
# CTAP traffic to this device instead of using the software handlers above.
usb_device = None

# Set during startup if --remote-usb is passed; when set, _dispatch_ctap_async
# relays CTAP requests to a remote `client/main.py usb-relay` over a second
# WebSocket connection, which forwards them to a USB security key.
remote_usb_relay = None
relay_connected_event = threading.Event()
relay_token = None

# Set by _finalize_ble_advert_data() once the tunnel server (self-hosted or
# Google) is set up and routingID is known. The main thread waits on this
# before building/starting the BLE advertisement.
ble_data_ready = threading.Event()
routingID = None
tunnel_serviceID = None
eid_plaintext = None
serviceData = None
psk = None


class RemoteUsbRelay:
    """Forwards CTAP request/response bytes to a connected usb-relay client."""

    def __init__(self, websocket):
        self.websocket = websocket
        self._lock = asyncio.Lock()

    async def call(self, request: bytes) -> bytes:
        async with self._lock:
            await self.websocket.send(request)
            return await self.websocket.recv()


def _cbor_to_display(obj):
    """Recursively convert CBOR-decoded objects to JSON-serialisable form."""
    if isinstance(obj, (bytes, bytearray)):
        h = obj.hex()
        return h[:128] + f"...({len(obj)}B)" if len(h) > 128 else h
    if isinstance(obj, dict):
        return {str(k): _cbor_to_display(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_cbor_to_display(v) for v in obj]
    return obj


def _log_ctap_message(direction: str, data: bytes, names: dict) -> None:
    """Log a raw CTAP request/response: hex bytes plus decoded CBOR body."""
    if direction == 'request':
        logging.info("-" * 64)
    if not data:
        logging.info("CTAP %s: (empty)", direction)
        return
    code = data[0]
    name = names.get(code, f"0x{code:02x}")
    logging.debug("CTAP %s: %s (%d bytes): %s", direction, name, len(data), data.hex())
    if len(data) > 1:
        try:
            pretty = json.dumps(_cbor_to_display(loads(data[1:])), indent=2)
            logging.info("CTAP %s: %s:\n%s", direction, name,
                         "\n".join("  " + line for line in pretty.splitlines()))
        except Exception as exc:
            logging.warning("CTAP %s: %s: <CBOR decode failed: %s>", direction, name, exc)


def dispatch_ctap(request: bytes) -> bytes:
    if usb_device is not None:
        try:
            return usb_device.call(CTAPHID.CBOR, request)
        except CtapError as exc:
            logging.error("USB device error: %s", exc)
            return bytes([exc.code])
        except OSError as exc:
            logging.error("USB device I/O error: %s", exc)
            return bytes([CTAP_ERR_NOT_ALLOWED])

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
    if cmd == CTAP_SELECTION:
        return handle_selection()
    logging.warning("Unknown CTAP command 0x%02x", cmd)
    return bytes([CTAP_ERR_INVALID_COMMAND])


### Tunnel / WebSocket handler ###

def _channel_encrypt(cipher, plaintext: bytes) -> bytes:
    return cipher.encrypt_with_ad(b"", pad_message(plaintext))


def _channel_decrypt(cipher, ciphertext: bytes) -> bytes:
    return unpad_message(cipher.decrypt_with_ad(b"", ciphertext))


async def _dispatch_ctap_async(payload: bytes) -> bytes:
    """Run dispatch_ctap off the event loop when relaying to a USB device,
    since usb_device.call() blocks until the user touches the key."""
    if usb_device is not None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, dispatch_ctap, payload)
    if remote_usb_relay is not None:
        try:
            return await remote_usb_relay.call(payload)
        except Exception as exc:
            logging.error("Remote USB relay error: %s", exc)
            return bytes([CTAP_ERR_NOT_ALLOWED])
    if args.remote_usb:
        logging.error("No USB relay client connected.")
        return bytes([CTAP_ERR_NOT_ALLOWED])
    return dispatch_ctap(payload)


async def handler(websocket):
    logging.info("Connection from path: %s", websocket.request.path)

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
    logging.debug("Received handshake msg1 (%d bytes): %s", len(msg1), msg1.hex())
    hs.read_message(msg1)

    # <- e, ee, se  (responder's reply)
    msg2 = hs.write_message()
    logging.debug("Sending handshake msg2 (%d bytes): %s", len(msg2), msg2.hex())
    await websocket.send(msg2)

    result = hs.finish()
    logging.info("Noise handshake complete.")

    send_cipher    = result.send_cipher
    receive_cipher = result.receive_cipher

    # Post-handshake mandatory message: send our cached authenticatorGetInfo
    # response as a bare CBOR wrapper map {1: cbor_encoded_info_bytes}.
    # The client reads this BEFORE sending any CTAP requests (CTAP 2.3
    # sctn-hybrid "readPostHandshakeMessage"); it does NOT have a type byte.
    info_request = bytes([CTAP_GET_INFO])
    _log_ctap_message("request", info_request, CTAP_COMMAND_NAMES)
    info_response = await _dispatch_ctap_async(info_request)
    _log_ctap_message("response", info_response, CTAP_STATUS_NAMES)
    # info_response is status_byte + cbor(info_map); strip the status byte --
    # the embedded bytes are just the raw cbor(info_map).
    info_cbor = info_response[1:]
    post_handshake = dumps({1: info_cbor}, canonical=True)
    await websocket.send(_channel_encrypt(send_cipher, post_handshake))
    logging.debug("Sent post-handshake cached getInfo.")

    # CTAP request/response loop.
    # Each frame: decrypt -> unpad -> [type_byte(0x01)] || ctap_request
    #             encrypt  <- pad  <- [type_byte(0x01)] || ctap_response
    while True:
        try:
            raw = await websocket.recv()
        except Exception as exc:
            logging.info("Connection closed: %s", exc)
            break

        try:
            plaintext = _channel_decrypt(receive_cipher, raw)
        except Exception as exc:
            logging.error("Decryption failed: %s", exc)
            break

        if not plaintext:
            logging.warning("Empty frame -- ignoring")
            continue

        frame_type = plaintext[0]
        payload    = plaintext[1:]

        if frame_type == CTAP_FRAME_SHUTDOWN:
            logging.info("Client sent Shutdown frame -- closing.")
            break

        if frame_type != CTAP_FRAME_CTAP:
            logging.warning("Unexpected frame type 0x%02x -- ignoring", frame_type)
            continue

        _log_ctap_message("request", payload, CTAP_COMMAND_NAMES)
        ctap_response = await _dispatch_ctap_async(payload)
        _log_ctap_message("response", ctap_response, CTAP_STATUS_NAMES)

        response_frame = bytes([CTAP_FRAME_CTAP]) + ctap_response
        await websocket.send(_channel_encrypt(send_cipher, response_frame))

    logging.info("Session complete -- exiting.")
    mainloop.quit()


async def usb_relay_handler(websocket):
    global remote_usb_relay
    logging.info("USB relay client connected from %s", websocket.remote_address)
    remote_usb_relay = RemoteUsbRelay(websocket)
    relay_connected_event.set()
    try:
        await websocket.wait_closed()
    finally:
        remote_usb_relay = None
        logging.info("USB relay client disconnected.")


async def connection_handler(websocket):
    path = websocket.request.path
    if path.startswith("/usb-relay/"):
        token = path.removeprefix("/usb-relay/")
        if not secrets.compare_digest(token, relay_token):
            await websocket.close(1008, "invalid token")
            return
        await usb_relay_handler(websocket)
    else:
        await handler(websocket)


def _finalize_ble_advert_data(routing_id, tunnel_service_id):
    """Compute eid_plaintext / serviceData / psk now that routingID and
    tunnel_serviceID are known, and unblock the main thread, which is
    waiting to build the BLE advertisement."""
    global routingID, tunnel_serviceID, eid_plaintext, serviceData, psk
    routingID = routing_id
    tunnel_serviceID = tunnel_service_id
    eid_plaintext = flags + nonce + routingID + tunnel_serviceID
    serviceData = encrypt_eid(eidKey, eid_plaintext)
    psk = derive(qrSecret, salt=eid_plaintext, purpose=keyPurposePSK, length=32)
    logging.debug("EID plaintext: %s", eid_plaintext.hex())
    logging.debug("EID encrypted: %s", serviceData.hex())
    logging.debug("PSK: %s", psk.hex())
    ble_data_ready.set()


def _load_ssl_context():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("fullchain.pem", keyfile="privkey.pem")
    return ssl_context


# --tunnel-server {google,local} -> (registration domain, tunnel_serviceID).
# tunnel_serviceID 0x0000 is Google (cable.ua5v.com, assignedTunnelServerDomains[0]
# in client/main.py); 0x0105 is the same custom-domain encoding 'self' uses,
# which client/main.py already maps to cable.pyzci7hxyjsvc.org.
TUNNEL_REGISTRARS = {
    'google': ("cable.ua5v.com", b'\x00\x00'),
    'local':  ("cable.pyzci7hxyjsvc.org", b'\x05\x01'),
}


async def main():
    try:
        if args.tunnel_server in TUNNEL_REGISTRARS:
            domain, tunnel_service_id = TUNNEL_REGISTRARS[args.tunnel_server]
            tunnel_id = derive(qrSecret, purpose=keyPurposeTunnelID)[:16]
            url = f"wss://{domain}/cable/new/{tunnel_id.hex()}"
            logging.info("Registering tunnel with %s", domain)
            logging.debug("  URL: %s", url)
            async with websockets.connect(
                url, subprotocols=["fido.cable"],
                additional_headers={"Origin": f"wss://{domain}"},
            ) as websocket:
                routing_id = bytes.fromhex(websocket.response.headers["X-caBLE-Routing-ID"])
                logging.debug("Routing ID from %s: %s", domain, routing_id.hex())
                _finalize_ble_advert_data(routing_id, tunnel_service_id)

                if args.remote_usb:
                    server = await serve(connection_handler, host="0.0.0.0", port=443,
                                         subprotocols=["fido.cable"], ssl=_load_ssl_context())
                    await asyncio.gather(handler(websocket), server.wait_closed())
                else:
                    await handler(websocket)
        else:
            _finalize_ble_advert_data(secrets.token_bytes(3), b'\x05\x01')
            server = await serve(connection_handler, host="0.0.0.0", port=443,
                                 subprotocols=["fido.cable"], ssl=_load_ssl_context())
            await server.wait_closed()
    except Exception as exc:
        logging.error("Fatal error setting up tunnel server: %r", exc)
        os._exit(1)


def run_asyncio():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
    loop.run_forever()


### Setup ###

arg_parser = argparse.ArgumentParser(description="FIDO CDA Authenticator using CTAP hybrid transport")
arg_parser.add_argument('fido_uri', metavar='FIDO-URI', help="FIDO:/... URI decoded from the QR code")
arg_parser.add_argument('--usb', action='store_true',
                        help="Relay CTAP messages to a USB security key instead of the built-in software authenticator")
arg_parser.add_argument('--remote-usb', action='store_true',
                        help="Relay CTAP messages to a USB security key plugged into a remote machine "
                             "running `client/main.py usb-relay`")
arg_parser.add_argument('--relay-token',
                        help="Secret token for the /usb-relay/<token> path (default: randomly generated)")
arg_parser.add_argument('--tunnel-server', choices=['self', 'google', 'local'], default='google',
                        help="'google' (default) registers a tunnel with Google's caBLE "
                             "relay (cable.ua5v.com); 'local' registers with our own "
                             "tunnel/main.py relay at cable.pyzci7hxyjsvc.org instead; "
                             "'self' hosts our own WSS tunnel endpoint directly. The "
                             "'google' option relies on undocumented infrastructure that "
                             "could change or break.")
arg_parser.add_argument('--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set logging verbosity (default: INFO); DEBUG additionally shows "
                             "raw CTAP hex bytes, handshake bytes, and key material")
args = arg_parser.parse_args()

logging.basicConfig(level=getattr(logging, args.log_level), format='%(levelname)s: %(message)s')

if args.usb and args.remote_usb:
    arg_parser.error("--usb and --remote-usb are mutually exclusive")

# Binding port 443 (self-hosted tunnel server, or the --remote-usb relay
# endpoint) requires root. BLE advertising via D-Bus may also need root
# unless a polkit policy grants the current user access to org.bluez.
if (args.tunnel_server == 'self' or args.remote_usb) and os.getuid() != 0:
    logging.error("Need root to bind port 443 (--tunnel-server self or --remote-usb).")
    sys.exit(1)

fido_uri = args.fido_uri

if args.usb:
    usb_device = select_usb_device()

if args.remote_usb:
    relay_token = args.relay_token or secrets.token_urlsafe(24)

decoded = fido_decode(fido_uri)
logging.debug("Decoded FIDO URI: %s", decoded)

try:
    compressed_pubkey = decoded[0]  # 33-byte compressed P-256 public key
    logging.debug("Client static pubkey (compressed):   %s", compressed_pubkey.hex())

    # Decompress to 65-byte uncompressed form -- required for DH and the
    # caBLE Noise prologue (which mixes the uncompressed encoding).
    client_pubkey_obj = deserialize_public_key_compressed(compressed_pubkey)
    client_pubkey_uncompressed = serialize_public_key(client_pubkey_obj)
    logging.debug("Client static pubkey (uncompressed): %s", client_pubkey_uncompressed.hex())

    qrSecret = decoded[1]  # 16-byte QR secret
    logging.debug("QR secret: %s", qrSecret.hex())

    timestamp = decoded[3]
    logging.info("Timestamp: %s", datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'))

    cmd = decoded[5]  # 'ga' or 'mc'
    logging.info("Request type: %s", cmd)
    # Both 'ga' and 'mc' are handled at the CTAP dispatch layer -- no assertion here.

except KeyError as exc:
    logging.error("Missing required FIDO URI field: %s", exc)
    sys.exit(1)

# Derive EID key and construct BLE advertisement plaintext.
eidKey = derive(qrSecret, purpose=keyPurposeEIDKey)
logging.debug("EID key: %s", eidKey.hex())

flags = b'\x00'
nonce = secrets.token_bytes(10)
# tunnel_serviceID (2-byte little-endian domain index), routingID, and the
# resulting eid_plaintext / serviceData / PSK (CTAP 2.3 §11.5
# "derive(qrSecret, eid, keyPurposePSK)") are computed by main(), in the
# background thread started below: for --tunnel-server self this is
# immediate (0x0105 = custom domain cable.pyzci7hxyjsvc.org, random
# routingID); for --tunnel-server google it happens after registering with
# Google's relay and learning routingID from its response.

# Start WebSocket tunnel server / Google tunnel registration in a background thread.
threading.Thread(target=run_asyncio, daemon=True).start()

logging.info("Waiting for tunnel setup...")
ble_data_ready.wait()

if args.remote_usb:
    relay_url = f"wss://cable.pyzci7hxyjsvc.org/usb-relay/{relay_token}"
    logging.info("Waiting for USB relay client to connect:")
    logging.info("  python client/main.py usb-relay --server %s", relay_url)
    relay_connected_event.wait()

### BLE advertising ###

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()

adapter_path = BLUEZ_NAMESPACE + ADAPTER_NAME
logging.info("BLE adapter: %s", adapter_path)
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
    logging.info("Shutting down...")
    mainloop.quit()
