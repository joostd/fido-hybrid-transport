#!/usr/bin/env python

import pyqrcode

import os
import sys
import time
import asyncio
import hmac
import hashlib
import json
import secrets
import argparse
from bleak import BleakScanner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cbor2 import dumps, loads

from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedOK
import websockets

from fido2.hid import CtapHidDevice, CTAPHID, ConnectionFailure
from fido2.ctap import CtapError

from cable_noise import NoiseHandshake, KeyPair, PATTERN_KN_PSK0, pad_message, unpad_message, dh
from ctap_usb import select_usb_device

_parser = argparse.ArgumentParser(description="FIDO caBLE client")
_parser.add_argument('command', nargs='?',
                     choices=['get-info', 'make-credential', 'get-assertion', 'usb-relay', 'stdio-relay'],
                     default='get-info')
_parser.add_argument('--rp-id', default='example.com')
_parser.add_argument('--user-id', help="User ID in hex for make-credential (default: user-name)")
_parser.add_argument('--user-name', help="User name for make-credential (required for make-credential)")
_parser.add_argument('--display-name', help="User display name for make-credential (default: same as --user-name)")
_parser.add_argument('--server', help="wss://.../usb-relay/<token> URL (for usb-relay)")
_parser.add_argument('--hint', choices=['mc', 'ga'], help="FIDO URI command hint (mc=makeCredential, ga=getAssertion)")
args = _parser.parse_args()

# Validate and set defaults for make-credential
if args.command == 'make-credential':
    if args.user_name is None:
        _parser.error("make-credential requires --user-name")

    # Default display-name to user-name if not specified
    if args.display_name is None:
        args.display_name = args.user_name

    # Default user-id to user-name if not specified
    if args.user_id is None:
        args.user_id = args.user_name
else:
    # For other commands, set defaults if needed
    if args.display_name is None and args.user_name is not None:
        args.display_name = args.user_name

def _call_usb_device(usb_device, request):
    # ConnectionFailure("Wrong channel") is a transient hiccup seen on macOS,
    # where another process (e.g. ctkd) also polling the security key over
    # USB HID can cause one of its response packets to be delivered to us.
    # The request is safe to retry -- just try again.
    for attempt in range(3):
        try:
            return usb_device.call(CTAPHID.CBOR, request)
        except CtapError as exc:
            return bytes([exc.code])
        except ConnectionFailure as exc:
            print(f"  USB device connection failure: {exc} (attempt {attempt + 1}/3)")
            time.sleep(0.1)
    return bytes([0x30])  # CTAP2_ERR_NOT_ALLOWED -- gave up after retries


if args.command == 'usb-relay':
    usb_device = select_usb_device()
    with connect(args.server, subprotocols=["fido.cable"]) as websocket:
        print(f"Connected to relay: {args.server}")
        try:
            for request in websocket:
                print(f"Relay request ({len(request)} bytes): {request.hex()}")
                try:
                    response = _call_usb_device(usb_device, request)
                except OSError as exc:
                    print(f"USB device I/O error: {exc}")
                    break
                print(f"Relay response ({len(response)} bytes): {response.hex()}")
                websocket.send(response)
        except websockets.exceptions.ConnectionClosed as exc:
            print(f"Relay connection closed: {exc}")
    sys.exit(0)

def fido_encode(data):
  # CBOR-encode input dict
  cbor_data = dumps(data)
  # group in chuncks of 7 bytes
  n = 7
  chunks = [cbor_data[i:i + n][::-1] for i in range(0, len(cbor_data), n)]
  # convert chunks to decimals
  decimals = [ str(int.from_bytes(b)) for b in chunks ]
  return "".join( [ i.rjust(17,"0") for i in decimals[:-1]] + [ decimals[-1] ] )

#qrSecret = bytes.fromhex('b2c251f13fcc397bc753121d7953b491')
qrSecret = secrets.token_bytes(16)
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
pubKey = public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint)
pubKeyUncompressed = public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
print(f"compressed public key: {pubKey.hex()}")
print(f"uncompressed public key: {pubKeyUncompressed.hex()}")
timestamp = int(time.time())
#timestamp = 1234567890  # timestamp does not seem to be used?

assignedTunnelServerDomains = ["cable.ua5v.com", "cable.auth.com"] # Google, Apple

authenticatorData = {
  0: pubKey,
  1: qrSecret,
  2: len(assignedTunnelServerDomains),
  3: timestamp,
  4: True,  # this client can perform state-assisted transactions (sctn-hybrid-state-assisted)
  5: args.hint if args.hint else ('mc' if args.command == 'make-credential' else 'ga')
}
fido = fido_encode(authenticatorData)

print( "FIDO:/" + fido )

keyPurposeEIDKey   = bytes.fromhex('01000000')
keyPurposeTunnelID = bytes.fromhex('02000000')
keyPurposePSK      = bytes.fromhex('03000000')

# Post-handshake message types (CTAP 2.3 sctn-hybrid Data Transfer).
CTAP_FRAME_SHUTDOWN = 0x00
CTAP_FRAME_CTAP     = 0x01
CTAP_FRAME_UPDATE   = 0x02

# Linking info (CTAP 2.3 sctn-hybrid-state-assisted), keyed by the
# authenticator's public key so repeat links from the same authenticator
# overwrite each other.
LINKED_AUTHENTICATORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "linked_authenticators.json")

uuid = '0000fff9-0000-1000-8000-00805f9b34fb'

url = pyqrcode.create( "FIDO:/" + fido, mode='alphanumeric', error='L' )
print(url.terminal(quiet_zone=1))


async def scan():
    async with BleakScanner() as scanner:
        async for bleDevice, advertisement_data in scanner.advertisement_data():
          if uuid in advertisement_data.service_data.keys():
            print(f"Received: {advertisement_data!r}")
            return advertisement_data.service_data[uuid]




def derive(secret, salt=b'', purpose=None):
    hkdf = HKDF( algorithm=hashes.SHA256(), length=64, salt=salt, info=purpose)
    key = hkdf.derive(secret)
    return key

def trialDecrypt(eidKey, cableData):
    aesKey = eidKey[:32]
    print(f"AES Key:  { aesKey.hex() }")
    hmacKey = eidKey[32:]
    print(f"HMAC Key: { hmacKey.hex() }")
    ciphertext = cableData[:16]
    h = hmac.new(hmacKey, ciphertext, hashlib.sha256).digest()
    #print(h.hexdigest())
    #print(f"HMAC-SHA256: {h[:4]}")
    #print(cableData[16:])
    if h[:4] != cableData[16:]:
        return None
    cipher = Cipher(algorithms.AES(aesKey), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    #print(plaintext.hex())
    assert(plaintext[0] == 0)
    return plaintext

async def ping(uri):
    async with websockets.connect(uri) as websocket:
        print(f"connected to { uri }")
        pong_waiter = await websocket.ping()
         #wait for the corresponding pong
        latency = await pong_waiter
        print(f"Latency: {latency}")


def _load_linked_authenticators():
    try:
        with open(LINKED_AUTHENTICATORS_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _save_linked_authenticators(linked):
    with open(LINKED_AUTHENTICATORS_PATH, "w") as f:
        json.dump(linked, f, indent=2)


def _handle_update_message(payload, handshake_hash, tunnel_server_domain):
    """Handle a type-2 update message. If it carries linking info (CTAP 2.3
    sctn-hybrid-state-assisted), verify it and persist it for later use."""
    update = loads(payload)
    linking = update.get(1) if isinstance(update, dict) else None
    if linking is None:
        return

    contact_id  = linking[1]
    link_id     = linking[2]
    link_secret = linking[3]
    auth_pubkey = linking[4]
    auth_name   = linking[5]
    signature   = linking[6]

    # The authenticator's "signature" is an HMAC of the handshake hash, keyed
    # by ECDH(authenticator's link pubkey, this session's QR identity key) --
    # it proves the authenticator holds the private key matching auth_pubkey.
    shared_key = dh(private_key, auth_pubkey)
    expected_signature = hmac.new(shared_key, handshake_hash, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_signature, signature):
        print(f"Linking info from {auth_name!r}: signature verification failed -- ignoring")
        return

    linked = _load_linked_authenticators()
    linked[auth_pubkey.hex()] = {
        "name": auth_name,
        "contact_id": contact_id.hex(),
        "link_id": link_id.hex(),
        "link_secret": link_secret.hex(),
        "tunnel_server_domain": tunnel_server_domain,
    }
    _save_linked_authenticators(linked)
    print(f"Linking info received and verified for {auth_name!r} -- saved to {LINKED_AUTHENTICATORS_PATH}")


def _drain_update_frames(websocket, receive_cipher, handshake_hash, tunnel_server_domain, timeout=0.5):
    """Read and handle any pending UPDATE frames from the authenticator.
    Used after the post-handshake message to consume linking-info frames
    that iOS sends when state-assisted transactions are advertised in the QR."""
    while True:
        try:
            raw = websocket.recv(timeout=timeout)
            resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
            frame_type, body = resp[0], resp[1:]
            if frame_type == CTAP_FRAME_UPDATE:
                _handle_update_message(body, handshake_hash, tunnel_server_domain)
                continue
            # Got a non-UPDATE frame - shouldn't happen, but stop draining
            break
        except Exception:
            # Timeout or other error means no more frames to read
            break


def _send_ctap_and_recv(websocket, send_cipher, receive_cipher, ctap_payload, handshake_hash, tunnel_server_domain):
    """Send a CTAP request frame and read frames until the CTAP response,
    handling any interleaved update (linking info) messages along the way."""
    frame = bytes([CTAP_FRAME_CTAP]) + ctap_payload
    websocket.send(send_cipher.encrypt_with_ad(b"", pad_message(frame)))
    while True:
        raw = websocket.recv(timeout=10)
        resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
        frame_type, body = resp[0], resp[1:]
        if frame_type == CTAP_FRAME_CTAP:
            return body
        if frame_type == CTAP_FRAME_UPDATE:
            _handle_update_message(body, handshake_hash, tunnel_server_domain)
            continue
        print(f"Unexpected frame type 0x{frame_type:02x} -- ignoring")


if __name__ == "__main__":
    eidKey = derive(secret=qrSecret, purpose=keyPurposeEIDKey)
    print(f"Key: { eidKey.hex() }")

    payload = None
    print("Scanning...")
    while True:
        cableData = asyncio.run(scan())


        #cableData = bytes.fromhex('f3bd42594d32f8b0dcbcf5e0302a9cfbec5f2a82')
        assert(len(cableData) == 20)
        print(f"encrypted BLE advert: { cableData.hex() }")
        # try to decrypt the cableData using eidKey
        payload = trialDecrypt(eidKey, cableData)
        if payload == None:
            print("decryption failed - ignoring")
            continue
        print(f"Decrypted: { payload.hex() }")
        break

    flags = payload[0:1]
    nonce = payload[1:11] # the value that demonstrates possession of the BLE advert
    routingID = payload[11:14]
    tunnel_serviceID = payload[14:]

    print(f"flags: { flags.hex() }")
    print(f"nonce: { nonce.hex() }")
    print(f"routingID: { routingID.hex() }")
    print(f"tunnel_serviceID: { tunnel_serviceID.hex() }")
    encodedTunnelServerDomain = tunnel_serviceID[0] + (tunnel_serviceID[1] << 8)
    # Values zero through 255 are assigned, and values >= 256 are translated into a domain name by hashing.
    assert(encodedTunnelServerDomain >= 0 and (encodedTunnelServerDomain < len(assignedTunnelServerDomains) or encodedTunnelServerDomain > 255))
    if encodedTunnelServerDomain > 255:
        tunnelServerDomain = 'cable.pyzci7hxyjsvc.org' # TODO hardcoding 0x0105 here, calculate domain name instead
    else:
        tunnelServerDomain = assignedTunnelServerDomains[encodedTunnelServerDomain]
    tunnelID = derive(secret=qrSecret, purpose=keyPurposeTunnelID)[:16]

    connectURL = "wss://" + tunnelServerDomain + "/cable/connect/" + routingID.hex() + "/" + tunnelID.hex() # TODO add TLS
    print(connectURL)

    with connect(connectURL, subprotocols=["fido.cable"],
                  additional_headers={"Origin": f"wss://{tunnelServerDomain}"}) as websocket:
        try:
            print(f"connected to {connectURL}")

            # PSK: salt is eid_plaintext (payload), not cableData (encrypted EID).
            # derive() is hardcoded to length=64; [:32] is safe because
            # HKDF T(1) is identical whether you request 32 or 64 bytes of output.
            psk = derive(secret=qrSecret, salt=payload, purpose=keyPurposePSK)[:32]
            print(f"PSK: {psk.hex()}")

            local_static = KeyPair(private_key=private_key, public_bytes=pubKeyUncompressed)

            hs = NoiseHandshake(
                pattern=PATTERN_KN_PSK0,
                role="initiator",
                local_static=local_static,
                psk=psk,
            )

            msg1 = hs.write_message()
            print(f"Sending msg1 ({len(msg1)} bytes): {msg1.hex()}")
            websocket.send(msg1)

            msg2 = websocket.recv(timeout=10)
            print(f"Received msg2 ({len(msg2)} bytes): {msg2.hex()}")
            hs.read_message(msg2)

            result = hs.finish()
            send_cipher = result.send_cipher
            receive_cipher = result.receive_cipher
            handshake_hash = result.handshake_hash
            print("Noise handshake complete.")

            # Post-handshake: server sends {1: cbor_info_bytes} immediately after handshake.
            raw = websocket.recv(timeout=10)
            post_hs = loads(unpad_message(receive_cipher.decrypt_with_ad(b"", raw)))
            # The post-handshake message contains {1: raw_cbor_encoded_info_map}
            cached_info = loads(post_hs[1])
            print(f"Post-handshake cached getInfo: {cached_info}")

            if args.command == 'get-info':
                # Use the cached getInfo from the post-handshake message instead of
                # sending a redundant request. iOS does not respond to the redundant
                # getInfo, and the spec already provides this information.
                print(f"authenticatorGetInfo: {cached_info}")

            elif args.command == 'make-credential':
                client_data_hash = secrets.token_bytes(32)
                # Decode user_id from hex if it looks like hex, otherwise encode as UTF-8
                try:
                    user_id_bytes = bytes.fromhex(args.user_id)
                except ValueError:
                    user_id_bytes = args.user_id.encode('utf-8')

                mc_req = dumps({
                    1: client_data_hash,
                    2: {'id': args.rp_id, 'name': args.rp_id},
                    3: {'id': user_id_bytes, 'name': args.user_name, 'displayName': args.display_name},
                    4: [{'type': 'public-key', 'alg': -7}],
                    7: {'rk': True, 'uv': True},
                }, canonical=True)
                body = _send_ctap_and_recv(websocket, send_cipher, receive_cipher, bytes([0x01]) + mc_req, handshake_hash, tunnelServerDomain)
                status = body[0]
                print(f"CTAP makeCredential response: status=0x{status:02x}")
                if status == 0x00:
                    print(f"  response map: {loads(body[1:])}")

            elif args.command == 'get-assertion':
                client_data_hash = secrets.token_bytes(32)
                ga_req = dumps({
                    1: args.rp_id,
                    2: client_data_hash,
                }, canonical=True)
                body = _send_ctap_and_recv(websocket, send_cipher, receive_cipher, bytes([0x02]) + ga_req, handshake_hash, tunnelServerDomain)
                status = body[0]
                print(f"CTAP getAssertion response: status=0x{status:02x}")
                if status == 0x00:
                    print(f"  response map: {loads(body[1:])}")

            elif args.command == 'stdio-relay':
                # Generic CTAP relay over a pair of pipes — the hybrid-transport
                # analogue of usb-relay.  An external process (sk-hybrid.so/dylib,
                # an OpenSSH SSH_SK_PROVIDER) writes length-prefixed CTAP request
                # frames to our fd 3 and reads length-prefixed CTAP response frames
                # back from our fd 4.
                #
                # Wire format on both pipes:
                #   [4-byte big-endian payload length] [payload bytes]
                #
                # Request payload (fd 3 → here → phone):
                #   [0x01 CTAP_FRAME_CTAP] [CTAP cmd byte] [CBOR params...]
                #   This is forwarded verbatim to the phone via the Noise tunnel.
                #
                # Response payload (phone → here → fd 4):
                #   The raw caBLE Noise payload from the phone is:
                #     [0x01 frame_type] [CTAP status] [CBOR body...]
                #   We strip the leading frame-type byte before writing to fd 4,
                #   so the C consumer sees [CTAP status] [CBOR body...] directly.
                #   (The C code also defensively strips the 0x01 prefix if present,
                #   so if your cable_noise.unpad_message already strips it, the
                #   result is the same either way — no double-stripping occurs.)
                #
                # fds 0/1/2 stay attached to the real terminal throughout (the QR
                # code, BLE scan output, and tunnel status printed above remain
                # visible to the user who needs to scan with their phone).

                # Drain any UPDATE frames that may have been sent after post-handshake
                _drain_update_frames(websocket, receive_cipher, handshake_hash, tunnelServerDomain, timeout=0.5)

                import sys as _sys
                relay_in  = os.fdopen(3, 'rb')
                relay_out = os.fdopen(4, 'wb')
                print("sk-hybrid relay ready; waiting for CTAP frames on fd 3.",
                      file=_sys.stderr, flush=True)
                while True:
                    # Read one length-prefixed request frame from the C side.
                    lenbuf = relay_in.read(4)
                    if len(lenbuf) < 4:
                        break  # C side closed the pipe — done
                    n = int.from_bytes(lenbuf, 'big')
                    ctap_frame = relay_in.read(n)
                    if len(ctap_frame) < n:
                        break  # truncated — shouldn't happen, but bail cleanly

                    # Forward the CTAP frame to the phone over the Noise tunnel.
                    websocket.send(
                        send_cipher.encrypt_with_ad(b"", pad_message(ctap_frame)))

                    # Receive the phone's response, skipping non-CTAP frames.
                    # The phone can send caBLE linking-info messages (frame type != 0x01)
                    # between the post-handshake getInfo and the CTAP response.
                    # Loop until we get a CTAP frame or timeout.
                    resp = None
                    attempts = 0
                    max_attempts = 5  # Allow up to 5 non-CTAP frames before giving up
                    while attempts < max_attempts:
                        try:
                            raw = websocket.recv(timeout=30)
                            resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
                            if resp and len(resp) > 0 and resp[0] == CTAP_FRAME_CTAP:
                                # Got a CTAP frame - this is what we want
                                break
                            # Non-CTAP frame received; skip silently
                            attempts += 1
                        except Exception:
                            # Timeout or other error
                            resp = None
                            break

                    # Strip the caBLE frame-type prefix byte (0x01) so that the
                    # payload written to fd 4 is [CTAP_status, CBOR_body...].
                    if resp and len(resp) > 0 and resp[0] == CTAP_FRAME_CTAP:
                        ctap_resp = resp[1:]
                    else:
                        # No valid CTAP response received; send error back to C
                        ctap_resp = bytes([0x30])  # CTAP2_ERR_NOT_ALLOWED

                    relay_out.write(len(ctap_resp).to_bytes(4, 'big'))
                    relay_out.write(ctap_resp)
                    relay_out.flush()

        except websockets.exceptions.ConnectionClosedOK as e:
            print(f"Connection closed OK: {e}")

    #loop = asyncio.new_event_loop()
    #asyncio.set_event_loop(loop)
    #loop.run_until_complete(ping(connectURL))
