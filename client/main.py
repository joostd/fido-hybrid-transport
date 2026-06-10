#!/usr/bin/env python

import pyqrcode

import os
import sys
import time
import asyncio
import hmac
import hashlib
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

from cable_noise import NoiseHandshake, KeyPair, PATTERN_KN_PSK0, pad_message, unpad_message
from ctap_usb import select_usb_device

_parser = argparse.ArgumentParser(description="FIDO caBLE client")
_parser.add_argument('command', nargs='?',
                     choices=['get-info', 'make-credential', 'get-assertion', 'usb-relay'],
                     default='get-info')
_parser.add_argument('--rp-id', default='example.com')
_parser.add_argument('--server', help="wss://.../usb-relay/<token> URL (for usb-relay)")
args = _parser.parse_args()

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
  4: False,
  5: 'mc' if args.command == 'make-credential' else 'ga'
}
fido = fido_encode(authenticatorData)

print( "FIDO:/" + fido )

keyPurposeEIDKey   = bytes.fromhex('01000000')
keyPurposeTunnelID = bytes.fromhex('02000000')
keyPurposePSK      = bytes.fromhex('03000000')

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

    with connect(connectURL, subprotocols=["fido.cable"]) as websocket:
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
            print("Noise handshake complete.")

            # Post-handshake: server sends {1: cbor_info_bytes} immediately after handshake.
            raw = websocket.recv(timeout=10)
            post_hs = loads(unpad_message(receive_cipher.decrypt_with_ad(b"", raw)))
            print(f"Post-handshake cached getInfo: {post_hs}")

            CTAP_FRAME_CTAP = 0x01

            if args.command == 'get-info':
                ctap_frame = bytes([CTAP_FRAME_CTAP, 0x04])
                websocket.send(send_cipher.encrypt_with_ad(b"", pad_message(ctap_frame)))
                print("Sent CTAP getInfo.")
                raw = websocket.recv(timeout=10)
                resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
                status = resp[1]
                print(f"CTAP getInfo response: status=0x{status:02x}, info={loads(resp[2:])}")

            elif args.command == 'make-credential':
                client_data_hash = secrets.token_bytes(32)
                mc_req = dumps({
                    1: client_data_hash,
                    2: {'id': args.rp_id, 'name': args.rp_id},
                    3: {'id': b'user01', 'name': 'Test User'},
                    4: [{'type': 'public-key', 'alg': -7}],
                }, canonical=True)
                ctap_frame = bytes([CTAP_FRAME_CTAP, 0x01]) + mc_req
                websocket.send(send_cipher.encrypt_with_ad(b"", pad_message(ctap_frame)))
                print(f"Sent CTAP makeCredential (rp={args.rp_id}).")
                raw = websocket.recv(timeout=10)
                resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
                status = resp[1]
                print(f"CTAP makeCredential response: status=0x{status:02x}")
                if status == 0x00:
                    print(f"  response map: {loads(resp[2:])}")

            elif args.command == 'get-assertion':
                client_data_hash = secrets.token_bytes(32)
                ga_req = dumps({
                    1: args.rp_id,
                    2: client_data_hash,
                }, canonical=True)
                ctap_frame = bytes([CTAP_FRAME_CTAP, 0x02]) + ga_req
                websocket.send(send_cipher.encrypt_with_ad(b"", pad_message(ctap_frame)))
                print(f"Sent CTAP getAssertion (rp={args.rp_id}).")
                raw = websocket.recv(timeout=10)
                resp = unpad_message(receive_cipher.decrypt_with_ad(b"", raw))
                status = resp[1]
                print(f"CTAP getAssertion response: status=0x{status:02x}")
                if status == 0x00:
                    print(f"  response map: {loads(resp[2:])}")

        except websockets.exceptions.ConnectionClosedOK as e:
            print(f"Connection closed OK: {e}")

    #loop = asyncio.new_event_loop()
    #asyncio.set_event_loop(loop)
    #loop.run_until_complete(ping(connectURL))
