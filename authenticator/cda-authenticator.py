#!/usr/bin/python

# FIDO CDA Authenticator using CTAP hybrid transport
# https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hybrid

import sys # argv
import os
import datetime
# WS
import asyncio, threading
from websockets.server import serve
# BLE
import dbus
import dbus.exceptions
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
# crypto
import hmac
import hashlib
import secrets
import ssl
from cbor2 import loads, dumps
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
# noise
from noise.connection import NoiseConnection, Keypair

### FIDO URIs ###

def fido_encode(data):
  # CBOR-encode input dict
  cbor_data = dumps(data)
  print(cbor_data)
  # group in chuncks of 7 bytes
  n = 7
  chunks = [cbor_data[i:i + n][::-1] for i in range(0, len(cbor_data), n)]
  print(chunks)
  # convert chunks to decimals
  decimals = [ str(int.from_bytes(b, "little")) for b in chunks ]
  print(decimals)
  return "".join( [ i.rjust(17,"0") for i in decimals[:-1]] + [ decimals[-1] ] )

def fido_decode(s):
  assert( s.startswith('FIDO:/') )
  s = s.lstrip('FIDO:/')
  chunkSize = 17
  chunks = [ s[i:i + chunkSize] for i in range(0, len(s), chunkSize) ]
  parts = [ int(chunk).to_bytes(7,"little") for chunk in chunks ]
  parts[-1].lstrip(b'\0')
  return loads(b''.join(parts))

### Key Derivation ###

# TODO move to common code
keyPurposeEIDKey   = bytes.fromhex('01000000')
keyPurposeTunnelID = bytes.fromhex('02000000')
keyPurposePSK      = bytes.fromhex('03000000')

def derive(secret, salt=b'', purpose=None):
    hkdf = HKDF( algorithm=hashes.SHA256(), length=64, salt=salt, info=purpose)
    key = hkdf.derive(secret)
    return key

### Encryption ###

""" encrypt 16-byte plaintext with 64-byte eidKey and append 4-byte HMAC"""
def encrypt(eidKey, plaintext):
    aesKey = eidKey[:32]
    hmacKey = eidKey[32:]
    cipher = Cipher(algorithms.AES(aesKey), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    h = hmac.new(hmacKey, ciphertext, hashlib.sha256).digest()
    return b''.join([ ciphertext, h[:4]])


### BLE ###

ADAPTER_NAME = "hci0"
BLUEZ_SERVICE_NAME = "org.bluez"
BLUEZ_NAMESPACE = "/org/bluez/"
DBUS_PROPERTIES="org.freedesktop.DBus.Properties"
ADVERTISEMENT_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisement1"
ADVERTISING_MANAGER_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisingManager1"

# UUID 0xFFF9: FIDO2 secure client-to-authenticator transport
FIDO_UUID = '0000fff9-0000-1000-8000-00805f9b34fb' # FIDO Service Discovery

class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'

# much of this code was copied or inspired by test\example-advertisement in the BlueZ source
class Advertisement(dbus.service.Object):
  PATH_BASE = '/org/bluez/ldsg/advertisement'

  def __init__(self, bus, index, advertising_type, service_data = None):
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
    #self.discoverable = True
    dbus.service.Object.__init__(self, bus, self.path)

  def get_properties(self):
    properties = dict()
    properties['Type'] = self.ad_type
    if self.service_uuids is not None:
      properties['ServiceUUIDs'] = dbus.Array(self.service_uuids, signature='s')
    if self.solicit_uuids is not None:
      properties['SolicitUUIDs'] = dbus.Array(self.solicit_uuids, signature='s')
    if self.manufacturer_data is not None:
      properties['ManufacturerData'] = dbus.Dictionary( self.manufacturer_data, signature='qv')
    if self.service_data is not None:
      properties['ServiceData'] = dbus.Dictionary(self.service_data, signature='sv')
    if self.local_name is not None:
      properties['LocalName'] = dbus.String(self.local_name)
    #if self.discoverable is not None and self.discoverable == True:
      #properties['Discoverable'] = dbus.Boolean(self.discoverable)
    if self.include_tx_power:
      properties['Includes'] = dbus.Array(["tx-power"], signature='s')
    if self.data is not None:
      properties['Data'] = dbus.Dictionary( self.data, signature='yv')
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
  global adv
  global adv_mgr_interface
  # we're only registering one advertisement object so index (arg2) is hard coded as 0
  print("Registering advertisement",adv.get_path())
  adv_mgr_interface.RegisterAdvertisement(adv.get_path(), {}, reply_handler=register_ad_cb, error_handler=register_ad_error_cb)

### FIDO.CABLE ###

name = b"Noise_KNpsk0_P256_AESGCM_SHA256"
#name = b"Noise_KNpsk0_25519_AESGCM_SHA256" # TEMP
responder = NoiseConnection.from_name(name)



# Naive implementation of the WebSockets fido.cable subprotocol

# TODO: multiple paths
async def handler(websocket, path):
    print(f"Path: {path}")
    print(f"starting handshake I>R")
    responder.start_handshake()
    # -> psk, e

    handshake1 = await websocket.recv()
    print(f"Received --> psk, e: {handshake1.hex()}")
    # this is the KNpsk0 initiator (client/browser) handshake message, consisting of an uncompressed P256 ephemeral key (ie 65 bytes) and a 16 byte encrypted empty message
    empty = responder.read_message(handshake1)
    print(empty.hex())
    #assert empty == b''

    # <- e, ee, se
    handshake2 = responder.write_message()
    print(f"Sending response: {handshake2.hex()}")
    await websocket.send(handshake2)
    assert responder.handshake_finished
    print(f"handshake finished")

    # TEST - rev string
    message = await websocket.recv()
    print(f"Received: {message.hex()}")
    plaintext = responder.decrypt(message)
    print(f"Plaintext: {plaintext}")
    rev = plaintext[::-1]
    ciphertext = responder.encrypt(rev)
    print(f"Ciphertext: {ciphertext.hex()}")
    await websocket.send(ciphertext)

async def main():
    # Generate out-of-band with Lets Encrypt, chown to current user and 400 permissions
    ssl_cert = "fullchain.pem"
    ssl_key = "privkey.pem"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ssl_cert, keyfile=ssl_key)
    server = await serve(handler, host="0.0.0.0", port=443, subprotocols=["fido.cable"], ssl=ssl_context)
    #server = await serve(handler, host=None, port=2222)
    await server.wait_closed()

def run_asyncio():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete( main() )
    loop.run_forever()


### SETUP ###

if os.getuid() != 0:
        print(f"Need root!")
        sys.exit(1)

if len(sys.argv) < 2:
        print(f"Need a FIDO URI!")
        sys.exit(1)
fido_uri = sys.argv[1]

# Decode FIDO URI

decoded = fido_decode(fido_uri)
print(f"Decoded FIDO URI:\n {decoded}")

labels = [ "public key", "shared secret", "known tunnel domains", "timestamp", "state-assisted", "flow hint" ]
for k,v in decoded.items():
    pass
    #print(labels[k], v.hex() if isinstance(v, (bytes, bytearray)) else v)

try:
    pubKey = decoded[0] # a 33-byte, P-256, X9.62, compressed public key
    print(f"Client's static Public Key: { pubKey.hex() }")
    qrSecret = decoded[1]   # 16-byte random QR secret
    print(f"Shared secret: { qrSecret.hex() }")
    _ = decoded[2]  # number of assigned tunnel server domains known to this implementation
    timestamp = decoded[3] # current time in epoch seconds
    print(f"time: { datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') }")
    _ = decoded[4]  # true if the device displaying the QR code can perform state-assisted transactions (e.g. Chrome)
    cmd = decoded[5]    # ga (get assertion) or mc (make credential)
    assert cmd == 'ga'
except KeyError as error:
    print(f"Key not Found: { error } ")
    sys.exit(1)

#

eidKey = derive(qrSecret, purpose=keyPurposeEIDKey) # no salt
print(f"EID Key: { eidKey.hex() }")


# Construct payload for BLE advertisement:
# flag(1) | nonce(10) | routingID(3) | tunnel ID(2)

flags = b'\0'
nonce = secrets.token_bytes(10)
routingID = secrets.token_bytes(3)
# 0x0000 = Google (cable.ua5v.com), 0x0100 = Apple (cable.auth.com), ..., 0x0001 = cable.qz2ekwmnd332c.info
tunnel_serviceID = b'\x05\x01' # cable.pyzci7hxyjsvc.org

payload = b''.join([ flags, nonce, routingID, tunnel_serviceID ])
print(f"Payload: { payload.hex() }")

# encrypt payload to prove proximity to the client
serviceData = encrypt(eidKey, payload)
print(f"Encrypted Payload: { serviceData.hex() }")

print(f"deriving psk from shared secret {qrSecret.hex()} and advertisement plaintext {payload.hex()}")
psk = derive(qrSecret, payload, keyPurposePSK)  # payload is used as salt
print(f"psk: { psk.hex() }")

psk = psk[:32] # TODO: is this correct?
responder.set_psks(psk)

responder.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, pubKey)
responder.set_as_responder()

# TODO: is psk derived from unencrypted (patload) or encrypted (serviceData) ??

# start tunnel service
threading.Thread(target=run_asyncio).start()

### Mainloop / asyncio

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
# we're assuming the adapter supports advertising
adapter_path = BLUEZ_NAMESPACE + ADAPTER_NAME
print(f"BLE Adapter path: {adapter_path}")

adv_mgr_interface = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME,adapter_path), ADVERTISING_MANAGER_INTERFACE)
# service data
serviceDict = { FIDO_UUID : dbus.Array(serviceData, signature='y') }
# we're only registering one advertisement object so index (arg2) is hard coded as 0
adv = Advertisement(bus, 0, 'broadcast', dbus.Dictionary(serviceDict, signature='sv'))
start_advertising()

# TODO: handle KeyboardInterrupt
try:
    mainloop = GLib.MainLoop()
    mainloop.run()
except KeyboardInterrupt:
    print("Attempting graceful shutdown, press Ctrl+C again to exit...", flush=True)
    mainloop.quit()

