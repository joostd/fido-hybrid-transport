# FIDO Cross-Device Authenticator

authenticator/main.py plays the CTAP "authenticator" role over hybrid
transport (caBLE): it does the BLE advert + Noise(KNpsk0) handshake with a
real browser, then answers CTAP requests either with its built-in software
authenticator or (with --usb) by relaying them verbatim to a USB security
key plugged into the same machine via fido2.hid.CtapHidDevice.

client/main.py is a test tool playing the "platform"/browser role: it
generates a FIDO URI/QR code, does the BLE scan + Noise handshake, and sends
a single get-info / make-credential / get-assertion request.

## deps

sudo apt install libdbus-1-dev libglib2.0-dev

## venv

python3 -m venv --system-site-packages venv
. venv/bin/activate

pip install cbor2 websockets cryptography dbus-python fido2

## cert

apt install certbot
certbot certonly -d cable.pyzci7hxyjsvc.org     # adapt to your domain
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/fullchain.pem
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/privkey.pem

# run

    sudo -s # must run as root
    source venv/bin/activate
    python main.py FIDO://... # scan the QR code from a CTAP client and paste the decoded FIDO URL

Point an existing CTAP 2.3 client at the Pi's WebSocket endpoint;
confirm the Noise handshake completes and `get-info` returns a valid response

## USB mode

Instead of using the built-in software authenticator, you can relay all CTAP
messages to a real USB FIDO2 security key (e.g. a YubiKey) plugged into the Pi:

    sudo -s
    source venv/bin/activate
    python main.py --usb FIDO://...

On startup, the authenticator scans for connected USB CTAPHID devices. If none
is found, it prints an error and exits. If multiple are found, it prints the
list and uses the first one.

In this mode, `getInfo` (including the post-handshake message) and every CTAP
request/response (`makeCredential`, `getAssertion`, etc.) are relayed verbatim
to/from the USB key. Touch prompts are forwarded to the physical key, so watch
its LED and touch it when it blinks.

## Remote USB Security Key

    Browser  <--caBLE (BLE+Noise, existing)-->  authenticator/main.py  <--WSS relay-->  client/main.py (usb-relay mode)  <--USB HID-->  Security key

	--remote-usb mode forwards the raw CTAP request/response bytes over a second WebSocket connection to client, which
 forwards them to/from a local USB key -- mirroring the existing --usb
 relay, just over the network.

client dials out to authenticator (which already self-hosts a public WSS server with a real TLS cert on :443), using a new path containing a random secret token; security relies on wss:// (TLS) plus that unguessable path -- no extra Noise/PSK layer for this channel.


