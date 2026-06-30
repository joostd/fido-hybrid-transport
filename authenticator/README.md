# FIDO Cross-Device Authenticator

authenticator/main.py plays the CTAP "authenticator" role over hybrid
transport (caBLE): it does the BLE advert + Noise(KNpsk0) handshake with a
real browser or client, then answers CTAP requests either with its built-in
software authenticator or (with --usb / --remote-usb) by relaying them to a
USB security key via fido2.hid.CtapHidDevice.

client/main.py is a test tool playing the "platform"/browser role: it
generates a FIDO URI/QR code, does the BLE scan + Noise handshake, and sends
CTAP commands (get-info, make-credential, get-assertion) or runs in relay
modes (usb-relay, stdio-relay).

## deps

sudo apt install libdbus-1-dev libglib2.0-dev python3-gi python3-dbus python3-cairo

## venv

python3 -m venv --system-site-packages venv
. venv/bin/activate

pip install cbor2 websockets cryptography dbus-python fido2

### using uv instead

`gi` (PyGObject, for the BLE-advertising GLib mainloop) and `dbus` come from
the system packages above and aren't installable as plain wheels, so create
uv's `.venv` with `--system-site-packages` so it can see them:

    uv venv --system-site-packages
    uv sync
    uv run main.py FIDO://...

## cert

apt install certbot
certbot certonly -d cable.pyzci7hxyjsvc.org     # adapt to your domain
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/fullchain.pem
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/privkey.pem

# run

    source venv/bin/activate
    python main.py FIDO://... # scan the QR code from a CTAP client and paste the decoded FIDO URL

Point an existing CTAP 2.3 client at the Pi's WebSocket endpoint;
confirm the Noise handshake completes and `get-info` returns a valid response

Root is only required to bind port 443 (`--tunnel-server self` or
`--remote-usb`); run as root (`sudo -s`) in that case.

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

`--remote-usb` mode forwards the raw CTAP request/response bytes over a second WebSocket connection to client, which
forwards them to/from a local USB key -- mirroring the existing --usb
relay, just over the network.

client dials out to authenticator (which already self-hosts a public WSS server with a real TLS cert on :443), using a new path containing a random secret token; security relies on wss:// (TLS) plus that unguessable path -- no extra Noise/PSK layer for this channel.

**⚠️ Security Warning:** When using `--remote-usb`, you must fully trust the remote client. The client can send CTAP commands for any RP ID, potentially causing you to authenticate to unintended services. Only use this mode when you control both machines. See the main [README](../README.md) for security considerations.


