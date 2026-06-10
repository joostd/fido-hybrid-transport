# FIDO Cross-Device Authenticator

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
