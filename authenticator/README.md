# FIDO Cross-Device Authenticator

## deps

sudo apt install libdbus-1-dev libglib2.0-dev

## venv

python3 -m venv --system-site-packages venv
. venv/bin/activate

pip install cbor2 websockets cryptography dbus-python websockets

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
