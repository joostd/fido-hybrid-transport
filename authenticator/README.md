# FIDO Cross-Device Authenticator

## deps

sudo apt install libdbus-1-dev libglib2.0-dev

python3 -m venv --system-site-packages venv
. venv/bin/activate

pip install websockets # dbus-python

python cda-authenticator.py 


## cert

apt install certbot
certbot certonly -d cable.pyzci7hxyjsvc.org     # adapt to your domain
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/fullchain.pem
ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/privkey.pem
