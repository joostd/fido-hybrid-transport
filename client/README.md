# FIDO Cross-Device Authentication client

This FIDO client written in Python uses hybrid transport to communicate with a FIDO Authenticator
Note that this client developed on macOS and is not tested on other platforms.

To install, create a virtual environment:

	python3 -m venv venv
	. venv/bin/activate

Install dependencies:

	pip install pyqrcode bleak cryptography cbor2 websockets

Run the client to send a CTAP get-info command:

	./main.py

Alternatively, use `uv`:

	uv run main.py

Then scan the QR code on your iPhone or Android device.

You can also use the authenticator in [../authenticator](../authenticator) with the FIDO: URI.

# Usage:

	python main.py	# get-info (default)
	python main.py make-credential --rp-id example.com
	python main.py get-assertion --rp-id example.com

