# FIDO Cross-Device Authentication Client

This FIDO client written in Python uses hybrid transport (caBLE) to communicate with a FIDO authenticator.
Developed on macOS and tested on Linux.

## Installation

Create a virtual environment:

```bash
python3 -m venv venv
. venv/bin/activate
```

Install dependencies:

```bash
pip install pyqrcode bleak cryptography cbor2 websockets fido2
```

Alternatively, use `uv`:

```bash
uv sync
```

## Usage

```bash
python main.py                                    # get-info (default)
python main.py make-credential --rp-id example.com
python main.py get-assertion --rp-id example.com
python main.py usb-relay --server wss://example.com/usb-relay/<token>
python main.py stdio-relay --hint mc             # for OpenSSH sk-hybrid.so
```

Run the client and scan the QR code on your iPhone or Android device.

You can also use the authenticator in [../authenticator](../authenticator) with the FIDO: URI.

## Expected Behavior

**Single-command mode** (`get-info`, `make-credential`, `get-assertion`):

The client sends one CTAP command (or uses cached info for `get-info`) and then exits. After scanning the QR code and establishing the caBLE connection:

1. **For `get-info`**: The client uses the cached authenticatorGetInfo from the post-handshake message (per caBLE spec) and exits immediately
2. **For `make-credential` or `get-assertion`**: The client sends the CTAP command, the phone processes it (with user interaction), sends the response, and the client exits
3. **The phone may show "Devices couldn't connect" or a timeout message** - this is expected behavior since the client closes the connection after receiving the response

Note: `get-info` uses the cached response because the caBLE protocol already provides this in the post-handshake message. iOS does not respond to redundant getInfo requests.

This is intended for testing individual CTAP commands. For persistent connections, use `stdio-relay` or `usb-relay` modes which keep the connection open until the external process closes the pipes.

## Commands

- `get-info` - Query authenticator information (default)
- `make-credential` - Register a new credential with `--rp-id`
- `get-assertion` - Authenticate with `--rp-id`
- `usb-relay` - Relay CTAP commands to a local USB security key for a remote authenticator
- `stdio-relay` - Relay CTAP frames over file descriptors 3/4 for external processes like [sk-hybrid.so](https://github.com/joostd/openssh-hybrid-sk-provider)

## Options

- `--rp-id <domain>` - Relying party identifier (default: example.com)
- `--hint <mc|ga>` - FIDO URI command hint (mc=makeCredential, ga=getAssertion)
- `--server <url>` - WebSocket server URL (for usb-relay mode)

See the main [README](../README.md) for detailed usage and security considerations.
