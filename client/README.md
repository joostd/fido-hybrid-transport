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
python main.py make-credential --rp-id example.com --user-name "Alice Smith"
python main.py make-credential --rp-id example.com --user-id 0123456789abcdef --user-name "Alice"
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

### stdio-relay Mode

The `stdio-relay` command enables external processes (like [sk-hybrid.so](https://github.com/joostd/openssh-hybrid-sk-provider)) to use the caBLE transport by reading/writing length-prefixed CTAP frames over pipes:

- External process writes CTAP request frames to fd 3
- External process reads CTAP response frames from fd 4
- Wire format: `[4-byte big-endian length][CTAP frame bytes]`
- Request frames: `[0x01 CTAP_FRAME_CTAP][CTAP cmd byte][CBOR params...]`
- Response frames: `[CTAP status byte][CBOR body...]`

This allows sk-hybrid.so to delegate all BLE scanning, QR display, tunnel connection, and Noise encryption to this Python client while handling only CTAP framing in C.

The client displays the QR code and BLE scan output on the terminal (fds 0/1/2) while CTAP frames are exchanged on fds 3/4, so the user can see connection status while the external process communicates with the authenticator.

## Options

- `--rp-id <domain>` - Relying party identifier (default: example.com)
- `--user-id <hex>` - User ID in hex for make-credential (default: user-name as UTF-8)
- `--user-name <name>` - User name for make-credential (required for make-credential)
- `--display-name <name>` - User display name for make-credential (default: same as --user-name)
- `--hint <mc|ga>` - FIDO URI command hint (mc=makeCredential, ga=getAssertion)
- `--server <url>` - WebSocket server URL (for usb-relay mode)
- `--log-level <DEBUG|INFO|WARNING|ERROR>` - Logging level (default: INFO). Use DEBUG to see all raw CTAP messages and tunnel establishment with hex dumps

See the main [README](../README.md) for detailed usage and security considerations.
