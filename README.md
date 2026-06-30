# fido-hybrid-transport

FIDO2/WebAuthn hybrid transport (caBLE) implementation in Python with three components: client, authenticator, and tunnel server.

## Components

### Client (`client/main.py`)

FIDO caBLE client that connects to phone authenticators or relays CTAP commands.

**Commands:**

- `get-info` - Query authenticator information (default)
- `make-credential` - Register a new credential  
- `get-assertion` - Authenticate with an existing credential
- `usb-relay` - Relay CTAP commands from a remote authenticator to a local USB security key
- `stdio-relay` - Relay CTAP frames over file descriptors 3/4 for use by external processes

**Common Options:**
- `--rp-id <domain>` - Relying party identifier (default: example.com)
- `--hint <mc|ga>` - FIDO URI command hint (mc=makeCredential, ga=getAssertion)
- `--server <url>` - WebSocket server URL (for usb-relay mode)

**Examples:**

```bash
# Display QR code and connect to phone authenticator to query its info
python client/main.py get-info

# Create a credential on phone authenticator
python client/main.py make-credential --rp-id example.com

# Authenticate with phone authenticator  
python client/main.py get-assertion --rp-id example.com

# Relay CTAP commands to local USB security key
python client/main.py usb-relay --server wss://example.com/usb-relay/token123

# Run as stdio relay for OpenSSH SK provider (see below)
python client/main.py stdio-relay --hint mc
```

**stdio-relay Mode:**

The `stdio-relay` command enables external processes (like [sk-hybrid.so](https://github.com/joostd/openssh-hybrid-sk-provider)) to use the caBLE transport by reading/writing length-prefixed CTAP frames over pipes:

- External process writes CTAP request frames to fd 3
- External process reads CTAP response frames from fd 4  
- Wire format: `[4-byte big-endian length][CTAP frame bytes]`
- Request frames: `[0x01 CTAP_FRAME_CTAP][CTAP cmd byte][CBOR params...]`
- Response frames: `[CTAP status byte][CBOR body...]`

This allows sk-hybrid.so to delegate all BLE scanning, QR display, tunnel connection, and Noise encryption to this Python client while handling only CTAP framing in C.

### Authenticator (`authenticator/main.py`)

FIDO2 authenticator implementing hybrid transport with software or USB backend.

**Platform Requirements:**

Tested on Raspberry Pi (Raspberry Pi OS). Requires BLE advertising with custom service data:
- BlueZ 5.x or later
- D-Bus access to `org.bluez.LEAdvertisingManager1`
- BLE-capable Bluetooth hardware

On Raspberry Pi, BLE advertising works out of the box. Other Linux systems may require D-Bus permissions or running as root. Not tested on macOS (different BLE APIs).

**Usage:**

```bash
python authenticator/main.py <FIDO-URI> [options]
```

**Options:**
- `--usb` - Relay CTAP messages to local USB security key
- `--remote-usb` - Relay CTAP messages to remote USB key via usb-relay client
- `--relay-token <token>` - Secret token for /usb-relay endpoint (auto-generated if omitted)
- `--tunnel-server <google|local|self>` - Tunnel server mode:
  - `google` (default) - Use Google's cable.ua5v.com relay
  - `local` - Use custom tunnel at cable.pyzci7hxyjsvc.org
  - `self` - Host own WSS tunnel endpoint (requires root)

**Examples:**

```bash
# Software authenticator with Google tunnel relay
python authenticator/main.py "FIDO:/12345..."

# Relay to local USB security key
python authenticator/main.py "FIDO:/12345..." --usb

# Host own tunnel server (requires fullchain.pem/privkey.pem and root)
sudo python authenticator/main.py "FIDO:/12345..." --tunnel-server self

# Remote USB relay mode (requires root for port 443)
sudo python authenticator/main.py "FIDO:/12345..." --remote-usb
```

The authenticator displays a QR code, advertises over BLE, establishes a Noise-encrypted tunnel, and handles CTAP requests. Credentials are stored in `credentials.json`.

### Tunnel Server (`tunnel/main.py`)

Generic caBLE tunnel relay implementing the same protocol as Google's cable.ua5v.com:

- Authenticator connects to `/cable/new/<tunnel_id>` and receives routing ID
- Client connects to `/cable/connect/<routing_id>/<tunnel_id>`  
- Server relays binary WebSocket frames bidirectionally (never sees plaintext)

**Usage:**

```bash
sudo python tunnel/main.py
```

Requires `fullchain.pem` and `privkey.pem` in the working directory and root (binds port 443).

## Use Cases

**Testing Platform Implementations:**
- Test client implementations (Chrome, Safari, Windows Hello) against software authenticator
- Test mobile authenticators (iOS, Android) by querying capabilities with client

**Remote USB Security Key:**
- Sign in on remote browser using local USB key (USB/IP alternative)
- Use `--remote-usb` authenticator with `usb-relay` client

**OpenSSH Hybrid SK Provider:**  
- Use `stdio-relay` with [sk-hybrid.so](https://github.com/joostd/openssh-hybrid-sk-provider/tree/main)
- SSH authentication using phone as FIDO2 authenticator
- sk-hybrid.so builds CTAP frames, Python client handles caBLE transport

**CTAP Message Inspection:**
- Run client and authenticator together to observe CTAP protocol exchanges
- Useful for debugging and understanding FIDO2/WebAuthn flows

## Security Considerations

**⚠️ Phishing Potential:**

The client component can be used to mount phishing attacks by presenting users with a QR code that connects their authenticator to an attacker-controlled relying party. **This tool is intended for testing, research, and legitimate use cases only.** Do not use it for malicious purposes.

When scanning QR codes:
- Always verify the origin of the QR code
- Check that the relying party ID (RP ID) matches the service you intend to authenticate with
- Be cautious of unsolicited QR codes or authentication requests

**⚠️ Remote USB Relay Trust Model:**

The `--remote-usb` authenticator mode introduces significant security risks:

- **You must fully trust the remote client** connecting to your authenticator
- The remote client can send CTAP commands for **any RP ID**, not just the one you expect
- A malicious or compromised remote client could:
  - Register credentials for domains you don't control
  - Request assertions for arbitrary relying parties
  - Cause you to unknowingly authenticate to attacker-controlled services

**Only use `--remote-usb` when:**
- You control both the authenticator and client machines
- You trust the network path between them
- You understand that your USB security key will respond to any CTAP request the remote client sends

For production SSH use cases with untrusted remote machines, prefer local `stdio-relay` integration with sk-hybrid.so where the RP ID is enforced by OpenSSH on the client side.

## Requirements

See individual component directories for Python dependencies (websockets, cryptography, fido2, bleak, cbor2, pyqrcode, etc.).


