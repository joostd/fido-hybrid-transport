# fido-hybrid-transport

FIDO2/WebAuthn hybrid transport (caBLE) implementation in Python for testing, development, and integration.

## Overview

This repository contains three components for working with FIDO hybrid transport:

- **[Client](client/)** - Test tool for connecting to phone authenticators and relaying CTAP commands
- **[Authenticator](authenticator/)** - Software/USB-backed authenticator with hybrid transport
- **[Tunnel Server](tunnel/)** - Self-hosted caBLE tunnel relay (alternative to Google's infrastructure)

## Quick Start

**Test with phone authenticator:**
```bash
# Client displays QR code, connect with phone
python client/main.py make-credential --user-name "Alice"

# Authenticate
python client/main.py get-assertion --rp-id example.com
```

<<<<<<< HEAD
**Note:** In single-command mode (get-info, make-credential, get-assertion), the client sends one CTAP command and exits. Your phone may display "Devices couldn't connect" or timeout after the client closes - this is expected behavior. For persistent connections, use `stdio-relay` or `usb-relay` modes.

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

=======
**Run software authenticator:**
>>>>>>> temp-fix
```bash
# Authenticator displays QR code for client to scan
python authenticator/main.py "FIDO:/..."
```

See component READMEs for detailed documentation:
- [Client documentation](client/README.md) - Commands, options, and integration guides
- [Authenticator documentation](authenticator/README.md) - Platform requirements and setup
- [Tunnel server documentation](tunnel/README.md) - Self-hosted relay deployment

## Use Cases

**Testing & Development:**
- Test client implementations (Chrome, Safari, browsers) against software authenticator
- Query mobile authenticator capabilities (iOS, Android)
- Debug CTAP protocol exchanges by observing message flow

**OpenSSH Integration:**  
- Use phone as FIDO2 authenticator for SSH via [sk-hybrid.so](https://github.com/joostd/openssh-hybrid-sk-provider)
- Client's `stdio-relay` mode provides caBLE transport for OpenSSH SK provider

**Remote USB Security Key:**
- Sign in on remote browser using local USB key (alternative to USB/IP)

## Security Considerations

**⚠️ Phishing Potential:**

The client can be used to mount phishing attacks by presenting malicious QR codes. **This tool is for testing and research only.** When scanning QR codes, always verify the origin and RP ID.

**⚠️ Remote USB Relay:**

The `--remote-usb` authenticator mode requires full trust in the remote client, which can send CTAP commands for any RP ID. Only use when you control both machines. For SSH with untrusted remotes, use local `stdio-relay` integration where OpenSSH enforces the RP ID.

See component READMEs for detailed security considerations.

## Requirements

Python 3.8+ with dependencies listed in each component's directory (websockets, cryptography, fido2, bleak, cbor2, pyqrcode).
