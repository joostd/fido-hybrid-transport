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

**Run software authenticator:**
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
