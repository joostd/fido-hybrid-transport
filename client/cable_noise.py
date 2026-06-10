"""caBLE v2 Noise handshake implementation (CTAP 2.3 §11.5).

Self-contained copy of the noise layer from the claudemo client, adapted for
use as a standalone module.  Implements the three caBLE-specific deviations
from textbook Noise that `joostd/noiseprotocol` (and most other Noise libs)
do not handle:

  1. Prologue: two separate mixHash calls -- mixHash([0|1]) then
     mixHash(uncompressed_static_pubkey) -- before any tokens run.
  2. "e" token extra mixKey: both mixHash AND mixKey are called on the
     ephemeral public-key bytes (plain Noise only calls mixHash).
  3. AEAD nonce format: a 4-byte big-endian counter placed at the *start* of
     the 12-byte nonce during the handshake, and at the *end* for the
     post-handshake transport ciphers produced by split() -- two different
     layouts, both differing from the standard Noise placement.

Usage (responder side of KNpsk0):

    hs = NoiseHandshake(
        pattern=PATTERN_KN_PSK0,
        role="responder",
        local_static=generate_keypair(),   # authenticator's ephemeral static
        remote_static_public=client_pubkey_uncompressed,
        psk=psk_bytes,
    )
    plaintext = hs.read_message(msg1_from_initiator)
    msg2 = hs.write_message()
    result = hs.finish()
    # result.send_cipher / result.receive_cipher are CipherState objects
"""

from __future__ import annotations

import hmac as _hmac_mod
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOISE_DH_PUBLIC_KEY_SIZE = 65   # uncompressed P-256 point: 0x04 || X(32) || Y(32)
NOISE_HASH_SIZE = 32            # SHA-256 digest size
NOISE_AEAD_KEY_SIZE = 32        # AES-256
NOISE_AEAD_TAG_SIZE = 16
NOISE_AEAD_NONCE_SIZE = 12
QR_PEER_IDENTITY_SIZE = 33      # compressed X9.62 P-256 point
TRANSPORT_PADDING_GRANULARITY = 32

# Protocol name strings -- exactly 32 bytes (padded with NUL) so they fit in
# SHA-256's block and can be used directly as the initial h/ck value.
NOISE_PROTOCOL_KN = b"Noise_KNpsk0_P256_AESGCM_SHA256\0"
NOISE_PROTOCOL_NK = b"Noise_NKpsk0_P256_AESGCM_SHA256\0"

assert len(NOISE_PROTOCOL_KN) == 32
assert len(NOISE_PROTOCOL_NK) == 32

# Prologue discriminator byte: identifies which side's static key was
# pre-shared via the QR code (CTAP 2.3 sctn-hybrid).
NOISE_PROLOGUE_BYTE_RESPONDER_STATIC = 0   # NKpsk0: responder's key pre-shared
NOISE_PROLOGUE_BYTE_INITIATOR_STATIC = 1   # KNpsk0: initiator's key pre-shared

# ---------------------------------------------------------------------------
# Handshake patterns
# ---------------------------------------------------------------------------

PATTERN_KN_PSK0 = {
    "name": NOISE_PROTOCOL_KN,
    "prologue_owner": "initiator",
    "prologue_byte": NOISE_PROLOGUE_BYTE_INITIATOR_STATIC,
    "messages": [
        {"sender": "initiator", "tokens": ["psk", "e"]},
        {"sender": "responder", "tokens": ["e", "ee", "se"]},
    ],
}

PATTERN_NK_PSK0 = {
    "name": NOISE_PROTOCOL_NK,
    "prologue_owner": "responder",
    "prologue_byte": NOISE_PROLOGUE_BYTE_RESPONDER_STATIC,
    "messages": [
        {"sender": "initiator", "tokens": ["psk", "e", "es"]},
        {"sender": "responder", "tokens": ["e", "ee"]},
    ],
}

# ---------------------------------------------------------------------------
# DH adapter: P-256
# ---------------------------------------------------------------------------


@dataclass
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_bytes: bytes  # 65-byte uncompressed X9.62 point


def generate_keypair() -> KeyPair:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return KeyPair(private_key=private_key, public_bytes=serialize_public_key(private_key.public_key()))


def keypair_from_private_bytes(scalar: bytes) -> KeyPair:
    private_key = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    return KeyPair(private_key=private_key, public_bytes=serialize_public_key(private_key.public_key()))


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load a 65-byte uncompressed P-256 point."""
    if len(data) != NOISE_DH_PUBLIC_KEY_SIZE:
        raise ValueError(f"P-256 public key must be {NOISE_DH_PUBLIC_KEY_SIZE} bytes, got {len(data)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def deserialize_public_key_compressed(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load a 33-byte compressed P-256 point (as carried in the QR code)."""
    if len(data) != QR_PEER_IDENTITY_SIZE:
        raise ValueError(f"compressed P-256 public key must be {QR_PEER_IDENTITY_SIZE} bytes, got {len(data)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def dh(private_key: ec.EllipticCurvePrivateKey, public_key_bytes: bytes) -> bytes:
    peer = deserialize_public_key(public_key_bytes)
    return private_key.exchange(ec.ECDH(), peer)


# ---------------------------------------------------------------------------
# Transport padding
# ---------------------------------------------------------------------------


def pad_message(plaintext: bytes, granularity: int = TRANSPORT_PADDING_GRANULARITY) -> bytes:
    """Pad to a multiple of `granularity`; final byte = padding_count - 1."""
    extra = granularity - (len(plaintext) % granularity)
    return plaintext + bytes(extra - 1) + bytes([extra - 1])


def unpad_message(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("cannot unpad an empty message")
    n = padded[-1]
    if n + 1 > len(padded):
        raise ValueError("invalid padding")
    return padded[: len(padded) - 1 - n]


# ---------------------------------------------------------------------------
# CipherState
# ---------------------------------------------------------------------------


@dataclass
class CipherState:
    """AES-256-GCM with caBLE's two different 4-byte-counter nonce placements.

    Handshake ciphers use counter_prefix=True (counter in first 4 bytes).
    Transport ciphers produced by split() use counter_prefix=False (last 4).
    """

    key: bytes | None = None
    nonce: int = 0
    counter_prefix: bool = False

    def initialize(self, key: bytes) -> None:
        self.key = key
        self.nonce = 0

    def has_key(self) -> bool:
        return self.key is not None

    def _nonce_bytes(self) -> bytes:
        counter = self.nonce.to_bytes(4, "big")
        return (counter + b"\x00" * 8) if self.counter_prefix else (b"\x00" * 8 + counter)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.key is None:
            return plaintext
        ct = AESGCM(self.key).encrypt(self._nonce_bytes(), plaintext, ad)
        self.nonce += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.key is None:
            return ciphertext
        pt = AESGCM(self.key).decrypt(self._nonce_bytes(), ciphertext, ad)
        self.nonce += 1
        return pt


# ---------------------------------------------------------------------------
# SymmetricState
# ---------------------------------------------------------------------------


def _hkdf2(ck: bytes, ikm: bytes):
    prk = _hmac_mod.new(ck, ikm, "sha256").digest()
    out = HKDFExpand(algorithm=hashes.SHA256(), length=64, info=b"").derive(prk)
    return out[:32], out[32:]


def _hkdf3(ck: bytes, ikm: bytes):
    prk = _hmac_mod.new(ck, ikm, "sha256").digest()
    t1 = _hmac_mod.new(prk, b"\x01", "sha256").digest()
    t2 = _hmac_mod.new(prk, t1 + b"\x02", "sha256").digest()
    t3 = _hmac_mod.new(prk, t2 + b"\x03", "sha256").digest()
    return t1, t2, t3


@dataclass
class SymmetricState:
    chaining_key: bytes
    hash_value: bytes
    cipher: CipherState = field(default_factory=lambda: CipherState(counter_prefix=True))

    @classmethod
    def initialize(cls, protocol_name: bytes) -> "SymmetricState":
        if len(protocol_name) <= NOISE_HASH_SIZE:
            h = protocol_name + b"\x00" * (NOISE_HASH_SIZE - len(protocol_name))
        else:
            d = hashes.Hash(hashes.SHA256())
            d.update(protocol_name)
            h = d.finalize()
        return cls(chaining_key=h, hash_value=h)

    def mix_key(self, ikm: bytes) -> None:
        ck, temp_k = _hkdf2(self.chaining_key, ikm)
        self.chaining_key = ck
        self.cipher.initialize(temp_k)

    def mix_hash(self, data: bytes) -> None:
        d = hashes.Hash(hashes.SHA256())
        d.update(self.hash_value + data)
        self.hash_value = d.finalize()

    def mix_key_and_hash(self, ikm: bytes) -> None:
        ck, temp_h, temp_k = _hkdf3(self.chaining_key, ikm)
        self.chaining_key = ck
        self.mix_hash(temp_h)
        self.cipher.initialize(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cipher.encrypt_with_ad(self.hash_value, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cipher.decrypt_with_ad(self.hash_value, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        temp_k1, temp_k2 = _hkdf2(self.chaining_key, b"")
        c1, c2 = CipherState(), CipherState()
        c1.initialize(temp_k1)
        c2.initialize(temp_k2)
        return c1, c2


# ---------------------------------------------------------------------------
# HandshakeResult + NoiseHandshake
# ---------------------------------------------------------------------------


@dataclass
class HandshakeResult:
    send_cipher: CipherState
    receive_cipher: CipherState
    handshake_hash: bytes


class NoiseHandshake:
    """caBLE-compatible Noise handshake state machine (initiator or responder)."""

    def __init__(
        self,
        *,
        pattern: dict,
        role: str,
        local_static: KeyPair | None = None,
        local_ephemeral: KeyPair | None = None,
        remote_static_public: bytes | None = None,
        psk: bytes,
        debug_log: Callable | None = None,
    ) -> None:
        if role not in ("initiator", "responder"):
            raise ValueError(f"invalid role: {role!r}")
        self.pattern = pattern
        self.role = role
        self.psk = psk
        self.debug_log = debug_log or (lambda *_: None)
        self.symmetric = SymmetricState.initialize(pattern["name"])
        self.local_static = local_static
        self.local_ephemeral = local_ephemeral
        self.remote_static_public = remote_static_public
        self.remote_ephemeral_public: bytes | None = None
        self._message_index = 0
        self._apply_prologue()

    def _apply_prologue(self) -> None:
        """Two-step caBLE prologue: mixHash(discriminator_byte) then mixHash(uncompressed_static_pubkey)."""
        owner = self.pattern["prologue_owner"]
        self.symmetric.mix_hash(bytes([self.pattern["prologue_byte"]]))
        if owner == self.role:
            if self.local_static is None:
                raise ValueError("pattern requires a local static key")
            self.symmetric.mix_hash(self.local_static.public_bytes)
        else:
            if self.remote_static_public is None:
                raise ValueError("pattern requires a remote static key")
            self.symmetric.mix_hash(self.remote_static_public)

    def write_message(self, payload: bytes = b"") -> bytes:
        msg = self._next_message(expected_sender=self.role)
        out = bytearray()
        for token in msg["tokens"]:
            out += self._write_token(token)
        out += self.symmetric.encrypt_and_hash(payload)
        return bytes(out)

    def read_message(self, data: bytes) -> bytes:
        peer = "responder" if self.role == "initiator" else "initiator"
        msg = self._next_message(expected_sender=peer)
        offset = 0
        for token in msg["tokens"]:
            offset = self._read_token(token, data, offset)
        return self.symmetric.decrypt_and_hash(data[offset:])

    def _next_message(self, *, expected_sender: str) -> dict:
        if self._message_index >= len(self.pattern["messages"]):
            raise RuntimeError("handshake already complete")
        msg = self.pattern["messages"][self._message_index]
        if msg["sender"] != expected_sender:
            raise RuntimeError(f"out-of-order: expected {expected_sender!r}, got {msg['sender']!r}")
        self._message_index += 1
        return msg

    def is_complete(self) -> bool:
        return self._message_index >= len(self.pattern["messages"])

    def finish(self) -> HandshakeResult:
        if not self.is_complete():
            raise RuntimeError("handshake not complete")
        c1, c2 = self.symmetric.split()
        if self.role == "initiator":
            send_cipher, receive_cipher = c1, c2
        else:
            send_cipher, receive_cipher = c2, c1
        return HandshakeResult(send_cipher=send_cipher, receive_cipher=receive_cipher,
                               handshake_hash=self.symmetric.hash_value)

    def _write_token(self, token: str) -> bytes:
        if token == "e":
            if self.local_ephemeral is None:
                self.local_ephemeral = generate_keypair()
            # caBLE deviation: mixHash AND mixKey (not just mixHash as in plain Noise)
            self.symmetric.mix_hash(self.local_ephemeral.public_bytes)
            self.symmetric.mix_key(self.local_ephemeral.public_bytes)
            return self.local_ephemeral.public_bytes
        if token == "s":
            if self.local_static is None:
                raise ValueError("pattern requires a local static key")
            return self.symmetric.encrypt_and_hash(self.local_static.public_bytes)
        if token == "psk":
            self.symmetric.mix_key_and_hash(self.psk)
            return b""
        if token in ("ee", "es", "se", "ss"):
            self.symmetric.mix_key(self._dh_for_token(token))
            return b""
        raise ValueError(f"unsupported token: {token!r}")

    def _read_token(self, token: str, data: bytes, offset: int) -> int:
        if token == "e":
            key_bytes = data[offset: offset + NOISE_DH_PUBLIC_KEY_SIZE]
            if len(key_bytes) != NOISE_DH_PUBLIC_KEY_SIZE:
                raise ValueError("truncated message: missing ephemeral key")
            self.remote_ephemeral_public = key_bytes
            # caBLE deviation: mixHash AND mixKey
            self.symmetric.mix_hash(key_bytes)
            self.symmetric.mix_key(key_bytes)
            return offset + NOISE_DH_PUBLIC_KEY_SIZE
        if token == "s":
            has_key = self.symmetric.cipher.has_key()
            key_len = NOISE_DH_PUBLIC_KEY_SIZE + (NOISE_AEAD_TAG_SIZE if has_key else 0)
            encrypted = data[offset: offset + key_len]
            if len(encrypted) != key_len:
                raise ValueError("truncated message: missing static key")
            self.remote_static_public = self.symmetric.decrypt_and_hash(encrypted)
            return offset + key_len
        if token == "psk":
            self.symmetric.mix_key_and_hash(self.psk)
            return offset
        if token in ("ee", "es", "se", "ss"):
            self.symmetric.mix_key(self._dh_for_token(token))
            return offset
        raise ValueError(f"unsupported token: {token!r}")

    def _dh_for_token(self, token: str) -> bytes:
        """Resolve ee/es/se/ss to the correct local private key and remote public key."""
        first, second = token[0], token[1]
        local_map = {"e": self.local_ephemeral, "s": self.local_static}
        remote_map = {"e": self.remote_ephemeral_public, "s": self.remote_static_public}
        if self.role == "initiator":
            local_key = local_map[first]
            remote_pub = remote_map[second]
        else:
            local_key = local_map[second]
            remote_pub = remote_map[first]
        if local_key is None:
            raise ValueError(f"DH token {token!r}: local key not set")
        if remote_pub is None:
            raise ValueError(f"DH token {token!r}: remote key not set")
        return dh(local_key.private_key, remote_pub)
