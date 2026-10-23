"""BLE L2CAP data transport for the hybrid/caBLE client (macOS).

The Proximity Exchange Protocol allows the data transfer channel to be a BLE
L2CAP connection-oriented channel instead of a websocket to a tunnel server,
which lets the authenticator complete a transaction with no internet access:

    https://fidoalliance.org/specs/hybrid/proximity-exchange-protocol-v1.0-wd-20260717.html#sctn-ble-channel

The client advertises support by listing transport channel 1 under key 6 of the
QR code.  An authenticator that supports it then opens an insecure L2CAP CoC
server socket and appends the PSM to its BLE advertisement as a CBOR map
``{1: psm}`` following the 20-byte advert.  Every message on the socket is
prefixed with a 4-byte big-endian length.

This module provides a drop-in replacement for the websocket object used by
``main.py``: it exposes ``send()`` and ``recv(timeout=...)`` and works as a
context manager, so the Noise handshake and CTAP exchange above it are
unchanged.

macOS only.  CoreBluetooth is the only route to L2CAP on macOS, since `bleak`
does not support it and Python's socket module has no AF_BLUETOOTH there.  On
Linux the equivalent is roughly:

    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                      socket.BTPROTO_L2CAP)
    s.connect((bd_addr, psm))
"""

from __future__ import annotations

import logging
import struct
import sys
import time

ADVERT_LEN = 20
FIDO_UUID_FRAGMENT = "fff9"
_CB_POWERED_ON = 5
_NS_STREAM_STATUS_OPEN = 2


class BleTransportError(Exception):
    pass


def psm_from_service_data(service_data: bytes):
    """Return the L2CAP PSM from an advertisement suffix, or None.

    The suffix is a CBOR map keyed by transport channel identifier; channel 1
    is BLE and its value is the PSM.
    """
    if len(service_data) <= ADVERT_LEN:
        return None
    try:
        from cbor2 import loads

        suffix = loads(service_data[ADVERT_LEN:])
    except Exception:
        return None
    if isinstance(suffix, dict):
        return suffix.get(1)
    return None


def _pump(seconds: float) -> None:
    from Foundation import NSDate, NSRunLoop

    NSRunLoop.currentRunLoop().runUntilDate_(
        NSDate.dateWithTimeIntervalSinceNow_(seconds)
    )


class BleL2capTransport:
    """A framed L2CAP channel that quacks like the websocket in main.py."""

    def __init__(self, channel, central, peripheral):
        self._channel = channel
        self._central = central
        self._peripheral = peripheral
        self._in = channel.inputStream()
        self._out = channel.outputStream()

        from Foundation import NSDefaultRunLoopMode, NSRunLoop

        runloop = NSRunLoop.currentRunLoop()
        for stream in (self._in, self._out):
            stream.scheduleInRunLoop_forMode_(runloop, NSDefaultRunLoopMode)
            stream.open()
        for _ in range(40):
            if (
                self._in.streamStatus() >= _NS_STREAM_STATUS_OPEN
                and self._out.streamStatus() >= _NS_STREAM_STATUS_OPEN
            ):
                break
            _pump(0.05)

    # -- websocket-compatible API ---------------------------------------
    def send(self, data: bytes) -> None:
        framed = struct.pack(">I", len(data)) + data
        sent = 0
        deadline = time.time() + 10
        while sent < len(framed) and time.time() < deadline:
            n = self._out.write_maxLength_(framed[sent:], len(framed) - sent)
            if n > 0:
                sent += n
            else:
                _pump(0.05)
        if sent != len(framed):
            raise BleTransportError(f"short write: {sent}/{len(framed)}")

    def recv(self, timeout: float = 10) -> bytes:
        length = struct.unpack(">I", self._read_exact(4, timeout))[0]
        return self._read_exact(length, timeout)

    def close(self) -> None:
        # `send()` only guarantees the bytes reached the OS, not the air.  The
        # last thing written is usually the shutdown frame, and tearing the
        # link down from under it would defeat the point of sending it.
        _pump(0.3)
        for stream in (self._in, self._out):
            try:
                stream.close()
            except Exception:
                pass
        try:
            self._central.cancelPeripheralConnection_(self._peripheral)
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- internals -------------------------------------------------------
    def _read_exact(self, count: int, timeout: float) -> bytes:
        buf = b""
        deadline = time.time() + timeout
        while len(buf) < count and time.time() < deadline:
            if self._in.hasBytesAvailable():
                chunk = self._in.read_maxLength_(None, count - len(buf))
                if isinstance(chunk, tuple):
                    n, data = chunk
                    if n > 0:
                        buf += bytes(data[:n])
                elif chunk:
                    buf += bytes(chunk)
            else:
                _pump(0.05)
        if len(buf) < count:
            raise TimeoutError(f"wanted {count} bytes, got {len(buf)}")
        return buf


def discover_and_connect(trial_decrypt, timeout: float = 120):
    """Scan for an advert we can decrypt, then open its L2CAP channel.

    `trial_decrypt` takes the 20-byte advert and returns the decrypted payload
    or None, so the caller keeps ownership of the key schedule.

    Returns (advert_payload, BleL2capTransport).
    """
    if sys.platform != "darwin":
        raise BleTransportError(
            "the BLE L2CAP transport is implemented for macOS only; "
            "on Linux use socket.AF_BLUETOOTH/BTPROTO_L2CAP"
        )

    import objc
    from CoreBluetooth import (
        CBAdvertisementDataServiceDataKey,
        CBCentralManager,
        CBCentralManagerScanOptionAllowDuplicatesKey,
    )
    from Foundation import NSObject

    class _Delegate(NSObject):
        def init(self):
            self = objc.super(_Delegate, self).init()
            self.payload = None
            self.psm = None
            self.peripheral = None
            self.channel = None
            self.error = None
            self.done = False
            return self

        def centralManagerDidUpdateState_(self, central):
            if central.state() == _CB_POWERED_ON:
                logging.info("Scanning for BLE advert (L2CAP transport)...")
                central.scanForPeripheralsWithServices_options_(
                    None, {CBCentralManagerScanOptionAllowDuplicatesKey: True}
                )
            else:
                self.error = f"Bluetooth unavailable (state {central.state()})"
                self.done = True

        def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
            self, central, peripheral, advertisementData, rssi
        ):
            if self.peripheral is not None:
                return
            service_data = advertisementData.get(CBAdvertisementDataServiceDataKey)
            if not service_data:
                return
            for uuid, value in service_data.items():
                if FIDO_UUID_FRAGMENT not in str(uuid.UUIDString()).lower():
                    continue
                raw = bytes(value)
                payload = trial_decrypt(raw[:ADVERT_LEN])
                if payload is None:
                    logging.debug("BLE advert not for this client - ignoring")
                    return
                psm = psm_from_service_data(raw)
                logging.info(f"BLE advert matched (rssi {rssi}), PSM {psm}")
                if psm is None:
                    self.error = (
                        "advert has no BLE channel in its suffix; the "
                        "authenticator did not offer the L2CAP transport"
                    )
                    self.done = True
                    return
                self.payload = payload
                self.psm = psm
                self.peripheral = peripheral
                peripheral.setDelegate_(self)
                central.stopScan()
                central.connectPeripheral_options_(peripheral, None)
                return

        def centralManager_didConnectPeripheral_(self, central, peripheral):
            logging.debug("connected; opening L2CAP channel")
            peripheral.openL2CAPChannel_(self.psm)

        def centralManager_didFailToConnectPeripheral_error_(self, c, p, error):
            self.error = f"connect failed: {error}"
            self.done = True

        def centralManager_didDisconnectPeripheral_error_(self, c, p, error):
            if self.channel is None:
                self.error = f"disconnected before L2CAP channel: {error}"
                self.done = True

        def peripheral_didOpenL2CAPChannel_error_(self, peripheral, channel, error):
            if error is not None or channel is None:
                self.error = f"openL2CAPChannel failed: {error}"
            else:
                self.channel = channel
            self.done = True

    delegate = _Delegate.alloc().init()
    central = CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)

    deadline = time.time() + timeout
    while time.time() < deadline and not delegate.done:
        _pump(0.25)

    if delegate.channel is None:
        raise BleTransportError(delegate.error or "timed out waiting for a BLE advert")

    logging.info(f"L2CAP channel open (PSM {delegate.channel.PSM()})")
    return delegate.payload, BleL2capTransport(
        delegate.channel, central, delegate.peripheral
    )
