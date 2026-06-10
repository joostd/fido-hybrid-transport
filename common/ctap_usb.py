import sys

from fido2.hid import CtapHidDevice


def select_usb_device():
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        print("No USB CTAP device found.")
        sys.exit(1)
    if len(devices) > 1:
        print(f"Found {len(devices)} USB CTAP devices, using the first:")
        for d in devices:
            print(f"  {d}")
    for extra in devices[1:]:
        extra.close()
    device = devices[0]
    print(f"Relaying CTAP messages to USB device: {device}")
    return device
