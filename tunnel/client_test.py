import sys

from websockets.sync.client import connect
from websockets.exceptions import InvalidStatus

# the tunnel service under test - replace with your tunnel server (this is Google)
domain = "cable.ua5v.com"

uri = sys.argv[1]
# wss://{domain}/cable/connect/{routing_id}/{tunnel_id}
print(f"[client] connecting to {uri}")
try:
    with connect(uri, subprotocols=["fido.cable"],
                  additional_headers={"Origin": f"wss://{domain}"},
                  open_timeout=10) as ws:
        print("[client] CONNECTED!")
        ws.send(b'\x01\x02\x03\x04')
        print("[client] sent test message 0x01020304")
        try:
            msg = ws.recv(timeout=10)
            print(f"[client] received: {msg.hex() if isinstance(msg,(bytes,bytearray)) else msg!r}")
        except TimeoutError:
            print("[client] timed out waiting for reply")
except InvalidStatus as exc:
    resp = exc.response
    print(f"[client] HTTP status: {resp.status_code}")
    if resp.body:
        print(f"[client] body: {resp.body[:300]!r}")
except Exception as exc:
    print(f"[client] ERROR: {type(exc).__name__}: {exc}")
