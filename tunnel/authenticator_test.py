import secrets
from websockets.sync.client import connect

# the tunnel service under test - replace with your tunnel server (this is Google)
domain = "cable.ua5v.com"

tunnel_id = secrets.token_bytes(16).hex().upper()
print(f"[authenticator] random tunnel_id {tunnel_id}")
uri = f"wss://{domain}/cable/new/{tunnel_id}"
print(f"[authenticator] connecting to {uri}")
try:
    with connect(uri, subprotocols=["fido.cable"],
                  additional_headers={"Origin": f"wss://{domain}"},
                  open_timeout=10) as ws:
        routing_id = ws.response.headers.get("X-caBLE-Routing-ID")
        print(f"[authenticator] connected, routing_id={routing_id}")
        uri2 = f"wss://{domain}/cable/connect/{routing_id}/{tunnel_id}"
        print(f"\nclient, connect to:\n{uri2}")

        try:
            msg = ws.recv(timeout=20)
            print(f"[authenticator] received ({len(msg) if hasattr(msg,'__len__') else '?'} bytes): "
                  f"{msg.hex() if isinstance(msg, (bytes, bytearray)) else msg!r}")
            ws.send(b'\xAA\xBB\xCC\xDD')
            print("[authenticator] sent reply 0xAABBCCDD")
        except TimeoutError:
            print("[authenticator] timed out waiting for message")
except Exception as exc:
    print(f"[authenticator] ERROR: {type(exc).__name__}: {exc}")
