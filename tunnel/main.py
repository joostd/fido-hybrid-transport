#!/usr/bin/env python

# Generic two-party caBLE tunnel relay, replicating the observed behavior of
# Google's cable.ua5v.com: the authenticator opens
# wss://<host>/cable/new/<tunnel_id_hex> and gets back a 101 response with an
# X-caBLE-Routing-ID header; the initiator/browser then connects to
# wss://<host>/cable/connect/<routing_id_hex>/<tunnel_id_hex> and the two
# connections are relayed bidirectionally. The relay never sees plaintext --
# it just pipes binary WebSocket frames between the two connections.

import asyncio
import http
import logging
import secrets
import ssl

from websockets import serve

HOST = "0.0.0.0"
PORT = 443
TUNNEL_ID_LENGTH = 16    # bytes
ROUTING_ID_LENGTH = 3    # bytes
PAIRING_TIMEOUT = 180    # seconds to wait for the /cable/connect/ peer

# routing_id (bytes) -> (tunnel_id: bytes, new_websocket, peer_future)
pending = {}


class _SuppressHandshakeTracebacks(logging.Filter):
    """Random clients (port scanners, health checks, ...) constantly hit
    :443 without doing a WebSocket handshake; websockets logs each as an
    ERROR with a full traceback. Replace that with a one-line message."""

    def filter(self, record):
        if record.msg == "opening handshake failed":
            exc = record.exc_info[1] if record.exc_info else None
            print(f"Rejected non-WebSocket connection: {exc!r}")
            return False
        return True


logging.getLogger("websockets.server").addFilter(_SuppressHandshakeTracebacks())


def _parse_path(path):
    """Return ('new', tunnel_id) or ('connect', routing_id, tunnel_id), or
    None if the path doesn't match either form."""
    parts = path.strip("/").split("/")
    try:
        if len(parts) == 3 and parts[:2] == ["cable", "new"]:
            tunnel_id = bytes.fromhex(parts[2])
            return ("new", tunnel_id) if len(tunnel_id) == TUNNEL_ID_LENGTH else None
        if len(parts) == 4 and parts[:2] == ["cable", "connect"]:
            routing_id = bytes.fromhex(parts[2])
            tunnel_id = bytes.fromhex(parts[3])
            if len(routing_id) == ROUTING_ID_LENGTH and len(tunnel_id) == TUNNEL_ID_LENGTH:
                return ("connect", routing_id, tunnel_id)
            return None
    except ValueError:
        return None
    return None


def process_response(connection, request, response):
    """Validate the path, assign+advertise a routing ID for /cable/new/, and
    reject /cable/connect/ for unknown tunnels up front."""
    parsed = _parse_path(request.path)
    if parsed is None:
        return connection.respond(http.HTTPStatus.BAD_REQUEST, "Bad path\n")
    if parsed[0] == "new":
        routing_id = secrets.token_bytes(ROUTING_ID_LENGTH)
        connection.cable_routing_id = routing_id
        response.headers["X-caBLE-Routing-ID"] = routing_id.hex()
    else:
        _, routing_id, tunnel_id = parsed
        entry = pending.get(routing_id)
        if entry is None or entry[0] != tunnel_id:
            return connection.respond(http.HTTPStatus.NOT_FOUND, "Unknown tunnel\n")
    connection.cable_request = parsed
    return None


async def relay(a, b):
    """Pipe messages both ways between a and b until either side closes,
    then close both."""

    async def pump(src, dst):
        async for message in src:
            await dst.send(message)

    tasks = [asyncio.create_task(pump(a, b)), asyncio.create_task(pump(b, a))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(a.close(), b.close(), return_exceptions=True)


async def handle_new(websocket, tunnel_id):
    routing_id = websocket.cable_routing_id
    peer_future = asyncio.get_running_loop().create_future()
    pending[routing_id] = (tunnel_id, websocket, peer_future)
    print(f"new: tunnel {tunnel_id.hex()} -> routing_id {routing_id.hex()}")
    try:
        closed = asyncio.ensure_future(websocket.wait_closed())
        done, _ = await asyncio.wait(
            [peer_future, closed], timeout=PAIRING_TIMEOUT,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if peer_future not in done:
            if not closed.done():
                closed.cancel()
            print(f"new: routing_id {routing_id.hex()} timed out waiting for peer")
            return
        if not closed.done():
            closed.cancel()
    finally:
        pending.pop(routing_id, None)

    # The /cable/connect/ side (handle_connect) now drives the relay for both
    # connections; just wait here until it closes us.
    await websocket.wait_closed()


async def handle_connect(websocket, routing_id, tunnel_id):
    entry = pending.pop(routing_id, None)
    if entry is None or entry[0] != tunnel_id:
        await websocket.close(1008, "Unknown tunnel")
        return
    _, new_websocket, peer_future = entry
    peer_future.set_result(websocket)
    print(f"connect: routing_id {routing_id.hex()} -- relaying")
    await relay(new_websocket, websocket)


async def handler(websocket):
    parsed = websocket.cable_request
    if parsed[0] == "new":
        await handle_new(websocket, parsed[1])
    else:
        await handle_connect(websocket, parsed[1], parsed[2])


def load_ssl_context():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("fullchain.pem", keyfile="privkey.pem")
    return ssl_context


async def main():
    async with serve(handler, host=HOST, port=PORT, subprotocols=["fido.cable"],
                      process_response=process_response,
                      ssl=load_ssl_context()) as server:
        print(f"caBLE tunnel relay listening on wss://{HOST}:{PORT}")
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
