# caBLE Tunnel Relay

tunnel/main.py is a self-hosted replacement for Google's undocumented
`cable.ua5v.com` caBLE tunnel relay. It implements the same two endpoints:

- `wss://<host>/cable/new/<tunnel_id_hex>` -- the authenticator registers a
  tunnel and gets back a 101 response with an `X-caBLE-Routing-ID` header.
- `wss://<host>/cable/connect/<routing_id_hex>/<tunnel_id_hex>` -- the
  initiator/browser connects using the routing ID + tunnel ID from the BLE
  advert, and is bidirectionally relayed to the `/cable/new/` connection.

The relay never sees plaintext (the Noise handshake and all CTAP messages are
end-to-end encrypted between the authenticator and the initiator) -- it just
pipes binary WebSocket frames between the two connections.

## cert

Reuses the project's `cable.pyzci7hxyjsvc.org` domain (see
`authenticator/README.md`'s `## cert` section):

    apt install certbot
    certbot certonly -d cable.pyzci7hxyjsvc.org     # adapt to your domain
    ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/fullchain.pem
    ln -s /etc/letsencrypt/live/cable.pyzci7hxyjsvc.org/privkey.pem

## run

    sudo uv run main.py

Binds `:443` with TLS, so it must run as root.

Use with `authenticator/main.py --tunnel-server local`, which registers a
tunnel here (instead of with Google) and embeds `cable.pyzci7hxyjsvc.org` in
the BLE advert.
