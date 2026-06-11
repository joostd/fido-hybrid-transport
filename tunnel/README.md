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

## moving to a different host

To move the relay (and its `cable.pyzci7hxyjsvc.org` domain) to a new host:

1. Migrate the Let's Encrypt cert + renewal state so the new host can keep
   auto-renewing:

       # on the old host
       sudo tar czf /tmp/letsencrypt-backup.tar.gz -C /etc letsencrypt
       scp /tmp/letsencrypt-backup.tar.gz new-host:/tmp/

       # on the new host
       sudo tar xzf /tmp/letsencrypt-backup.tar.gz -C /etc

   then symlink `fullchain.pem`/`privkey.pem` as in `## cert` above.

2. Point `cable.pyzci7hxyjsvc.org:443` at the new host -- update its DNS
   record if the new host has a different public IP, or update the router's
   port-443 forward if it's on the same network.

3. `uv sync` and `## run` as above on the new host.

4. Stop cert renewals on the old host (`sudo systemctl disable --now
   certbot.timer`) so the two hosts don't fight over the same Let's Encrypt
   account state.

5. Verify: `openssl s_client -connect cable.pyzci7hxyjsvc.org:443 -servername
   cable.pyzci7hxyjsvc.org` should show the migrated cert.

No changes are needed to `authenticator/main.py --tunnel-server local` or
`client/main.py` -- they only reference the domain name, so DNS/routing
determines which host they hit.
