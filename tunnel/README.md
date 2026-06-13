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

## testing

To verify the relay is up and routing correctly, without running the full
authenticator/client BLE flow:

### handshake (curl)

curl >= 8.x has built-in `ws://`/`wss://` support, enough to check the
`/cable/new/` registration and `/cable/connect/` reject path:

    # register a tunnel, get a routing ID back
    TUNNEL_ID=$(openssl rand -hex 16)
    curl -sv --http1.1 -m 5 \
      -H "Sec-WebSocket-Protocol: fido.cable" \
      -H "Origin: wss://cable.pyzci7hxyjsvc.org" \
      "wss://cable.pyzci7hxyjsvc.org/cable/new/$TUNNEL_ID"
    # -> 101 Switching Protocols, X-caBLE-Routing-ID: <hex>

    # unknown routing ID is rejected
    curl -sv --http1.1 -m 5 \
      -H "Sec-WebSocket-Protocol: fido.cable" \
      -H "Origin: wss://cable.pyzci7hxyjsvc.org" \
      "wss://cable.pyzci7hxyjsvc.org/cable/connect/<bogus_routing_id>/$TUNNEL_ID"
    # -> 404 Not Found

### two-way relay (websocat)

For an end-to-end test of the actual relay (pairing `/cable/new/` with
`/cable/connect/` and exchanging bytes), use
[websocat](https://github.com/vi/websocat) ("netcat for websockets"):

    cargo install websocat

Terminal 1 (registers the tunnel; look for `X-CaBLE-Routing-ID` in the `-v`
log output):

    TUNNEL_ID=$(openssl rand -hex 16)
    echo "tunnel_id: $TUNNEL_ID"
    websocat -v --protocol fido.cable --origin wss://cable.pyzci7hxyjsvc.org \
      "wss://cable.pyzci7hxyjsvc.org/cable/new/$TUNNEL_ID"

Terminal 2 (connects using that routing ID + the same tunnel ID):

    websocat --protocol fido.cable --origin wss://cable.pyzci7hxyjsvc.org \
      "wss://cable.pyzci7hxyjsvc.org/cable/connect/<routing_id>/$TUNNEL_ID"

Once both are connected, anything typed (+ Enter) in one terminal should
appear in the other, confirming the relay pipes frames bidirectionally.

## running as a systemd service

For a persistent deployment, run the relay under systemd instead of a
foreground `sudo uv run main.py`:

    uv sync   # creates .venv/

`/etc/systemd/system/cable-tunnel.service`:

    [Unit]
    Description=caBLE tunnel relay
    After=network.target

    [Service]
    WorkingDirectory=/path/to/fido-hybrid-transport/tunnel
    ExecStart=/path/to/fido-hybrid-transport/tunnel/.venv/bin/python main.py
    Restart=on-failure
    ProtectSystem=strict
    ProtectHome=read-only
    PrivateTmp=yes
    ReadOnlyPaths=/etc/letsencrypt

    [Install]
    WantedBy=multi-user.target

Then:

    sudo systemctl daemon-reload
    sudo systemctl enable --now cable-tunnel
    sudo systemctl status cable-tunnel

Notes:

- `ProtectHome=read-only` (not `yes`): `uv sync` creates `.venv/bin/python`
  as a symlink into uv's managed Python under `~/.local/share/uv/python/...`.
  `ProtectHome=yes` hides `/home`/`/root` entirely inside the service's mount
  namespace, so that symlink target no longer exists and the service fails
  with `203/EXEC` ("Unable to locate executable"). `read-only` keeps it
  readable.
- Restart on cert renewal, so the relay picks up the renewed cert:

      # /etc/letsencrypt/renewal-hooks/deploy/cable-tunnel.sh
      #!/bin/sh
      systemctl restart cable-tunnel

  then `chmod +x` it.

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

## running behind an SSH reverse tunnel

To run the relay on a machine that isn't directly reachable on `:443`
(e.g. a home/local machine behind NAT), while still serving it as
`cable.pyzci7hxyjsvc.org:443` from a reachable host (e.g. the Ubuntu box
from `## moving to a different host`):

1. On the local machine, run the relay as usual (`## cert` + `## run` --
   it still binds its own `:443` with TLS):

       sudo uv run main.py

2. From the local machine, open a reverse tunnel to a high port on the
   remote host:

       ssh -R 8443:localhost:443 user@cable.pyzci7hxyjsvc.org

   Use a high port (>1024), not `443` -- `sshd`'s default `GatewayPorts no`
   restricts `-R 443:...` listeners to `127.0.0.1` on the remote (so they're
   unreachable from outside), and binding `-R` to a privileged port like
   `443` generally requires the SSH session itself to be root.

3. On the remote host, redirect public `:443` to the forwarded port. The
   `-R 8443:...` listener is bound to `127.0.0.1:8443` (`sshd`'s default
   `GatewayPorts no` restricts it to loopback), so `REDIRECT` doesn't work
   here -- it rewrites the destination to the host's public IP, which has no
   `:8443` listener. Instead, `DNAT` straight to the loopback listener, and
   allow loopback as a NAT destination for externally-arriving packets:

       sudo sysctl -w net.ipv4.conf.all.route_localnet=1
       sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8443

   To persist across reboots: add `net.ipv4.conf.all.route_localnet=1` to a
   file in `/etc/sysctl.d/`, and save the iptables rule with `iptables-save`
   (e.g. via `iptables-persistent`) or add an equivalent `nftables`/`ufw`
   rule.

4. Verify as in step 5 of `## moving to a different host`.

Nothing else needs to run on the remote host's `:443` -- the relay process,
TLS termination, and cert all stay on the local machine.
