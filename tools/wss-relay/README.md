# WSS relay for Telegram Desktop MTProto mux tunnel

## Deploy checklist

1. DNS A/AAAA for your domain.
2. Install Go 1.22+, build relay: `go build -o wss-relay`.
3. Install systemd unit from `wss-relay.service.example` (adjust `ExecStart` flags), then `systemctl daemon-reload && systemctl enable --now wss-relay`.
4. Copy `nginx.conf.example` to nginx sites, fix `server_name` and TLS paths.
5. `nginx -t && systemctl reload nginx`.
6. Open firewall TCP 443.
7. In tdesktop: `tg://wss?server=HOST&port=443&tunnels=6`.

## Client link format

```
tg://wss?server=HOST&port=443&tunnels=6&token=TOKEN
```

Path is always `/ws/mux` on the client. `tunnels` is the number of parallel mux WebSocket connections (1–9, default 6). `token` is optional unless relay auth is enabled.

## Authentication

Relay accepts (when `-auth-file` or `-auth-token` is set):

- `Authorization: Bearer <token>`

Token file (`auth.tokens.example`): one **SHA-256 hex hash** per line (see comments in the file). Generate:

```bash
printf 'my-secret-token' | sha256sum | awk '{print $1}'
```

Flags:

- `-auth-file` — path to hash list (recommended)
- `-auth-token` — single plaintext token (dev/single-user only)

Without either flag, mux accepts anonymous connections (backward compatible).

## Limits

Relay flags:

- `-max-tunnels-per-ip` — max concurrent mux WebSocket tunnels (`/ws/mux`) per client IP. Default `12` (about `tunnels × 2` for reconnect overlap). `0` disables the limit.
- `-max-streams` — max MTProto streams inside one mux tunnel. Default `256`.
- `-stream-idle-timeout` — close mux streams with no traffic for this long. Default `10m`. `0` disables.
- `-ws-ping-interval` — WebSocket ping interval per tunnel. Default `30s`. `0` disables.
- `-ws-read-timeout` — WebSocket read deadline, extended on traffic or pong. Default `90s`. `0` disables.
- `-telegram-only` — allow upstream TCP only to Telegram DC subnets from [cidr.txt](https://core.telegram.org/resources/cidr.txt). Default `true`. Set `false` only for local testing.

On the edge proxy, keep `read_timeout` / `write_timeout` near `2m` (see `Caddyfile.example`) so dead client connections do not keep relay tunnels open for hours.

Upstream targets are checked before dial (including DNS for hostnames) and again on the connected peer address.

Client IP is taken from `X-Real-IP`, then the first hop in `X-Forwarded-For`, then `RemoteAddr`. Set those headers only from a trusted reverse proxy.

Optional nginx edge guard: `limit_conn` on `/ws/mux` (see `nginx.conf.example`).

## Monitoring

Live dashboard on the relay listen address (`127.0.0.1:8283`):

- UI: `/stats` (auto-refresh every 2s)
- JSON: `/stats/json`

Disable with `-stats-path=""`. On the server, open via SSH tunnel:

```bash
ssh -L 8283:127.0.0.1:8283 root@HOST
```

Then browse `http://127.0.0.1:8283/stats`.

## Architecture

```
tdesktop --TLS+WS+mux--> edge:443 --WS--> wss-relay:8283 --TCP--> Telegram DC
```
