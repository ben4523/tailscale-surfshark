# tailscale-surfshark

Single Docker container that exposes a **Tailscale exit node** whose egress traffic is routed through **Surfshark** (WireGuard). A web UI, accessible only over Tailscale, lets you toggle Surfshark on/off, switch locations, and refresh the location list.

Built to be deployed on a Synology DS920+ (DSM 7, Container Manager). Works anywhere Docker + WireGuard + Tailscale do.

## Traffic flow

```
Client device → Tailscale → container (tailscale0) → wg0 → eth0 → ISP → Surfshark → Internet
```

## Architecture

See [`docs/superpowers/specs/2026-06-14-tailscale-surfshark-design.md`](docs/superpowers/specs/2026-06-14-tailscale-surfshark-design.md) for the full design rationale. TL;DR:

- One container, bridge networking (so it does not collide with Tailscale on the Synology host).
- A Go control daemon (PID 1) supervises `tailscaled` and `wg-quick`, applies iptables NAT + kill-switch rules, and serves the web UI on the container's tailnet IP.
- State persists in `./data/` (Tailscale identity, cached Surfshark configs, generated WireGuard keypair, `state.json`).
- Kill switch and auto-failover are ON by default, configurable via env vars.

## Quick start (Synology DSM 7)

1. SSH into your Synology, `cd /volume1/docker/`.
2. `git clone <this repo> tailscale-surfshark && cd tailscale-surfshark`
3. Copy and fill the env file:

   ```bash
   cp .env.example .env
   chmod 600 .env
   nano .env
   ```

   Required: `TS_AUTHKEY`, `TS_ALLOWED_USERS`, `SURFSHARK_EMAIL`, `SURFSHARK_PASSWORD`.

4. In the Tailscale admin: generate a **reusable, no-expiry pre-auth key** tagged `tag:exit-node`. In your tailnet ACL, ensure `autoApprovers.exitNode` includes `tag:exit-node` so the new device doesn't require manual approval.
5. Bring it up:

   ```bash
   docker compose up -d --build
   ```

6. In the Tailscale admin, the new device should appear (default hostname: `synology-surfshark-exit`).
7. Open the UI from any device on your tailnet: browse to `http://<tailnet-ip-of-exit-node>:8080`. Identity is verified through Tailscale — only emails listed in `TS_ALLOWED_USERS` get in.
8. On client devices that should use the exit node: Tailscale admin → device → "Use exit node" → pick `synology-surfshark-exit`.

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `TS_AUTHKEY` | yes | — | Tailscale pre-auth key, tagged `tag:exit-node` |
| `TS_ALLOWED_USERS` | yes | — | Comma-separated tailnet emails allowed to use the UI |
| `TS_HOSTNAME` | no | `synology-surfshark-exit` | Shown in the Tailscale admin |
| `SURFSHARK_EMAIL` | no¹ | — | Required to auto-fetch the location list |
| `SURFSHARK_PASSWORD` | no¹ | — | Same |
| `KILL_SWITCH` | no | `true` | If `true`, exit-node clients lose internet when wg0 is down |
| `FAILOVER` | no | `true` | If `true`, watchdog switches to next preferred location when wg0 stays unhealthy |
| `SURFSHARK_API_BASE` | no | `https://api.surfshark.com` | Override for testing |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` |

¹ Optional, but if both are unset and `./data/surfshark/configs/` is empty, the UI will only have manually-dropped configs to choose from.

## Manual verification checklist

Run after every deployment or release. The unit-test suite covers all internal logic; this checklist validates the runtime behavior that only a real tailnet + ISP can exercise.

- [ ] First boot with real Surfshark creds → `./data/surfshark/configs/` populates within ~30s.
- [ ] Tailscale client (MacBook) set to "Use exit node = synology-surfshark-exit" → `curl ifconfig.io` returns a Surfshark egress IP.
- [ ] `tailscale ping <exit-node>` shows `via DIRECT` (not DERP). Relay means firewall is blocking UDP — see the reference blog post.
- [ ] Client speed test > 50 Mbps (relay caps near 10).
- [ ] Switch location via UI → public IP changes within 10s.
- [ ] Toggle OFF + `KILL_SWITCH=true` → exit-node client loses internet (red banner not shown, kill switch is armed).
- [ ] Toggle OFF + `KILL_SWITCH=false` → exit-node client keeps internet via Synology ISP IP. UI shows a persistent **red bypass banner**.
- [ ] Force Surfshark drop (block UDP outbound briefly via host firewall) → auto-failover triggers within 2 min, UI shows a yellow banner with `from → to`.
- [ ] Reboot Synology → container restarts, Tailscale identity is the same, cached configs intact, toggle state restored.

## Operations

### Logs

```bash
docker logs -f tailscale-surfshark
```

Structured JSON; every user-initiated action is logged with the caller's tailnet identity.

### Drop additional configs manually

If Surfshark adds a region you want and you don't want to wait for next refresh, drop `<location-id>.json` files (same schema as the cached ones) into `./data/surfshark/configs/`. The UI dropdown updates on next status fetch.

### Disable kill switch temporarily

```bash
sed -i 's/^KILL_SWITCH=.*/KILL_SWITCH=false/' .env
docker compose up -d
```

The persistent red banner makes "I forgot bypass was on" failure mode loud.

### Reset everything

```bash
docker compose down
rm -rf ./data/
```

You will need a new pre-auth key for next boot (the persisted Tailscale identity is gone).

## Troubleshooting

- **UI unreachable:** verify `tailscale status` on a client shows the exit-node device as Online. Then check `docker logs tailscale-surfshark` for the `http listening` line — the bind IP must be the tailnet IPv4. If it's `0.0.0.0`, the container couldn't read the tailnet IP at boot (usually `tailscaled` hadn't authenticated yet).
- **Speeds < 20 Mbps:** likely DERP-relayed (firewall blocking UDP). See the reference blog post for the OPNsense rule that fixed this for the author.
- **All configs unusable after refresh:** Surfshark may have revoked the keypair server-side. Delete `./data/surfshark/keys/` and click "Refresh from Surfshark" in the UI — a new keypair will be generated and registered.
- **Smoke test fails locally:** `make smoke` validates entrypoint env wiring on Docker Desktop. Full behavior requires a real tailnet (see the manual checklist).

## Development

Local commands:

```bash
make build           # Go binary at bin/surfshark-control
make test            # unit tests with -race
make image           # Docker build (multi-stage, ~75 MB final image)
make smoke           # boots the container and asserts entrypoint validates env
```

Go ≥ 1.25 required (matches `go.mod`). The Dockerfile pins `golang:1.25-alpine` for the build stage.

## Reference

This project automates the manual setup described in [a blog post about tailscale + surfshark on a Debian VM], packaged as a single Synology-ready container.
