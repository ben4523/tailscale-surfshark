# Tailscale-Surfshark Exit Node — Design

- **Date:** 2026-06-14
- **Status:** Approved (brainstorming complete, ready for implementation planning)
- **Author:** 7571645+ben4523@users.noreply.github.com
- **Target host:** Synology DS920+ (DSM 7, Container Manager)

## 1. Goal

Ship a single Docker container that acts as a Tailscale exit node whose egress traffic is routed through Surfshark (WireGuard). A web UI, accessible only over Tailscale, lets the operator toggle Surfshark on/off, switch locations, and refresh the location list from Surfshark.

The product replaces the bespoke Debian VM setup described in the reference blog post with a portable, self-contained image deployable on any Docker host (initially: a Synology DS920+ already running Tailscale at the host level).

### Traffic flow

```
Client device → Tailscale → container (tailscale0) → wg0 → eth0 → ISP → Surfshark → Internet
```

### Non-goals

- Multi-user RBAC, billing, quotas.
- Bandwidth graphs, historical metrics.
- Auto-discovery of Surfshark configs without an account.
- Replacing the Tailscale instance already running on the Synology host.

## 2. Architecture

A single container running on the Synology, in **bridge networking mode** (not host — to avoid colliding with the host's Tailscale instance on `tailscale0`).

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Synology DS920+ (DSM 7, host)                    │
│   ┌──────────────┐                                                  │
│   │  Tailscale   │  ← existing host instance, untouched             │
│   │   (host)     │                                                  │
│   └──────────────┘                                                  │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  Container (bridge net, cap NET_ADMIN, /dev/net/tun)        │   │
│   │   ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │   │
│   │   │  tailscaled  │  │   wg-quick   │  │  Go control     │   │   │
│   │   │ (exit node)  │  │ (Surfshark)  │  │  daemon + UI    │   │   │
│   │   └──────┬───────┘  └──────┬───────┘  └────────┬────────┘   │   │
│   │     tailscale0          wg0                  HTTP on        │   │
│   │          │                │                  tailscale IP   │   │
│   │          └───────┬────────┘                                 │   │
│   │                  │ iptables: FORWARD tailscale0→wg0,        │   │
│   │                  │           MASQUERADE on wg0,             │   │
│   │                  │           kill-switch DROP when wg0 down │   │
│   │                  ▼                                          │   │
│   │              eth0 (bridge → Synology LAN → router)          │   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Container requirements

- `cap_add: [NET_ADMIN]`
- `devices: [/dev/net/tun:/dev/net/tun]`
- `sysctls: { net.ipv4.ip_forward=1, net.ipv6.conf.all.forwarding=1 }`
- `restart: unless-stopped`
- One persistent volume `./data → /data`
- Bridge network (default)

### Why one container

`tailscaled`, `wg-quick`, and the control daemon must share a single network namespace — splitting them would block FORWARD between interfaces. Single-container is the simplest viable boundary.

## 3. Components

### 3.1 `tailscaled` (Tailscale daemon, kernel-mode)

- Installed in the image via apk (Alpine base).
- Launched in background by `entrypoint.sh`. The Go daemon supervises it via a 30s health check (`tailscale status`) and restarts it on failure (3 consecutive failures within 5 minutes → container exits, Docker restart policy takes over).
- Auth via `TS_AUTHKEY` env var at first boot. State persisted in `/data/tailscale/` so the node identity is stable across container recreations.
- Flags: `--advertise-exit-node --accept-routes --accept-dns=false --hostname=$TS_HOSTNAME`.
- Exposes Unix socket `/var/run/tailscale/tailscaled.sock`, used by the Go daemon for `tailscale whois` (UI auth) and `tailscale status` (dashboard data).

### 3.2 Surfshark WireGuard (`wg0` via `wg-quick`)

- Not a long-running daemon. The kernel WireGuard interface is created on demand by `wg-quick up wg0` and removed by `wg-quick down wg0`.
- The Go daemon writes `/etc/wireguard/wg0.conf` from the selected cached config + the persistent keypair (`/data/surfshark/keys/`) before bringing the interface up.
- "Surfshark ON" state == `wg0` interface present and healthy.

### 3.3 Go control daemon (PID 1)

The main container process. Single static binary, image based on `alpine` (we need `iproute2`, `wireguard-tools`, `iptables`, `tailscale`).

Modules:

- **HTTP server:** binds on the container's Tailscale IPv4 (resolved at startup via `tailscale ip -4`), port 8080.
- **Identity middleware:** on every request, calls `tailscale whois <source-ip>` via the Unix socket. Resolves to a tailnet identity (email). Checks against `TS_ALLOWED_USERS` whitelist. Rejects with 401 if not found or not whitelisted. No sessions, no cookies — identity verified per request.
- **State manager:** in-memory struct, persisted to `/data/state.json` (atomic write via temp + rename).
- **Surfshark API client:** authenticates with `SURFSHARK_EMAIL` / `SURFSHARK_PASSWORD`, registers the local WireGuard public key, fetches the server list, materializes one `.conf` per location into `/data/surfshark/configs/`.
- **Iptables manager:** applies and tears down NAT/FORWARD/kill-switch rules. Idempotent — safe to re-run on every state transition.
- **Watchdogs:**
  - `tailscaled-watchdog`: 30s interval, restart on failure.
  - `wg-watchdog`: 30s interval when toggle is ON. Triggers recovery if no handshake for 90s OR ping `1.1.1.1` via wg0 fails 3× in 30s.
  - `status-poller`: refreshes public IP via `https://ifconfig.io` through wg0 every 60s; refreshes wg0 last-handshake / latency every 10s.

### 3.4 `entrypoint.sh`

- Validates required env vars (`TS_AUTHKEY`, `TS_ALLOWED_USERS`). Exits 1 with a clear message if missing.
- Launches `tailscaled` in background, waits up to 30s for the socket to appear.
- Calls `tailscale up --authkey=$TS_AUTHKEY --advertise-exit-node --accept-routes --accept-dns=false --hostname=$TS_HOSTNAME` (idempotent — succeeds on re-runs once state is persisted).
- `exec`s the Go binary as PID 1 (`exec /app/surfshark-control`).

### 3.5 Volume layout (`/data`)

```
/data/
├── tailscale/            # TS state directory (node identity, tokens)
├── surfshark/
│   ├── configs/          # one .conf per cached location
│   ├── keys/             # generated WireGuard keypair (0600)
│   └── last-fetch.json   # cache metadata (timestamp, server count)
├── state.json            # UI state (current location, toggle, kill switch effective)
└── logs/                 # rolling logs, 10 MB × 5
```

## 4. Data Flow

### 4.1 Cold boot (first start)

1. Container Manager runs `docker compose up`.
2. `entrypoint.sh` validates env, starts `tailscaled`, runs `tailscale up`, then execs the Go daemon.
3. Go daemon:
   - Loads `state.json` (or initializes defaults if missing).
   - Checks `/data/surfshark/configs/`. If empty and `SURFSHARK_EMAIL`/`PASSWORD` present:
     - Generates a WireGuard keypair into `/data/surfshark/keys/`.
     - Logs into Surfshark API, registers the public key, fetches the server list, writes one `.conf` per location.
   - Applies base iptables (MASQUERADE on wg0, FORWARD tailscale0 → wg0).
   - If `KILL_SWITCH=true` and toggle is ON, arms the kill-switch rule (DROP FORWARD tailscale0 → eth0 except via wg0).
   - If toggle is ON, runs `wg-quick up wg0` with the selected location.
   - Starts HTTP server on tailscale-ip:8080.
   - Starts watchdogs.

### 4.2 Toggle Surfshark OFF

1. `POST /api/surfshark/toggle {enabled: false}`.
2. Identity middleware verifies caller.
3. Handler runs `wg-quick down wg0`.
4. If `KILL_SWITCH=true`: kill-switch DROP rule kept active → exit-node clients lose internet (intended).
5. If `KILL_SWITCH=false`: ACCEPT FORWARD tailscale0 → eth0 rule installed → bypass mode active, clients exit via Synology ISP IP. A persistent red banner appears in the UI.
6. State persisted, SSE notification sent.

### 4.3 Switch location

1. `POST /api/surfshark/location {name: "us-nyc"}`.
2. Verify the target `.conf` exists in cache.
3. `wg-quick down wg0` (if up), copy target `.conf` → `/etc/wireguard/wg0.conf` with PrivateKey injected from keys dir, `wg-quick up wg0`.
4. Wait up to 10s for ping `1.1.1.1` via wg0 to succeed. On timeout, roll back to previous location, return 504.
5. Update state.json, SSE notify.

### 4.4 Refresh server list

1. `POST /api/surfshark/refresh`. Returns 202 immediately.
2. Background goroutine: re-authenticate, re-register existing pubkey (idempotent), fetch list, overwrite cached `.conf`s, remove obsolete ones.
3. SSE event `refresh_complete` updates the UI dropdown.

### 4.5 Auto-failover (watchdog wg-watchdog)

1. When `wg0` is unhealthy (no handshake for 90s OR 3 ping failures in 30s):
   - Attempt self-heal on current location: `wg-quick down + up`, 3 times, 10s apart.
2. If still unhealthy:
   - Walk through `preferred_locations` (from state.json) in order. If empty, fall back to the 3 alphabetically nearest neighbors of the current location name.
   - First location whose handshake + ping succeed becomes the new active location.
   - SSE event `auto_failover` triggers a yellow banner: "Switched us-nyc → us-bos (auto)".
3. If all candidates fail:
   - Toggle remains ON in state, wg0 stays down. Kill switch (if enabled) stays armed → no leak.
   - SSE event `all_failed` → red banner.
4. Disable with env var `FAILOVER=false` (default `true`).

## 5. State & Persistence

`/data/state.json` is the source of truth across restarts.

```json
{
  "version": 1,
  "surfshark": {
    "toggle": true,
    "current_location": "us-nyc",
    "preferred_locations": ["us-nyc", "us-bos", "fr-par"],
    "last_refresh": "2026-06-14T11:42:31Z",
    "last_failover": null
  },
  "kill_switch": {
    "enabled_by_env": true,
    "currently_armed": false
  },
  "stats_cache": {
    "public_ip": "185.232.21.44",
    "public_ip_location": "New York, US",
    "last_measured": "2026-06-14T11:42:55Z",
    "wg0_latency_ms": 28,
    "wg0_last_handshake": "2026-06-14T11:42:30Z"
  }
}
```

Rules:

- Atomic write (`state.json.tmp` + rename).
- Single writer (the Go daemon), so an in-memory mutex is enough.
- `version` field allows future schema migrations.
- No SQLite — a single JSON file is sufficient given the write frequency (a few writes per minute max).

Out of state.json (intentional):

- Surfshark credentials → env only.
- Tailscale auth key → env only.
- Surfshark `.conf` files → on disk, one per location.
- Logs → `/data/logs/` (rolling).

## 6. Error Handling

### 6.1 Startup

| Case | Behavior |
|---|---|
| `TS_AUTHKEY` missing | Exit 1, log "missing TS_AUTHKEY in .env" |
| `TS_ALLOWED_USERS` missing | Exit 1, log "no tailnet identity whitelisted, refusing to start" |
| `tailscaled` fails to authenticate within 60s | Exit 2 (auth key expired/invalid) |
| `SURFSHARK_*` missing AND no cached configs | Start anyway, UI shows banner "no configs available" |
| Configs present but keypair missing | Exit 3 (unrecoverable — operator must refresh) |
| `ip_forward=0` detected at runtime | Attempt `sysctl -w`; on failure, exit 3 |

### 6.2 Runtime

| Case | Behavior |
|---|---|
| Toggle ON requested but `current_location` no longer in cache | Auto-pick first available, log warning, SSE notify |
| `wg-quick up` fails (already up) | Auto-cleanup `wg-quick down wg0`, retry once |
| `tailscaled` crash detected | Restart; 3 restarts in 5 min → container exit |
| Refresh API call fails | Keep old cache, log error, return 502 with explicit message |
| Surfshark rejects keypair (revoked) | Regenerate locally, re-register; backup old keys in `keys/old-YYYYMMDD/` |
| Location switch ping timeout (> 10s) | Rollback to previous location, return 504 |
| `state.json` corrupted at boot | Backup as `state.json.broken-YYYYMMDD`, recreate with defaults |
| `/data` disk full | Log error, persistent UI banner, refresh blocked |

### 6.3 Safety / leak prevention

| Case | Behavior |
|---|---|
| Toggle OFF + kill switch OFF (bypass mode) | Persistent red banner: "VPN BYPASS ACTIVE — real IP exposed for exit-node clients" |
| Session token theft | N/A — no sessions, identity re-verified per request |
| `.env` world-readable | Documented in README: `chmod 600 .env` |
| DNS leak from exit-node clients | `--accept-dns=false` on Tailscale side. DNS for exit-node-routed clients flows via wg0 (Surfshark DNS by default, or a user-set DNS in env if needed) |

### 6.4 Logging

- Every UI action logged with caller's tailnet identity (audit trail).
- Structured JSON logs, both stdout (Docker captures) and `/data/logs/` (rolling 10 MB × 5).
- Levels: `INFO` (user actions, state changes), `WARN` (recovery, failover), `ERROR` (crashes, unrecoverable failures).

## 7. Web UI

Single page, vanilla JS + Fetch + EventSource for SSE, ~200 lines of HTML/JS embedded in the Go binary via `//go:embed`. No build step, no framework.

### Sections

1. **Header:** product name + caller's tailnet identity (top right).
2. **Status panel:** Surfshark on/off + location, Tailscale connection state + hostname, kill switch armed/disarmed, current public IP + geo, last handshake + latency, failover enabled + last event.
3. **Controls:** toggle switch, location dropdown + Switch button, Refresh button.
4. **Preferred locations:** drag-reorderable list, used as failover preference order.
5. **Live log:** last 50 entries, streamed via SSE.
6. **Banners:** yellow (recovering), red (bypass active OR all failover failed), blue (refresh/switch in progress).

### HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Embedded HTML page |
| `GET` | `/api/status` | Full snapshot (state.json + live stats) |
| `POST` | `/api/surfshark/toggle` | `{enabled: bool}` |
| `POST` | `/api/surfshark/location` | `{name: string}` |
| `POST` | `/api/surfshark/refresh` | Returns 202, async |
| `POST` | `/api/surfshark/preferred` | `{locations: string[]}` |
| `GET` | `/api/events` | SSE stream (status, logs, notifications) |
| `GET` | `/api/healthz` | Container health (200 if daemon alive) |

### Explicitly out of scope for v1

- Manual `.conf` upload through the UI.
- Surfshark credential entry through the UI.
- Bandwidth graphs / historical metrics.
- Multi-user roles.

## 8. Testing

Three layers.

### 8.1 Go unit tests

Pure logic only:

- Surfshark API client (mocked HTTP server).
- State manager (load/save/atomic, version migration, corruption recovery).
- Identity middleware (table-driven: whois → allowed/refused).
- Iptables rules builder (snapshot test on generated rule strings, no real exec).
- Config parser (Surfshark `.conf` → struct → final `.conf` with injected key).
- Failover state machine (table-driven).

Target: `go test ./...` under 5s.

### 8.2 Integration (docker-compose)

A test compose file that:

- Builds the container with stub binaries replacing `tailscale`/`tailscaled` (CLI stubs that match the expected calls).
- Spins up a mock Surfshark API server.
- Mounts an ephemeral `/data`.
- Asserts:
  - Entrypoint succeeds end-to-end.
  - `/api/healthz` responds.
  - Unauthenticated requests → 401.
  - Authenticated calls trigger the right side effects (real iptables, dummy `wg0` interface).
  - state.json survives a restart.

Target: `make test-integration` under 30s.

### 8.3 Manual end-to-end on Synology (checklist in README)

- First boot with real Surfshark creds → configs downloaded.
- Tailscale client using the exit node → `ifconfig.io` shows Surfshark IP.
- `tailscale ping <exit-node>` shows `via DIRECT` (not DERP).
- Speed test from client > 50 Mbps (sanity check — relayed mode would cap at ~10).
- Switch location → public IP changes within 10s.
- Toggle OFF + kill switch ON → exit-node client loses internet.
- Toggle OFF + kill switch OFF → exit-node client keeps internet via Synology ISP IP, red banner visible.
- Force Surfshark drop (block UDP outbound briefly) → failover triggers within 2 min.
- Reboot Synology → everything comes back up with stable Tailscale identity and configs.

## 9. What the operator must provide

To deploy this, the user needs to supply:

| Env var | Source | Notes |
|---|---|---|
| `TS_AUTHKEY` | Tailscale admin → Settings → Keys → Generate auth key | Reusable, tagged `tag:exit-node`, no expiry recommended. Tailnet ACL must auto-approve exit nodes for this tag. |
| `TS_HOSTNAME` | Operator choice | e.g., `synology-surfshark-exit`. Shown in the Tailscale admin. |
| `TS_ALLOWED_USERS` | Operator's tailnet email(s) | Comma-separated. Only these identities can use the UI. |
| `SURFSHARK_EMAIL` | Surfshark account | Used to fetch configs at first boot and on refresh. |
| `SURFSHARK_PASSWORD` | Surfshark account | Same. |
| `KILL_SWITCH` | Operator | `true` (default) or `false`. |
| `FAILOVER` | Operator | `true` (default) or `false`. |

### Tailscale admin side

- Create an auth key tagged `tag:exit-node`.
- ACL: ensure `autoApprovers.exitNode` includes `tag:exit-node` so the new device doesn't need manual approval.

### Synology side

- DSM 7 with Container Manager installed.
- The `tun` kernel module must be available (default on DSM 7).
- `chmod 600 .env` after creating it.

### Optional setup (post-install)

- In the Tailscale admin UI for each client device that should egress via this exit node: enable "Use exit node" → pick `synology-surfshark-exit`.

## 10. Open verification items (not blockers, to confirm during implementation)

- Whether `sysctls` in docker-compose actually takes effect on DSM 7 Container Manager, or whether `ip_forward` needs to be set on the host first.
- Behavior of two `tailscaled` instances on the same Synology when both want kernel-mode networking — confirmed compatible by Tailscale docs, to verify on real hardware.
- Exact endpoints of Surfshark's private WireGuard API at deployment time (community-maintained, may have drifted from latest reference implementation).
