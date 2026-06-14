#!/bin/bash
set -euo pipefail

err() { echo "entrypoint: $*" >&2; }

: "${TS_AUTHKEY:?TS_AUTHKEY is required (Tailscale pre-auth key)}"
: "${TS_ALLOWED_USERS:?TS_ALLOWED_USERS is required (comma-separated tailnet emails)}"
TS_HOSTNAME="${TS_HOSTNAME:-synology-surfshark-exit}"

mkdir -p /data/tailscale /data/surfshark /data/logs
mkdir -p /etc/wireguard
chmod 700 /data/surfshark

# Ensure ip_forward (sysctls in compose should already set it; this is a guard).
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
  err "net.ipv4.ip_forward is 0; attempting to set"
  sysctl -w net.ipv4.ip_forward=1 || { err "failed to enable ip_forward"; exit 3; }
fi

# Tell wg-quick to use userspace WireGuard. DSM kernels miss the wireguard.ko
# module; wireguard-go provides a userspace TUN-based implementation that the
# wg-quick script falls back to when the kernel can't create the interface.
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

# Start tailscaled in background, state in /data/tailscale.
# --tun=userspace-networking runs Tailscale entirely in user-space netstack,
# bypassing the DSM kernel's missing netfilter modules. Exit-node routing
# still works: outbound connections from netstack use the container's normal
# routing table (which wg-quick will point at wg0).
TS_DEBUG_FIREWALL_MODE=nftables \
tailscaled \
  --state=/data/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock \
  --tun=userspace-networking \
  &
TSD_PID=$!

# Wait for socket.
for i in $(seq 1 30); do
  if [[ -S /var/run/tailscale/tailscaled.sock ]]; then break; fi
  sleep 1
done
if [[ ! -S /var/run/tailscale/tailscaled.sock ]]; then
  err "tailscaled socket never appeared"
  kill "$TSD_PID" 2>/dev/null || true
  exit 2
fi

# Bring tailscale up (idempotent).
tailscale up \
  --authkey="${TS_AUTHKEY}" \
  --advertise-exit-node \
  --accept-routes \
  --accept-dns=false \
  --hostname="${TS_HOSTNAME}"

# Expose the local HTTP UI to the tailnet. In userspace-networking mode the
# Tailscale IP is not on a kernel interface, so the Go server binds 127.0.0.1
# and Tailscale serve forwards incoming tailnet traffic to it. Headers
# (Tailscale-User-Login etc.) are injected so the auth middleware can
# identify the caller without calling whois.
# Idempotent reset; we don't care if reset fails on first boot.
tailscale serve reset 2>/dev/null || true
tailscale serve --bg --http=8080 http://127.0.0.1:8080 || \
  err "tailscale serve failed (UI may be unreachable from tailnet — check tailnet HTTPS prefs)"

# Hand off to the Go daemon as PID 1.
exec /app/surfshark-control
