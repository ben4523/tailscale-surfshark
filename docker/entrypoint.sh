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

# Start tailscaled in background, state in /data/tailscale.
tailscaled \
  --state=/data/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock \
  --tun=tailscale0 \
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

# Hand off to the Go daemon as PID 1.
exec /app/surfshark-control
