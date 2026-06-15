#!/bin/bash
set -euo pipefail

err() { echo "entrypoint: $*" >&2; }

: "${TS_ALLOWED_USERS:?TS_ALLOWED_USERS is required (comma-separated tailnet emails or '*')}"

mkdir -p /data/surfshark /data/logs
chmod 700 /data/surfshark

# Guard rail: kernel forwarding must be on for the fast exit-node's traffic
# to traverse this netns into tun0. Compose sysctls should already do this.
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
  err "net.ipv4.ip_forward is 0; attempting to set"
  sysctl -w net.ipv4.ip_forward=1 || { err "failed to enable ip_forward"; exit 3; }
fi

# tailscaled USED to run here as the "slow" exit-node (userspace-networking,
# DERP-relayed). It has been retired in favor of tss-tailscale-front which
# runs on the host netns with kernel TUN and direct UDP — same Surfshark
# egress path, just faster. This container is now only:
#   1) the Go HTTP daemon (dashboard + gluetun control)
#   2) the iptables forwarding glue that lets the fast node's exit-node
#      traffic actually leave through gluetun's tun0
setup_egress_forwarding() {
  local bridge_iface tun_iface
  # Wait up to 60s for tun0. If gluetun hasn't established the tunnel yet,
  # there's nothing to MASQUERADE to. The daemon launches regardless; rules
  # can be re-applied on the next tunnel up.
  for i in $(seq 1 60); do
    if ip link show tun0 &>/dev/null; then
      tun_iface=tun0
      break
    fi
    sleep 1
  done
  if [[ -z "${tun_iface:-}" ]]; then
    err "egress-forwarding: tun0 never appeared, skipping (fast exit-node will fail to egress until next reconnect)"
    return 0
  fi

  # Identify the interface bound to the tss-egress bridge by its known IP
  # space (172.30.0.0/24, hard-coded in docker-compose.yml).
  bridge_iface=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.0\./ {print $2; exit}')
  if [[ -z "$bridge_iface" ]]; then
    err "egress-forwarding: no interface in 172.30.0.0/24 — tss-egress bridge not attached, skipping"
    return 0
  fi

  err "egress-forwarding: bridge=$bridge_iface tun=$tun_iface"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true

  # -C tests existence; -I inserts at the top of the chain. We insert at top
  # so we win against any DROP gluetun may have appended for the FORWARD
  # chain (which it does by default with FIREWALL=on). iptables-legacy is
  # required: DSM kernels don't support nf_tables.
  iptables-legacy -C FORWARD -i "$bridge_iface" -o "$tun_iface" -j ACCEPT 2>/dev/null \
    || iptables-legacy -I FORWARD 1 -i "$bridge_iface" -o "$tun_iface" -j ACCEPT
  iptables-legacy -C FORWARD -i "$tun_iface" -o "$bridge_iface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables-legacy -I FORWARD 1 -i "$tun_iface" -o "$bridge_iface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables-legacy -t nat -C POSTROUTING -o "$tun_iface" -s 172.30.0.0/24 -j MASQUERADE 2>/dev/null \
    || iptables-legacy -t nat -A POSTROUTING -o "$tun_iface" -s 172.30.0.0/24 -j MASQUERADE
}

# Run in background so a stuck wait doesn't block daemon startup.
setup_egress_forwarding &

# Hand off to the Go daemon as PID 1.
exec /app/surfshark-control
