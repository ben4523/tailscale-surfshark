#!/bin/bash
set -euo pipefail

err() { echo "entrypoint-front: $*" >&2; }
log() { echo "entrypoint-front: $*"; }

: "${TS_AUTHKEY_FRONT:?TS_AUTHKEY_FRONT is required (separate auth key for the fast exit-node)}"
TS_HOSTNAME_FRONT="${TS_HOSTNAME_FRONT:-synology-surfshark-exit-fast}"
TS_PORT_FRONT="${TS_PORT_FRONT:-41642}"
TS_TUN_NAME="${TS_TUN_NAME:-tailscale1}"
GLUETUN_BRIDGE_IP="${GLUETUN_BRIDGE_IP:-172.30.0.2}"

mkdir -p /var/lib/tailscale /var/run/tailscale

# Kernel TUN (tailscale<N>) instead of userspace-networking: real packet
# forwarding via the host's network stack, which gives us 30–50% better
# throughput than the netstack/gvisor path. Bind UDP on a non-conflicting
# port so we coexist with the DSM-native Tailscale (41641 default) and the
# slow exit-node in gluetun's netns.
log "starting tailscaled on port $TS_PORT_FRONT (tun=$TS_TUN_NAME)"
tailscaled \
  --state=/var/lib/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock \
  --tun="$TS_TUN_NAME" \
  --port="$TS_PORT_FRONT" \
  &
TSD_PID=$!

for i in $(seq 1 30); do
  [[ -S /var/run/tailscale/tailscaled.sock ]] && break
  sleep 1
done
if [[ ! -S /var/run/tailscale/tailscaled.sock ]]; then
  err "tailscaled socket never appeared"
  kill "$TSD_PID" 2>/dev/null || true
  exit 2
fi

log "tailscale up (advertise-exit-node, hostname=$TS_HOSTNAME_FRONT)"
# --accept-routes=false: this node doesn't need to learn other tailnet routes;
#   it just exists to forward exit-node traffic.
# --accept-dns=false: we don't want to mangle the host's resolv.conf.
tailscale --socket=/var/run/tailscale/tailscaled.sock up \
  --authkey="${TS_AUTHKEY_FRONT}" \
  --advertise-exit-node \
  --accept-routes=false \
  --accept-dns=false \
  --hostname="${TS_HOSTNAME_FRONT}"

# Wait for the kernel TUN device. tailscaled creates it after a successful
# "up". Without this we'd policy-route into a nonexistent interface.
for i in $(seq 1 30); do
  ip link show "$TS_TUN_NAME" &>/dev/null && break
  sleep 1
done
if ! ip link show "$TS_TUN_NAME" &>/dev/null; then
  err "$TS_TUN_NAME interface never appeared"
  exit 3
fi

# Find the host-side route to gluetun's bridge IP. Docker creates a bridge
# interface (br-XXXX) on the host with a gateway in 172.30.0.0/24, so the
# kernel already knows how to reach 172.30.0.2 via that bridge.
BRIDGE_DEV=$(ip -4 route get "$GLUETUN_BRIDGE_IP" 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1); exit}}')
if [[ -z "$BRIDGE_DEV" ]]; then
  err "could not resolve host route to gluetun bridge IP $GLUETUN_BRIDGE_IP — is the tss-egress bridge up?"
  exit 4
fi
log "host route to $GLUETUN_BRIDGE_IP goes via $BRIDGE_DEV"

# Policy routing: a separate routing table whose default route points at
# gluetun's tun0 (via the bridge IP), and a rule that picks that table for
# packets arriving on tailscale1 (i.e., exit-node traffic from peers).
# Everything else on the host keeps its normal default route (Free).
TABLE_NAME="tss-egress"
TABLE_ID=200
if ! grep -q "^$TABLE_ID $TABLE_NAME$" /etc/iproute2/rt_tables 2>/dev/null; then
  echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
fi

# Idempotent setup: flush before re-adding so re-runs don't pile up duplicates.
ip route flush table "$TABLE_NAME" 2>/dev/null || true
ip route add default via "$GLUETUN_BRIDGE_IP" dev "$BRIDGE_DEV" table "$TABLE_NAME"

# Remove any prior rule pointing at this table, then add ours.
while ip rule del table "$TABLE_NAME" 2>/dev/null; do :; done
ip rule add iif "$TS_TUN_NAME" table "$TABLE_NAME" priority 100

log "policy routing installed: iif $TS_TUN_NAME -> table $TABLE_NAME -> via $GLUETUN_BRIDGE_IP dev $BRIDGE_DEV"

# Idempotent: drop any prior `tailscale serve` config from earlier deploys.
# We don't use it anymore — see below for why.
tailscale --socket=/var/run/tailscale/tailscaled.sock serve reset 2>/dev/null || true

# Expose the dashboard to the tailnet via a plain TCP reverse proxy.
#
# WHY NOT `tailscale serve`: serve uses HTTP Host-header routing, which means
# a request to http://100.X.X.X:8080/ (the bare tailnet IP) returns 404 —
# it only matches when Host is the configured hostname/FQDN. The user
# legitimately wants both IP and hostname access from the dashboard.
#
# socat binds ONLY on the tailnet IP (NOT 0.0.0.0) so LAN clients can't
# reach the dashboard without being on the tailnet. The forwarded source IP
# arriving at the daemon is 172.30.0.1 (the bridge gateway), which the auth
# middleware trusts as proxy-vouched — same status as loopback.
TS_IP=$(tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 2>/dev/null | head -1)
if [[ -z "$TS_IP" ]]; then
  err "could not read tailnet IPv4 from tailscaled — dashboard proxy not started"
else
  log "starting socat proxy: $TS_IP:8080 -> $GLUETUN_BRIDGE_IP:8080"
  socat TCP-LISTEN:8080,bind="$TS_IP",reuseaddr,fork TCP:"$GLUETUN_BRIDGE_IP":8080 &
fi

# Egress watcher — toggles the policy routing rule based on the user's VPN
# state in the daemon. When the dashboard says VPN ON, exit-node traffic
# follows table $TABLE_NAME (→ gluetun → Surfshark). When the dashboard says
# VPN OFF, the rule is removed and tailscaled's standard exit-node iptables
# (auto-MASQUERADE on ovs_eth0) carries the traffic straight out via Free.
# Lets the user toggle Surfshark on/off from the dashboard without losing
# internet on the peer — instead of dropping to a dead tun0, traffic falls
# back to the host default route.
egress_watcher() {
  local last_state="init" body state
  while true; do
    body=$(curl -s -m 3 "http://${GLUETUN_BRIDGE_IP}:8080/api/status" 2>/dev/null) || { sleep 5; continue; }
    # Crude but deterministic — the daemon's JSON always has the surfshark
    # block first and its `toggle` field is a plain bool literal.
    state=$(printf '%s' "$body" | grep -o '"toggle":[a-z]*' | head -1 | cut -d: -f2)
    if [[ "$state" != "true" && "$state" != "false" ]]; then sleep 5; continue; fi
    if [[ "$state" != "$last_state" ]]; then
      if [[ "$state" == "true" ]]; then
        ip rule add iif "$TS_TUN_NAME" table "$TABLE_NAME" priority 100 2>/dev/null || true
        log "VPN on -> exit-node traffic via gluetun (Surfshark)"
      else
        # Drop ALL matching rules in case duplicates were ever inserted.
        while ip rule del iif "$TS_TUN_NAME" table "$TABLE_NAME" 2>/dev/null; do :; done
        log "VPN off -> exit-node traffic via host default (Free direct)"
      fi
      last_state="$state"
    fi
    sleep 5
  done
}
egress_watcher &

# Block on tailscaled so the container stays alive and we get its logs.
wait "$TSD_PID"
