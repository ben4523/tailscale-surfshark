#!/bin/bash
# Stub for the `tailscale` CLI used by integration smoke tests.
# Implements only the subcommands the daemon actually calls.
case "$1" in
  up)
    exit 0
    ;;
  ip)
    # Return empty: causes main.go to fall back to binding 0.0.0.0 (smoke-test mode).
    if [[ "$2" == "-4" ]]; then exit 0; fi
    ;;
  status)
    if [[ "$2" == "--json" ]]; then
      cat <<'JSON'
{"BackendState":"Running","Self":{"HostName":"stub-exit","TailscaleIPs":["100.64.0.5"]}}
JSON
      exit 0
    fi
    ;;
  whois)
    if [[ "$2" == "--json" ]]; then
      cat <<'JSON'
{"UserProfile":{"LoginName":"ben@example.com"}}
JSON
      exit 0
    fi
    ;;
esac
exit 0
