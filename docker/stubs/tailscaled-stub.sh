#!/bin/bash
# Stub for `tailscaled`. Creates the expected socket file then idles.
mkdir -p /var/run/tailscale
touch /var/run/tailscale/tailscaled.sock
chmod 666 /var/run/tailscale/tailscaled.sock
exec sleep infinity
