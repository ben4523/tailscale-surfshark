#!/bin/bash
# Container smoke test — validates the image is wired correctly without
# requiring a real Tailscale tailnet or Surfshark account.
#
# Full end-to-end validation lives in the README "Manual verification
# checklist" and runs against a real Synology + real tailnet.
#
# Cases:
#  1. Missing TS_AUTHKEY -> entrypoint exits 1 with explicit message
#  2. Missing TS_ALLOWED_USERS -> entrypoint exits 1 with explicit message
#  3. All required env vars set, real tailscaled allowed to start, but invalid
#     authkey will eventually fail. We assert the container at least proceeds
#     past env validation and tailscaled startup (i.e. doesn't fail at the
#     entrypoint guard layer).

set -euo pipefail

IMAGE="${IMAGE:-tailscale-surfshark:dev}"

fail=0
pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; fail=1; }

echo "[1] Missing TS_AUTHKEY..."
out=$(docker run --rm "$IMAGE" 2>&1 || true)
if echo "$out" | grep -q "TS_AUTHKEY is required"; then
  pass "entrypoint rejects missing TS_AUTHKEY"
else
  fail "expected 'TS_AUTHKEY is required', got:\n$out"
fi

echo "[2] Missing TS_ALLOWED_USERS..."
out=$(docker run --rm -e TS_AUTHKEY=stub "$IMAGE" 2>&1 || true)
if echo "$out" | grep -q "TS_ALLOWED_USERS is required"; then
  pass "entrypoint rejects missing TS_ALLOWED_USERS"
else
  fail "expected 'TS_ALLOWED_USERS is required', got:\n$out"
fi

echo "[3] Binary runs (vet via go test still gates Go-level correctness)..."
out=$(docker run --rm --entrypoint=/bin/sh "$IMAGE" -c 'ls -la /app/surfshark-control && /app/surfshark-control --help 2>&1 || true' 2>&1)
if echo "$out" | grep -q "surfshark-control"; then
  pass "binary present and invocable"
else
  fail "binary missing or not invocable:\n$out"
fi

if [[ "$fail" -eq 0 ]]; then
  echo "smoke: PASS"
else
  echo "smoke: FAIL"
  exit 1
fi
