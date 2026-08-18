#!/usr/bin/env bash
# Phase 0 — NAT matrix test: SERVE side (run on machine A with sudo).
#
#   Machine A:  sudo ./phase0-nat-matrix-server.sh
#   Machine B:  sudo ./phase0-nat-matrix-client.sh <EndpointId from A>
#
# Prints the EndpointId + virtual IP (the share box), then watches the log
# and prints the NAT verdict (direct vs relayed) as soon as the connect side
# negotiates a path. Ctrl+C to stop.
#
# Uses n0's public STUN/relay (the default preset — no --relay flag), so
# iroh's built-in QUIC-NAT-TRAVERSAL (noq) is fully exercised. Meaningful
# only across two *different* machines on different networks.
set -euo pipefail

cd "$(dirname "$0")/.."
source ./scripts/phase-lib.sh
LOG="/tmp/phase0-nat-serve.log"
KEY="/tmp/phase0-nat-serve.key"

trap 'phase_cleanup; exit 0' INT TERM

echo "=== Phase 0 NAT-matrix: server ==="
phase_serve "$KEY" "$LOG"
phase_share_box
echo "  waiting for the connect side... (Ctrl+C to stop)"
echo "  log: $LOG"
echo ""

seen=0
while :; do
    if [ "$seen" -eq 0 ] && grep -q "network_path=Ip(" "$LOG" 2>/dev/null; then
        seen=1
        echo "=== NAT verdict ==="
        grep -E "path::selected|Established" "$LOG" | tail -5 || true
        echo "  → DIRECT connection (hole-punch succeeded)"
        echo ""
    fi
    sleep 3
done
