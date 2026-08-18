#!/usr/bin/env bash
# Phase 0 — NAT matrix test: CONNECT side (run on machine B with sudo).
#
#   Machine B:  sudo ./phase0-nat-matrix-client.sh <EndpointId from A>
#
# Connects, lets the path negotiation settle (up to 30s), then prints whether
# the session went direct or relayed, plus this side's STUN-probed public IP
# (handy for classifying your NAT). Exits on its own.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
    echo "usage: sudo $0 <EndpointId from machine A>" >&2
    exit 1
}
case "${1:-}" in
    -h|--help) usage ;;
esac
EP="${1:-}"
[ -n "$EP" ] || usage

source ./scripts/phase-lib.sh
LOG="/tmp/phase0-nat-conn.log"
KEY="/tmp/phase0-nat-conn.key"

trap 'phase_cleanup; exit 0' INT TERM

echo "=== Phase 0 NAT-matrix: client ==="
echo "  dialing $EP via n0 preset (STUN + relay)"
phase_connect "$KEY" "$LOG" "$EP"
echo "  waiting up to 30s for the path to settle..."
echo ""

deadline=$((SECONDS + 30))
while [ $SECONDS -lt $deadline ]; do
    grep -q "network_path=Ip(" "$LOG" 2>/dev/null && break
    sleep 2
done

echo ""
phase_path_verdict "$LOG"
echo ""
echo "  this machine's STUN-probed public IP: $(phase_public_ip "$LOG" || echo unknown)"
echo ""
echo "  full log: $LOG"
phase_cleanup
echo "done"
