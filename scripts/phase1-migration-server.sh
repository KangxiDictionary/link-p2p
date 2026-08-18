#!/usr/bin/env bash
# Phase 1 — WiFi↔4G connection migration test: SERVE side (run on machine A
# with sudo).
#
#   Machine A:  sudo ./phase1-migration-server.sh
#   Machine B:  sudo ./phase1-migration-client.sh <EndpointId from A>
#
# Prints the share box, then watches the log and reports live whether the
# session gets torn down (peer disconnected) or rebuilt (a new TUN session
# established) while the connect side switches networks. Ctrl+C to stop.
#
# Both sides run RUST_LOG=iroh=debug,link_p2p=debug so one test yields two
# datasets: iroh's path events AND the app layer's reaction.
set -euo pipefail

cd "$(dirname "$0")/.."
source ./scripts/phase-lib.sh
LOG="/tmp/phase1-mig-serve.log"
KEY="/tmp/phase1-mig-serve.key"

trap 'phase_cleanup; exit 0' INT TERM

echo "=== Phase 1 migration test: server ==="
phase_serve "$KEY" "$LOG"
phase_share_box
echo "  waiting for the connect side... (Ctrl+C to stop)"
echo "  log: $LOG"
echo ""

est=0
printed_dc=0
while :; do
    n=$(grep -c "TUN session established" "$LOG" 2>/dev/null || true)
    if [ "$n" -gt "$est" ]; then
        est=$n
        echo "  [$(date +%H:%M:%S)] TUN session established #$est"
    fi
    if [ "$printed_dc" -eq 0 ] && grep -q "peer disconnected" "$LOG" 2>/dev/null; then
        printed_dc=1
        echo "  [$(date +%H:%M:%S)] peer disconnected — session was torn down (migration failed at the app layer)"
    fi
    sleep 2
done
