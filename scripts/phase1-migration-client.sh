#!/usr/bin/env bash
# Phase 1 — WiFi↔4G connection migration test: CONNECT side (run on machine B
# with sudo).
#
#   Machine B:  sudo ./phase1-migration-client.sh <EndpointId from A>
#
# Connects, then pings the serve VIP continuously for 40s while you switch
# this machine's network (WiFi → mobile hotspot / 4G). Afterwards it prints:
#   - the ping summary (how many pings were dropped during the switch — a
#     handful is normal, 100% loss means the session died)
#   - iroh's path events (path::selected / network_path — the switch evidence)
#   - whether the session was torn down (peer disconnected) or survived
#
# Both sides run RUST_LOG=iroh=debug,link_p2p=debug.
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
LOG="/tmp/phase1-mig-conn.log"
KEY="/tmp/phase1-mig-conn.key"
PING_LOG="/tmp/phase1-mig-ping.txt"

trap 'phase_cleanup; exit 0' INT TERM

echo "=== Phase 1 migration test: client ==="
phase_connect "$KEY" "$LOG" "$EP"
SERVE_VIP="$PHASE_PEER_VIP"

echo ""
echo "  >>> NOW switch this machine's network (WiFi off/on, or enable the"
echo "      hotspot). Pinging the serve VIP ($SERVE_VIP) for the next 40s..."
echo ""
LANG=C ping -i 0.5 -W 1 -c 80 "$SERVE_VIP" 2>&1 | tee "$PING_LOG" || true

echo ""
echo "=== ping summary ==="
grep -E "packet loss|round-trip" "$PING_LOG" 2>/dev/null || echo "  (no summary line — ping failed entirely)"
echo ""
echo "=== iroh path events (path switch evidence) ==="
grep -E "path::selected|network_path|set_status" "$LOG" | tail -8 || echo "  (none logged)"
echo ""
echo "=== session survived? ==="
if grep -q "peer disconnected" "$LOG"; then
    echo "  ❌ SESSION WAS TORN DOWN — migration failed at the app layer"
    echo "     (check the serve side: a new 'TUN session established' there means"
    echo "      the whole session was rebuilt instead of migrated)"
else
    echo "  ✅ session stayed up (no 'peer disconnected' in the log)"
fi
echo ""
echo "  full log: $LOG"
phase_cleanup
echo "done"
