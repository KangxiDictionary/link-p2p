#!/usr/bin/env bash
# Phase 0 — relay throughput benchmark: CONNECT side (run on machine B with sudo).
#
#   Machine B:  sudo ./phase0-relay-bench-client.sh <EndpointId> [serve-public-IP] [--force-relay <peer-public-ip>]
#
#   <EndpointId>         from the bench server's share box
#   [serve-public-IP]    the serve machine's public IP, for the direct control
#                        test (auto-detected from the log if omitted)
#   [--force-relay <ip>] additionally DROP inbound UDP from <ip> on THIS
#                        machine to force the relay path. The DROP is removed
#                        automatically when the script exits. For it to work
#                        you must also apply the same rule on the SERVE
#                        machine (the script prints the exact command).
#
# Runs iperf3 through the tunnel (to the serve VIP) and, if a public IP is
# available, a direct iperf3 control (no tunnel), then prints the path
# verdict. Prerequisite: the bench server is running (it hosts the iperf3
# servers) and iperf3 is installed here.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
    echo "usage: sudo $0 <EndpointId> [serve-public-IP] [--force-relay <peer-public-ip>]" >&2
    echo "  <EndpointId>         from the bench server's share box" >&2
    echo "  [serve-public-IP]    for the direct control test (auto-detected if omitted)" >&2
    echo "  [--force-relay <ip>] DROP inbound UDP from <ip> locally to force the relay" >&2
    exit 1
}
case "${1:-}" in
    -h|--help) usage ;;
esac

EP=""
REAL_IP=""
FORCE_IP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --force-relay)
            FORCE_IP="${2:-}"
            [ -n "$FORCE_IP" ] || usage
            shift 2
            ;;
        *)
            if [ -z "$EP" ]; then
                EP="$1"
            elif [ -z "$REAL_IP" ]; then
                REAL_IP="$1"
            else
                usage
            fi
            shift
            ;;
    esac
done
[ -n "$EP" ] || usage

source ./scripts/phase-lib.sh
LOG="/tmp/phase0-relay-conn.log"
KEY="/tmp/phase0-relay-conn.key"

cleanup_exit() {
    if [ -n "$FORCE_IP" ]; then
        phase_clear_relay "$FORCE_IP"
    fi
    phase_cleanup
    exit 0
}
trap cleanup_exit INT TERM

echo "=== Phase 0 relay-bench: client ==="
echo "  dialing $EP via n0 preset"
phase_connect "$KEY" "$LOG" "$EP"
SERVE_VIP="$PHASE_PEER_VIP"

# The serve machine's public IP: prefer the direct-path line in our own log,
# fall back to the command-line argument.
[ -n "$REAL_IP" ] || REAL_IP=$(phase_peer_public_ip "$LOG")
if [ -n "$REAL_IP" ]; then
    echo "  serve public IP: $REAL_IP"
else
    echo "  serve public IP: unknown (no direct path logged, no argument given)"
fi

if [ -n "$FORCE_IP" ]; then
    echo ""
    echo "=== forcing relay: DROP inbound UDP from $FORCE_IP on this machine ==="
    phase_force_relay "$FORCE_IP"
    MY_PUB=$(phase_public_ip "$LOG")
    if [ -n "$MY_PUB" ]; then
        echo "  >>> now run on the SERVE machine (root):"
        echo "      sudo scripts/phase-relay-ctl.sh force-relay $MY_PUB"
    else
        echo "  >>> now run on the SERVE machine (root):"
        echo "      sudo scripts/phase-relay-ctl.sh force-relay <this machine's public IP>"
    fi
    echo "  >>> press Enter once the DROP is applied on both sides..."
    if ! read -r _ 2>/dev/null; then
        echo "  (no interactive input — waiting 15s instead)"
        sleep 15
    fi
    echo "  waiting up to 20s for the direct path to die and the relay to take over..."
    torn=0
    deadline=$((SECONDS + 20))
    while [ $SECONDS -lt $deadline ]; do
        if grep -q "peer disconnected" "$LOG" 2>/dev/null; then
            torn=1
            echo "  ❌ session torn down during failover — the relay numbers below are"
            echo "     not a clean relay-path measurement. Re-run with the DROP applied"
            echo "     on both machines BEFORE connecting."
            break
        fi
        sleep 2
    done
    if [ "$torn" -eq 0 ]; then
        echo "  ✅ session survived the direct-path loss (relay failover or still deciding)"
    fi
    echo ""
    echo "=== path events after forcing relay ==="
    grep -E "path::selected|set_status" "$LOG" | tail -6 || echo "  (none logged)"
    echo ""
fi

echo "=== iperf3 through the tunnel (serve VIP $SERVE_VIP :5201, 20s) ==="
iperf3 -c "$SERVE_VIP" -p 5201 -t 20 -P 4 --connect-timeout 5000 2>&1 \
    || echo "  (tunnel iperf3 failed — is the bench server running with iperf3 up?)"

if [ -n "$REAL_IP" ]; then
    echo ""
    echo "=== iperf3 direct control (serve public IP $REAL_IP :5202, 20s, no tunnel) ==="
    iperf3 -c "$REAL_IP" -p 5202 -t 20 -P 4 --connect-timeout 5000 2>&1 \
        || echo "  (direct iperf3 failed — unreachable from here, or the direct server isn't up)"
else
    echo ""
    echo "  (no serve public IP available — skipping the direct control test)"
fi

echo ""
echo "=== path verdict ==="
phase_path_verdict "$LOG"
echo ""
echo "  full log: $LOG"
cleanup_exit
