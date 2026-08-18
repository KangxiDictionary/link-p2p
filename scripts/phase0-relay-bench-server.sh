#!/usr/bin/env bash
# Phase 0 — relay throughput benchmark: SERVE side (run on machine A with sudo).
#
#   Machine A:  sudo ./phase0-relay-bench-server.sh
#   Machine B:  sudo ./phase0-relay-bench-client.sh <EndpointId from A> [serve-public-IP] [--force-relay <peer-ip>]
#
# Starts `tun serve` AND the two iperf3 servers the client needs:
#   iperf3 -s -B <serve VIP> -p 5201   ← client's tunnel test
#   iperf3 -s -B <public IP> -p 5202   ← client's direct control test
# The public IP is detected from the STUN probe (Qad addr in the iroh debug
# log) and printed so you can pass it to the client. Ctrl+C to stop.
#
# Prerequisite: iperf3 installed on this machine.
set -euo pipefail

cd "$(dirname "$0")/.."
source ./scripts/phase-lib.sh
LOG="/tmp/phase0-relay-serve.log"
KEY="/tmp/phase0-relay-serve.key"

trap 'phase_cleanup; exit 0' INT TERM

echo "=== Phase 0 relay-bench: server ==="
phase_serve "$KEY" "$LOG"
phase_share_box

# Detect our public IP from the STUN probe. The serve banner appears before
# the probe finishes, so poll a bit.
pub=""
deadline=$((SECONDS + 30))
while [ $SECONDS -lt $deadline ]; do
    pub=$(phase_public_ip "$LOG")
    [ -n "$pub" ] && break
    sleep 2
done

if command -v iperf3 >/dev/null 2>&1; then
    VIP="${PHASE_SERVE_VIP:-}"
    if [ -n "$VIP" ]; then
        iperf3 -s -B "$VIP" -p 5201 >/tmp/phase0-relay-iperf-vip.log 2>&1 &
        PHASE_HELPER_PIDS="$PHASE_HELPER_PIDS $!"
        echo "  iperf3 server up: -s -B $VIP -p 5201 (tunnel test)"
    else
        echo "  warning: serve VIP unknown — skipping the tunnel iperf3 server" >&2
    fi
    if [ -n "$pub" ]; then
        iperf3 -s -B "$pub" -p 5202 >/tmp/phase0-relay-iperf-direct.log 2>&1 &
        PHASE_HELPER_PIDS="$PHASE_HELPER_PIDS $!"
        echo "  iperf3 server up: -s -B $pub -p 5202 (direct control)"
    else
        echo "  warning: public IP not detected — skipping the direct iperf3 server" >&2
    fi
else
    echo "  warning: iperf3 not found — the client's throughput tests will fail" >&2
fi

echo ""
echo "  public IP detected: ${pub:-unknown}"
[ -n "$pub" ] && echo "  → pass it to the client: sudo ./phase0-relay-bench-client.sh <EndpointId> $pub"
echo ""
echo "  waiting for the client... (Ctrl+C to stop)"
echo "  log: $LOG"
wait
