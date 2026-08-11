#!/usr/bin/env bash
# Phase 0 — relay throughput benchmark (TUN mode)
#
# Measures throughput through the TUN tunnel when the path is relayed, and
# compares against direct iperf3 between the two machines' real IPs.
#
# Usage:
#   Machine A (serve + iperf3 server):
#     ./phase0-relay-bench.sh serve
#     → prints EndpointId and VIP, starts serve, waits for Ctrl+C
#
#   Machine B (connect + iperf3 client):
#     ./phase0-relay-bench.sh connect <EndpointId> <serve-real-IP>
#     → connects, runs iperf3 through the TUN tunnel (to serve's VIP),
#       then runs a direct iperf3 control (to serve's real IP).
#
# Before running this, check the NAT-matrix test first to confirm whether
# your two machines actually go through the relay. If they get a direct
# connection (path_remote=Ip), this benchmark won't measure the relay path
# unless you force it (e.g. iptables DROP the direct UDP port on both sides).
#
# Prerequisites: iperf3 on both machines.
set -eu

cd "$(dirname "$0")/.."
LOG_S="/tmp/phase0-relay-serve.log"
LOG_C="/tmp/phase0-relay-conn.log"
RUST_ENV="RUST_LOG=iroh=info,link_p2p=info"
BIN="./target/release/link-p2p"
ID_S="/tmp/phase0-rl-srv.key"
ID_C="/tmp/phase0-rl-conn.key"
# Use n0 preset so STUN probes fire (and we can see whether the path went
# relayed or direct from the logs). If you want to force a *specific* relay,
# add --relay <url> below, but note that custom relay skips STUN candidates
# and may worsen hole-punching (see README.md).
SERVE_ARGS="--identity $ID_S"
CONN_ARGS="--identity $ID_C"

usage() {
    echo "Usage: $0 serve                          (machine A)"
    echo "       $0 connect <EndpointId> <real-IP> (machine B)"
    exit 1
}

case "${1:-}" in
    serve)
        rm -f "$ID_S" "$LOG_S"
        echo "=== Phase 0 relay-bench: serve ==="
        echo "  Starting tun serve via N0 preset → $LOG_S"
        env $RUST_ENV "$BIN" tun serve $SERVE_ARGS >"$LOG_S" 2>&1 &
        PID=$!
        sleep 8
        echo ""
        echo "  === share with the connect side ==="
        grep -E "EndpointId|virtual IP" "$LOG_S" || true
        echo ""
        echo "  Also start: iperf3 -s -B <serve-VIP>  (in another terminal)"
        echo "  Then wait for the connect side to finish."
        echo "  serve PID: $PID    Ctrl+C to stop."
        wait $PID
        ;;
    connect)
        EP="${2:-}"
        REAL_IP="${3:-}"
        [ -n "$EP" ] || usage
        [ -n "$REAL_IP" ] || usage
        rm -f "$ID_C" "$LOG_C"
        echo "=== Phase 0 relay-bench: connect ==="
        echo "  Dialing $EP via N0 preset"
        env $RUST_ENV "$BIN" tun connect --to "$EP" $CONN_ARGS >"$LOG_C" 2>&1 &
        PID=$!
        sleep 10
        echo ""
        echo "=== Path check (direct or relay?) ==="
        grep -E "Established|path_remote" "$LOG_C" || echo "(nothing yet)"
        echo ""
        # Extract connect's own VIP
        CONN_VIP=$(ip -o -4 addr show 2>/dev/null | awk -F'[ /]+' '/link-p2p[0-9]+[[:space:]]*inet/{print $4}' | grep -v "$(ip -o -4 addr show link-p2p0 2>/dev/null | awk -F'[ /]+' '{print $4}')" | head -1 || true)
        SERVE_VIP=$(grep -oP 'virtual IP .* \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_C" | tail -1 || echo "??")
        echo "  serve VIP: $SERVE_VIP   connect VIP: $CONN_VIP"
        echo ""
        # --- TUN iperf3 (through the tunnel) ---
        echo "=== iperf3 through the TUN tunnel (VIP $SERVE_VIP) ==="
        echo "  Make sure 'iperf3 -s -B $SERVE_VIP' is running on machine A."
        echo "  Press Enter to start tunnel iperf3 test (30s)..."
        read -r
        iperf3 -c "$SERVE_VIP" -t 30 -P 4 --connect-timeout 5000 2>&1 || echo "(iperf3 through tunnel failed — is the serve side listening?)"
        echo ""
        # --- Direct iperf3 (control — NO tunnel) ---
        echo "=== iperf3 direct (real IP $REAL_IP, no tunnel) ==="
        echo "  Make sure 'iperf3 -s -B $REAL_IP' is running on machine A."
        echo "  Press Enter to start direct iperf3 test (30s)..."
        read -r
        iperf3 -c "$REAL_IP" -t 30 -P 4 --connect-timeout 5000 2>&1 || echo "(iperf3 direct failed — is the serve side listening?)"
        echo ""
        echo "=== results summary ==="
        echo "  see above for tunnel vs direct throughput numbers"
        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
        echo "done"
        ;;
    *)
        usage
        ;;
esac
