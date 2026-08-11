#!/usr/bin/env bash
# Phase 0 — NAT matrix test helper
#
# Run me on two machines to check whether iroh achieves a direct connection
# through NAT, or falls back to the relay. Uses n0's public STUN/relay
# infrastructure (the default preset — no --relay flag), so iroh's built-in
# QUIC-NAT-TRAVERSAL (noq) is fully exercised.
#
# Usage:
#   Machine A (serve side):
#     ./phase0-nat-matrix.sh serve
#     → prints EndpointId, keeps running until Ctrl+C
#
#   Machine B (connect side):
#     ./phase0-nat-matrix.sh connect <EndpointId from A>
#     → connects, sleeps 15s, then prints path verdict and exits
#
# After both sides finish, check the logs under /tmp/phase0-{serve,conn}.log
# for the iroh debug output. Key strings to look for:
#   Established path_remote=Ip      → direct connection (hole-punch worked)
#   Established path_remote=Relay   → relayed (NAT too hostile)
#
# This test is meaningful only across two *different* machines on different
# networks (or at least different NATs). Running both sides on the same
# machine goes direct every time and tells you nothing.
set -eu

cd "$(dirname "$0")/.."
LOG_S="/tmp/phase0-serve.log"
LOG_C="/tmp/phase0-conn.log"
RUST_ENV="RUST_LOG=iroh=debug,link_p2p=info"
BIN="./target/release/link-p2p"
ID_S="/tmp/phase0-serve.key"
ID_C="/tmp/phase0-conn.key"

usage() {
    echo "Usage: $0 serve   (on machine A)"
    echo "       $0 connect <EndpointId>   (on machine B)"
    exit 1
}

case "${1:-}" in
    serve)
        rm -f "$ID_S" "$LOG_S"
        echo "=== Phase 0 NAT-matrix: serve ==="
        echo "  Starting tun serve without --relay (N0 preset: n0's STUN/relay)"
        echo "  RUST_LOG=iroh=debug → $LOG_S"
        env $RUST_ENV "$BIN" tun serve --identity "$ID_S" >"$LOG_S" 2>&1 &
        PID=$!
        sleep 8
        echo ""
        echo "  === share this with the connect side ==="
        grep -E "EndpointId|virtual IP" "$LOG_S" || true
        echo ""
        echo "  serve PID: $PID"

        # Watch the log for path events so the user can see what happened
        # without having to background the script and tail -f.
        echo "  waiting for NAT verdict (Ctrl+C anytime to stop)..."
        DEADLINE=$((SECONDS + 90))
        while [ $SECONDS -lt $DEADLINE ]; do
            if grep -q "path::selected" "$LOG_S" 2>/dev/null; then
                echo ""
                echo "  === NAT verdict (from $LOG_S) ==="
                grep -E "Established.*path|path.*selected|path_remote" "$LOG_S" | tail -10
                break
            fi
            sleep 2
        done
        echo ""
        echo "  Full log: $LOG_S    Ctrl+C to stop."
        wait $PID 2>/dev/null || true
        ;;
    connect)
        EP="${2:-}"
        [ -n "$EP" ] || usage
        rm -f "$ID_C" "$LOG_C"
        echo "=== Phase 0 NAT-matrix: connect ==="
        echo "  Dialing $EP via N0 preset"
        echo "  RUST_LOG=iroh=debug → $LOG_C"
        env $RUST_ENV "$BIN" tun connect --to "$EP" --identity "$ID_C" >"$LOG_C" 2>&1 &
        PID=$!
        sleep 15
        echo ""
        echo "=== Verdict (look for Established / path_remote in $LOG_C) ==="
        grep -E "Established|path_remote|direct|Direct" "$LOG_C" || echo "(nothing yet — the connection may still be in discovery)"
        echo ""
        echo "  connect PID: $PID"
        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
        echo "done"
        ;;
    *)
        usage
        ;;
esac
