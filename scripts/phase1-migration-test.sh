#!/usr/bin/env bash
# Phase 1 — WiFi↔4G connection migration test
#
# Verifies that switching a machine's network (WiFi → mobile hotspot, or
# WiFi → 4G) keeps the TUN session alive: iroh/noq's MagicSocket should move
# the QUIC connection to a new path underneath, and the application layer
# must NOT tear the session down (that was the run_datagram_loop fix).
#
# How to run (two machines):
#   Machine A (serve):  sudo ./phase1-migration-test.sh serve
#   Machine B (connect): sudo ./phase1-migration-test.sh connect <EndpointId>
#
# On the connect side the script waits 30s while you switch B's network
# (toggle WiFi / turn on hotspot). It pings the serve VIP continuously
# during the wait, then prints the verdict:
#   - how many pings were dropped during the switch (should be a handful,
#     not 100%)
#   - whether iroh logged a path switch (path::selected / network_path)
#   - whether the session was torn down (peer disconnected / new handshake)
#
# Both sides run with RUST_LOG=iroh=debug,link_p2p=debug so one test yields
# two datasets: iroh's path events AND the app layer's reaction.
set -eu

cd "$(dirname "$0")/.."
LOG_S="/tmp/phase1-serve.log"
LOG_C="/tmp/phase1-conn.log"
RUST_ENV="RUST_LOG=iroh=debug,link_p2p=debug"
BIN="./target/release/link-p2p"
ID_S="/tmp/phase1-serve.key"
ID_C="/tmp/phase1-conn.key"

usage() {
    echo "Usage: $0 serve   (machine A)"
    echo "       $0 connect <EndpointId>   (machine B)"
    exit 1
}

case "${1:-}" in
    serve)
        rm -f "$ID_S" "$LOG_S"
        echo "=== Phase 1 migration test: serve ==="
        echo "  RUST_LOG=iroh=debug → $LOG_S"
        env $RUST_ENV "$BIN" tun serve --identity "$ID_S" >"$LOG_S" 2>&1 &
        PID=$!
        sleep 8
        echo ""
        echo "  === share this with the connect side ==="
        grep -E "EndpointId|virtual IP" "$LOG_S" || true
        echo ""
        echo "  serve PID: $PID   Ctrl+C to stop."
        wait $PID
        ;;
    connect)
        EP="${2:-}"
        [ -n "$EP" ] || usage
        rm -f "$ID_C" "$LOG_C"
        echo "=== Phase 1 migration test: connect ==="
        echo "  RUST_LOG=iroh=debug → $LOG_C"
        env $RUST_ENV "$BIN" tun connect --to "$EP" --identity "$ID_C" >"$LOG_C" 2>&1 &
        PID=$!
        sleep 10
        echo ""
        SERVE_VIP=$(grep -oP 'reachable at \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_C" | tail -1 || true)
        [ -n "$SERVE_VIP" ] || SERVE_VIP=$(grep -oP 'virtual IP .* \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_C" | tail -1 || echo "??")
        echo "  serve VIP: $SERVE_VIP"
        echo ""
        echo "  >>> Now switch machine B's network (WiFi off/on, or turn on"
        echo "      the hotspot). Pinging for the next 30s..."
        echo ""
        # Ping continuously during the switch so we can count dropped pings.
        ping -i 0.5 -W 1 -c 60 "$SERVE_VIP" 2>&1 | tail -4 || true
        echo ""
        echo "=== iroh path events (path switch evidence) ==="
        grep -E "path::selected|network_path|set_status" "$LOG_C" | tail -8 || echo "(none logged)"
        echo ""
        echo "=== session survived? (no 'peer disconnected' / no re-handshake) ==="
        if grep -q "peer disconnected" "$LOG_C"; then
            echo "  ❌ SESSION WAS TORN DOWN — migration failed at the app layer"
        else
            echo "  ✅ session stayed up (no 'peer disconnected' in log)"
        fi
        if grep -c "TUN session established" "$LOG_C" | grep -q '^[1-9]'; then
            echo "  note: a re-handshake happened (new VIP exchange) — check timing"
        fi
        echo ""
        echo "  full log: $LOG_C"
        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
        echo "done"
        ;;
    *)
        usage
        ;;
esac
