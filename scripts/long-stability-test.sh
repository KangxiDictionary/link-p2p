#!/usr/bin/env bash
# Long-lived stream-mode stability check (two machines).
#
# Single-shot benches over a fresh direct path almost always look great;
# this script keeps a session up for DURATION seconds and samples:
#   - periodic HTTP GET through the tunnel (success / latency)
#   - periodic `link-p2p ping` RTT + path report
#   - whether the connect process stayed alive (no silent death)
#
# Does NOT require root (stream mode). Does NOT touch Tailscale.
#
# Roles:
#   SERVER (default): start http.server + `serve --forward`, print EndpointId,
#                     wait until Ctrl+C / DURATION.
#   CLIENT:           `DURATION=600 PEER=<id> ./scripts/long-stability-test.sh client`
#
# Env:
#   DURATION     seconds to run (default 600)
#   SAMPLE_SECS  probe interval (default 15)
#   LISTEN_PORT  connect listen port (default 19998)
#   HTTP_PORT    forward target on serve (default 18081)
#   BIN          path to link-p2p binary (default target/release/link-p2p)
#   RELAY        optional --relay URL (omit for default n0)
#   RUST_LOG     default link_p2p=info,iroh=info
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

ROLE="${1:-serve}"
DURATION="${DURATION:-600}"
SAMPLE_SECS="${SAMPLE_SECS:-15}"
LISTEN_PORT="${LISTEN_PORT:-19998}"
HTTP_PORT="${HTTP_PORT:-18081}"
BIN="${BIN:-target/release/link-p2p}"
export LANG=C LC_ALL=C LANGUAGE=
export RUST_LOG="${RUST_LOG:-link_p2p=info,iroh=info}"
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"

RELAY_ARGS=()
if [ -n "${RELAY:-}" ]; then
    RELAY_ARGS=(--relay "$RELAY")
fi

if [ ! -x "$BIN" ]; then
    echo "missing binary: $BIN (cargo build --release first)" >&2
    exit 1
fi

LOG_DIR="${LOG_DIR:-$(mktemp -d -t link-p2p-stability.XXXXXX)}"
mkdir -p "$LOG_DIR"
echo "logs → $LOG_DIR"

cleanup() {
    kill "${HTTP_PID:-}" "${SERVE_PID:-}" "${CONNECT_PID:-}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

case "$ROLE" in
serve|server)
    echo "=== long-stability SERVE for ${DURATION}s ==="
    python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 \
        >"$LOG_DIR/http.log" 2>&1 &
    HTTP_PID=$!
    sleep 1

    "$BIN" serve --forward "127.0.0.1:$HTTP_PORT" \
        --identity "$LOG_DIR/serve.key" \
        "${RELAY_ARGS[@]}" \
        >"$LOG_DIR/serve.log" 2>&1 &
    SERVE_PID=$!

    EP=""
    for _ in $(seq 1 60); do
        EP=$(parse_endpoint_id "$LOG_DIR/serve.log" 2>/dev/null || true)
        if [ -n "$EP" ]; then
            break
        fi
        sleep 1
    done
    if [ -z "$EP" ]; then
        echo "failed to read ENDPOINT_ID from serve log:" >&2
        tail -50 "$LOG_DIR/serve.log" >&2 || true
        exit 1
    fi
    echo
    echo "=========================================="
    echo "  EndpointId: $EP"
    echo "  On client:  PEER=$EP DURATION=$DURATION \\"
    echo "              ./scripts/long-stability-test.sh client"
    echo "=========================================="
    echo

    end=$((SECONDS + DURATION))
    while [ "$SECONDS" -lt "$end" ]; do
        if ! kill -0 "$SERVE_PID" 2>/dev/null; then
            echo "FAIL: serve exited early" >&2
            tail -80 "$LOG_DIR/serve.log" >&2 || true
            exit 1
        fi
        sleep 5
    done
    echo "serve window done; exiting"
    ;;

client)
    PEER="${PEER:?set PEER=<EndpointId> from the serve banner}"
    echo "=== long-stability CLIENT → $PEER for ${DURATION}s (sample every ${SAMPLE_SECS}s) ==="

    "$BIN" connect --to "$PEER" --listen "127.0.0.1:$LISTEN_PORT" \
        --identity "$LOG_DIR/conn.key" \
        "${RELAY_ARGS[@]}" \
        >"$LOG_DIR/connect.log" 2>&1 &
    CONNECT_PID=$!

    # Wait for listen port.
    for _ in $(seq 1 90); do
        if ss -ltn 2>/dev/null | grep -q ":$LISTEN_PORT " || \
           netstat -ltn 2>/dev/null | grep -q ":$LISTEN_PORT "; then
            break
        fi
        if ! kill -0 "$CONNECT_PID" 2>/dev/null; then
            echo "FAIL: connect died before listen" >&2
            cat "$LOG_DIR/connect.log" >&2 || true
            exit 1
        fi
        sleep 1
    done

    RESULT="$LOG_DIR/samples.tsv"
    echo -e "t_rel_s\thttp_ok\thttp_ms\tping_rtt_ms\tping_path\tconnect_alive" >"$RESULT"

    ok=0
    fail=0
    end=$((SECONDS + DURATION))
    while [ "$SECONDS" -lt "$end" ]; do
        t=$SECONDS
        alive=1
        kill -0 "$CONNECT_PID" 2>/dev/null || alive=0

        http_ok=0
        http_ms=-1
        if [ "$alive" = 1 ]; then
            start_ns=$(date +%s%N)
            if curl -fsS -m 10 "http://127.0.0.1:$LISTEN_PORT/" -o /dev/null; then
                http_ok=1
                end_ns=$(date +%s%N)
                http_ms=$(( (end_ns - start_ns) / 1000000 ))
                ok=$((ok + 1))
            else
                fail=$((fail + 1))
            fi
        else
            fail=$((fail + 1))
        fi

        ping_rtt="-"
        ping_path="-"
        if ping_out=$("$BIN" ping --to "$PEER" "${RELAY_ARGS[@]}" 2>/dev/null); then
            # Best-effort parse; keep raw fragments if format drifts.
            ping_rtt=$(printf '%s\n' "$ping_out" | sed -n 's/.*RTT[=: ]*\([0-9.]*\) *ms.*/\1/p' | head -1)
            ping_path=$(printf '%s\n' "$ping_out" | sed -n 's/.*path[: ]*\(.*\)/\1/p' | head -1 | tr '\t' ' ')
            [ -n "$ping_rtt" ] || ping_rtt="?"
            [ -n "$ping_path" ] || ping_path="?"
        fi

        echo -e "${t}\t${http_ok}\t${http_ms}\t${ping_rtt}\t${ping_path}\t${alive}" | tee -a "$RESULT"
        if [ "$alive" = 0 ]; then
            echo "FAIL: connect process died at t=${t}s" >&2
            tail -80 "$LOG_DIR/connect.log" >&2 || true
            break
        fi
        sleep "$SAMPLE_SECS"
    done

    echo
    echo "=== summary ==="
    echo "HTTP ok=$ok fail=$fail  samples → $RESULT"
    echo "connect log: $LOG_DIR/connect.log"
    if [ "$fail" -gt 0 ] || [ "$alive" = 0 ]; then
        exit 1
    fi
    ;;

*)
    echo "usage: $0 {serve|client}" >&2
    exit 2
    ;;
esac
