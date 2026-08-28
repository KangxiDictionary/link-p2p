#!/usr/bin/env bash
# Stream-mode smoke: relay → serve --forward → connect --listen → HTTP + echo.
# Usage: scripts/local-test.sh [path-to-iroh-relay]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

RELAY_BIN="${1:-tools/iroh-relay}"
RELAY_PORT=3340
SERVE_PORT=18080
LISTEN_PORT=19999

require_relay "$RELAY_BIN" || exit 1
require_release || exit 1

LOG_DIR="$(mktemp -d)"
info "logs → $LOG_DIR"

cleanup() {
    kill "${RELAY_PID:-}" "${HTTP_PID:-}" "${ECHO_PID:-}" "${SERVE_PID:-}" "${CONNECT_PID:-}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

cleanup_link_p2p_procs

section "relay :$RELAY_PORT"
"$RELAY_BIN" --dev >"$LOG_DIR/relay.log" 2>&1 &
RELAY_PID=$!
sleep 2

section "http.server :$SERVE_PORT"
python3 -m http.server "$SERVE_PORT" --bind 127.0.0.1 >"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

section "serve --forward"
target/release/link-p2p serve \
    --relay "http://127.0.0.1:$RELAY_PORT" \
    --forward "127.0.0.1:$SERVE_PORT" \
    --identity "$LOG_DIR/serve.key" >"$LOG_DIR/serve.log" 2>&1 &
SERVE_PID=$!

EP=$(wait_endpoint_id "$LOG_DIR/serve.log" 60) || {
    fail "no ENDPOINT_ID from serve"
    tail -30 "$LOG_DIR/serve.log" >&2 || true
    exit 1
}
info "EndpointId ${EP:0:12}…"

section "connect --listen :$LISTEN_PORT"
target/release/link-p2p connect \
    --to "$EP" \
    --relay "http://127.0.0.1:$RELAY_PORT" \
    --listen "127.0.0.1:$LISTEN_PORT" \
    --identity "$LOG_DIR/connect.key" >"$LOG_DIR/connect.log" 2>&1 &
CONNECT_PID=$!
sleep 4

section "HTTP GET through tunnel"
HTTP_CODE=$(curl -s -o "$LOG_DIR/body.html" -w '%{http_code}' "http://127.0.0.1:$LISTEN_PORT/")
if [[ "$HTTP_CODE" != "200" ]]; then
    fail "HTTP $HTTP_CODE (want 200)"
    cat "$LOG_DIR/serve.log" "$LOG_DIR/connect.log" >&2 || true
    exit 1
fi
BODY=$(cat "$LOG_DIR/body.html")
if [[ "$BODY" != *"Directory listing"* ]]; then
    fail "unexpected HTTP body"
    exit 1
fi
pass "HTTP 200"

section "100KB echo round-trip"
kill "$HTTP_PID" 2>/dev/null || true
wait "$HTTP_PID" 2>/dev/null || true
HTTP_PID=

python3 -c "
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $SERVE_PORT))
s.listen(8)
def h(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
" >"$LOG_DIR/echo.log" 2>&1 &
ECHO_PID=$!
sleep 1

PAYLOAD=$(python3 -c "print('x' * 100000)")
RESP=$(timeout 10 python3 -c "
import socket, sys
c = socket.create_connection(('127.0.0.1', $LISTEN_PORT), timeout=5)
payload = sys.stdin.buffer.read()
c.sendall(payload)
c.shutdown(socket.SHUT_WR)
c.settimeout(5)
out = b''
try:
    while True:
        d = c.recv(65536)
        if not d: break
        out += d
except socket.timeout:
    pass
print('MATCH' if out == payload else 'MISMATCH', len(out))
" <<<"$PAYLOAD" 2>&1) || true
kill "$ECHO_PID" 2>/dev/null || true
ECHO_PID=

if [[ "$RESP" == MATCH* ]]; then
    pass "echo ${RESP#MATCH } bytes identical"
else
    fail "echo got: $RESP"
    cat "$LOG_DIR/echo.log" >&2 || true
    exit 1
fi

echo
pass "stream smoke complete"
info "logs: $LOG_DIR"
