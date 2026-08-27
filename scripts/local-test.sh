#!/usr/bin/env bash
# Local end-to-end smoke test for link-p2p using a self-hosted relay.
#
# Requires: iroh-relay binary (built separately), python3 (as the TCP test
# target), curl, and a release build of link-p2p.
#
# Runs the full pipeline on localhost:
#   relay (3340)  <--serve-->  connect (9999)  --->  python http.server (8080)
#
# Usage: scripts/local-test.sh [path-to-iroh-relay]
set -u

RELAY_BIN="${1:-tools/iroh-relay}"
RELAY_PORT=3340
# Uncommon ports on purpose: 8080/9999 are frequently taken by other
# services (e.g. ipfs listens on 8080) and would break the test.
SERVE_PORT=18080  # python http.server (the "forward target")
LISTEN_PORT=19999 # local port exposed by `connect`

cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

# iroh's relay client fetches the relay's config over HTTP first. If a proxy
# is set in the environment (common in CI/sandboxes) it must not intercept
# loopback traffic, or the relay handshake gets 511'd. Same for curl below.
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"

if [ ! -x "$RELAY_BIN" ]; then
    echo "relay binary not found at $RELAY_BIN (build with: cargo install --path <iroh-relay src> --features server)" >&2
    exit 1
fi
if [ ! -x target/release/link-p2p ]; then
    echo "link-p2p not built; run 'cargo build --release' first" >&2
    exit 1
fi

LOG_DIR="$(mktemp -d)"
echo "logs in $LOG_DIR"

cleanup() {
    kill "${RELAY_PID:-}" "${HTTP_PID:-}" "${ECHO_PID:-}" "${SERVE_PID:-}" "${CONNECT_PID:-}" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

echo "=== starting relay on :$RELAY_PORT ==="
"$RELAY_BIN" --dev >"$LOG_DIR/relay.log" 2>&1 &
RELAY_PID=$!
sleep 2

echo "=== starting python http.server on :$SERVE_PORT (forward target) ==="
python3 -m http.server "$SERVE_PORT" --bind 127.0.0.1 >"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

echo "=== starting link-p2p serve ==="
target/release/link-p2p serve \
    --relay "http://127.0.0.1:$RELAY_PORT" \
    --forward "127.0.0.1:$SERVE_PORT" \
    --identity "$LOG_DIR/serve.key" >"$LOG_DIR/serve.log" 2>&1 &
SERVE_PID=$!
# iroh runs a 3s net_report before dialing the relay, so coming online takes
# ~4s even with a local relay; give it room on slow/constrained machines.
sleep 6

# Parse the machine line from serve stdout (`ENDPOINT_ID=<hex>`).
EP_ID=$(parse_endpoint_id "$LOG_DIR/serve.log")
if [ -z "$EP_ID" ]; then
    echo "failed to get EndpointId from serve output:" >&2
    cat "$LOG_DIR/serve.log" >&2
    exit 1
fi
echo "serve EndpointId: $EP_ID"

echo "=== starting link-p2p connect ==="
target/release/link-p2p connect \
    --relay "http://127.0.0.1:$RELAY_PORT" \
    --to "$EP_ID" \
    --listen "127.0.0.1:$LISTEN_PORT" \
    --identity "$LOG_DIR/connect.key" >"$LOG_DIR/connect.log" 2>&1 &
CONNECT_PID=$!
sleep 4

echo "=== HTTP GET through the tunnel ==="
HTTP_CODE=$(curl -s -o /tmp/local-test-body.html -w '%{http_code}' "http://127.0.0.1:$LISTEN_PORT/")
echo "HTTP status: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: expected 200, got $HTTP_CODE" >&2
    echo "--- serve.log ---"; cat "$LOG_DIR/serve.log"
    echo "--- connect.log ---"; cat "$LOG_DIR/connect.log"
    echo "--- relay.log ---"; tail -5 "$LOG_DIR/relay.log"
    exit 1
fi
BODY=$(cat /tmp/local-test-body.html)
echo "body: ${BODY:0:200}"
if [[ "$BODY" != *"Directory listing"* ]]; then
    echo "FAIL: unexpected body content" >&2
    exit 1
fi

echo "=== bidirectional byte-identical echo check ==="
# Stop the http.server and start a TCP echo server on the same forward
# target port, then round-trip a payload through the tunnel byte-for-byte.
kill "$HTTP_PID" 2>/dev/null
wait "$HTTP_PID" 2>/dev/null
HTTP_PID=
# Start a TCP echo server on the forward target port, then round-trip a
# payload through the tunnel and compare bytes.
python3 -c "
import socket, threading, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $SERVE_PORT))
s.listen(8)
def h(c):
    while True:
        d = c.recv(4096)
        if not d:
            break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
" >"$LOG_DIR/echo.log" 2>&1 &
ECHO_PID=$!
sleep 1

PAYLOAD=$(python3 -c "import os; print('x' * 100000)")
# Round-trip through the tunnel. The echo server never closes the
# connection (normal for a port forwarder), so the client will hit its
# recv timeout while waiting for EOF — that's expected. What matters is
# that it received the full payload byte-identically before the timeout.
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
        if not d:
            break
        out += d
except socket.timeout:
    pass  # echo server keeps the connection open; EOF never comes
print('MATCH' if out == payload else 'MISMATCH', len(out))
" <<< "$PAYLOAD" 2>&1)
kill "$ECHO_PID" 2>/dev/null

if [[ "$RESP" == MATCH* ]]; then
    echo "echo round-trip: OK (${RESP#MATCH } bytes, byte-identical)"
else
    echo "echo round-trip: FAILED (got: $RESP)" >&2
    echo "--- echo.log ---"; cat "$LOG_DIR/echo.log"
    exit 1
fi

echo
echo "=== ALL TESTS PASSED ==="
echo "serve.log:   $LOG_DIR/serve.log"
echo "connect.log: $LOG_DIR/connect.log"
