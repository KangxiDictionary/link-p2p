#!/usr/bin/env bash
# SOCKS5 e2e: serve --proxy + connect --socks5-listen → curl + binary echo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

require_relay || exit 1
require_release || exit 1
cleanup_link_p2p_procs

LOG_DIR="$(mktemp -d)"
info "logs → $LOG_DIR"

cleanup() {
    kill "${RELAY_PID:-}" "${HTTP_PID:-}" "${SERVE_PID:-}" "${CONNECT_PID:-}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

section "relay + http.server :18082"
tools/iroh-relay --dev >"$LOG_DIR/relay.log" 2>&1 &
RELAY_PID=$!
sleep 2
python3 -m http.server 18082 --bind 127.0.0.1 >"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

section "serve --proxy --allow-private"
# Loopback targets need --allow-private (SSRF guard blocks them by default).
target/release/link-p2p serve --proxy --allow-private \
    --relay http://127.0.0.1:3340 \
    --identity "$LOG_DIR/serve.key" >"$LOG_DIR/serve.log" 2>&1 &
SERVE_PID=$!

EP=$(wait_endpoint_id "$LOG_DIR/serve.log" 60) || {
    fail "no ENDPOINT_ID"
    cat "$LOG_DIR/serve.log" >&2
    exit 1
}
info "EndpointId ${EP:0:12}…"

section "connect --socks5-listen :19997"
target/release/link-p2p connect --socks5-listen 127.0.0.1:19997 \
    --relay http://127.0.0.1:3340 --to "$EP" \
    --identity "$LOG_DIR/conn.key" >"$LOG_DIR/conn.log" 2>&1 &
CONNECT_PID=$!
sleep 5

section "curl --socks5 (IP)"
CODE=$(curl -s -m 8 -o /dev/null -w '%{http_code}' --socks5 127.0.0.1:19997 http://127.0.0.1:18082/)
[[ "$CODE" == "200" ]] && pass "HTTP $CODE via IP" || { fail "HTTP $CODE via IP"; exit 1; }

section "curl --socks5-hostname (domain → serve DNS)"
CODE=$(curl -s -m 8 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:19997 http://localhost:18082/)
[[ "$CODE" == "200" ]] && pass "HTTP $CODE via hostname" || { fail "HTTP $CODE via hostname"; exit 1; }

section "binary echo via SOCKS5"
python3 - <<'EOF'
import socket, struct, threading, time, sys

def start_echo_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def echo_once(conn):
        try:
            data = conn.recv(65536)
            if data:
                conn.sendall(data)
        finally:
            conn.close()

    def accept_loop():
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=echo_once, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv, port

def socks5_connect(proxy_host, proxy_port, dest_host, dest_port):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
    sock.settimeout(5)
    sock.sendall(b"\x05\x01\x00")
    sel = sock.recv(2)
    assert sel == b"\x05\x00", f"method selection failed: {sel!r}"
    req = b"\x05\x01\x00\x01" + socket.inet_aton(dest_host) + struct.pack("!H", dest_port)
    sock.sendall(req)
    rep = bytearray()
    while len(rep) < 10:
        chunk = sock.recv(10 - len(rep))
        if not chunk:
            raise AssertionError("CONNECT reply truncated")
        rep.extend(chunk)
    assert rep[0] == 0x05 and rep[1] == 0x00, f"CONNECT failed: {bytes(rep).hex()}"
    return sock

payload = b"hello-through-socks5-" * 100
echo_srv, port = start_echo_server()
time.sleep(0.1)
direct = socket.create_connection(("127.0.0.1", port), timeout=5)
direct.settimeout(5)
direct.sendall(payload)
direct.shutdown(socket.SHUT_WR)
direct_out = direct.recv(len(payload) + 1)
direct.close()
if direct_out != payload:
    print(f"direct echo MISMATCH {len(direct_out)}/{len(payload)}", file=sys.stderr)
    raise SystemExit(1)

proxy_sock = socks5_connect("127.0.0.1", 19997, "127.0.0.1", port)
proxy_sock.sendall(payload)
proxy_sock.shutdown(socket.SHUT_WR)
proxy_out = b""
while len(proxy_out) < len(payload):
    chunk = proxy_sock.recv(len(payload) - len(proxy_out))
    if not chunk:
        break
    proxy_out += chunk
proxy_sock.close()
echo_srv.close()
if proxy_out != payload:
    print(f"proxy echo MISMATCH {len(proxy_out)}/{len(payload)}", file=sys.stderr)
    raise SystemExit(1)
print("ok")
EOF
pass "binary echo identical"

echo
pass "socks5 complete"
info "logs: $LOG_DIR"
