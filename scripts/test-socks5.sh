#!/usr/bin/env bash
# SOCKS5 end-to-end test: serve --proxy + connect --socks5-listen, then
# reach an arbitrary target via curl --socks5 (IP) and --socks5-hostname (domain).
set -euo pipefail
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

pkill -f '[t]arget/release/link-p2p' 2>/dev/null || true
pkill -f '[i]roh-relay' 2>/dev/null || true
sleep 1

if [ ! -x tools/iroh-relay ]; then
    echo "relay binary not found at tools/iroh-relay" >&2
    exit 1
fi
if [ ! -x target/release/link-p2p ]; then
    echo "link-p2p not built; run 'cargo build --release' first" >&2
    exit 1
fi

tools/iroh-relay --dev >/dev/null 2>&1 &
R=$!
sleep 2
# arbitrary target (not known to serve at startup)
python3 -m http.server 18082 --bind 127.0.0.1 >/dev/null 2>&1 &
H=$!
sleep 1

# Loopback targets need --allow-private (SSRF guard blocks them by default).
./target/release/link-p2p serve --proxy --allow-private --relay http://127.0.0.1:3340 \
    --identity .s5-serve.key >.s5-serve.log 2>&1 &
S=$!
sleep 7
EP=$(parse_endpoint_id .s5-serve.log)
if [ -z "$EP" ]; then
    echo "failed to get EndpointId from serve output:" >&2
    cat .s5-serve.log >&2
    exit 1
fi
echo "serve (proxy mode) EndpointId: $EP"

./target/release/link-p2p connect --socks5-listen 127.0.0.1:19997 \
    --relay http://127.0.0.1:3340 --to "$EP" --identity .s5-conn.key >.s5-conn.log 2>&1 &
C=$!
sleep 5

echo "=== curl --socks5（IP 目标）==="
curl -s -m 8 -o /dev/null -w "HTTP %{http_code}\n" --socks5 127.0.0.1:19997 http://127.0.0.1:18082/
echo "=== curl --socks5-hostname（域名目标，serve 侧解析）==="
curl -s -m 8 -o /dev/null -w "HTTP %{http_code}\n" --socks5-hostname 127.0.0.1:19997 http://localhost:18082/
echo "=== 二进制回环（echo server 经 SOCKS5）==="
python3 - <<'EOF'
import socket
import struct
import threading
import time

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
    req = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton(dest_host)
        + struct.pack("!H", dest_port)
    )
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

# 1. Direct baseline — echo server only, no SOCKS5 layer.
echo_srv, port = start_echo_server()
time.sleep(0.1)
direct = socket.create_connection(("127.0.0.1", port), timeout=5)
direct.settimeout(5)
direct.sendall(payload)
direct.shutdown(socket.SHUT_WR)
direct_out = direct.recv(len(payload) + 1)
direct.close()
print(
    "direct echo:",
    "OK" if direct_out == payload else f"MISMATCH {len(direct_out)}/{len(payload)}",
)

# 2. Same echo target through the SOCKS5 proxy chain.
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
print(
    "echo round-trip:",
    "OK" if proxy_out == payload else f"MISMATCH {len(proxy_out)}/{len(payload)}",
)
if direct_out != payload or proxy_out != payload:
    raise SystemExit(1)
EOF

kill $R $H $S $C 2>/dev/null || true
rm -f .s5-*.key .s5-serve.log .s5-conn.log
echo "=== ALL SOCKS5 TESTS PASSED ==="
