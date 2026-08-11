#!/usr/bin/env bash
# SOCKS5 end-to-end test: serve --proxy + connect --socks5-listen, then
# reach an arbitrary target via curl --socks5 (IP) and --socks5-hostname (domain).
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."

pkill -f 'link-p2p' 2>/dev/null
pkill -f iroh-relay 2>/dev/null
sleep 1

tools/iroh-relay --dev >/dev/null 2>&1 &
R=$!
sleep 2
# arbitrary target (not known to serve at startup)
python3 -m http.server 18082 --bind 127.0.0.1 >/dev/null 2>&1 &
H=$!
sleep 1

./target/release/link-p2p serve --proxy --relay http://127.0.0.1:3340 \
    --identity .s5-serve.key >.s5-serve.log 2>&1 &
S=$!
sleep 7
EP=$(sed -n 's/^    \([0-9a-f]\{52,\}\)$/\1/p' .s5-serve.log | head -1)
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
# quick TCP echo server on an ephemeral port
import threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(4)
port = srv.getsockname()[1]
def echo(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
def accept():
    while True:
        c, _ = srv.accept()
        threading.Thread(target=echo, args=(c,), daemon=True).start()
threading.Thread(target=accept, daemon=True).start()

# SOCKS5 client: greeting, CONNECT to 127.0.0.1:port, then echo round-trip
c = socket.create_connection(('127.0.0.1', 19997), timeout=5)
c.sendall(b'\x05\x01\x00')
assert c.recv(2) == b'\x05\x00', "method selection failed"
c.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + port.to_bytes(2, 'big'))
resp = c.recv(10)
assert resp[0] == 0x05 and resp[1] == 0x00, f"CONNECT failed: {resp.hex()}"
payload = b'hello-through-socks5-' * 100
c.sendall(payload)
c.shutdown(socket.SHUT_WR)
out = b''
try:
    while True:
        d = c.recv(65536)
        if not d: break
        out += d
except socket.timeout:
    pass  # echo server keeps the connection open; EOF never comes
print("echo round-trip:", "OK" if out == payload else f"MISMATCH {len(out)}/{len(payload)}")
EOF

kill $R $H $S $C 2>/dev/null
rm -f .s5-*.key .s5-*.log
