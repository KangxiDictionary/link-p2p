#!/usr/bin/env bash
# FIN propagation test: does the sink see EOF after the client closes a
# large transfer? (The drain-stall hypothesis says it may be delayed.)
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

pkill -f 'link-p2p' 2>/dev/null
pkill -f iroh-relay 2>/dev/null
sleep 1

tools/iroh-relay --dev >/dev/null 2>&1 &
R=$!
sleep 2

python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19012))
s.listen(4)
print('sink ready', flush=True)
c, _ = s.accept()
c.settimeout(15)
total = 0
t0 = time.monotonic()
try:
    while True:
        d = c.recv(65536)
        if not d:
            print(f'EOF after {total/1e6:.1f} MB, {time.monotonic()-t0:.2f}s', flush=True)
            break
        total += len(d)
except socket.timeout:
    print(f'NO EOF within 15s; received {total/1e6:.1f} MB', flush=True)
" >.fin-sink.log 2>&1 &
SINK=$!
sleep 1

./target/release/link-p2p serve --forward 127.0.0.1:19012 \
    --relay http://127.0.0.1:3340 --identity .fin-serve.key >.fin-serve.log 2>&1 &
S=$!
sleep 7
EP=$(parse_endpoint_id .fin-serve.log)
echo "EndpointId: ${EP:0:12}..."

./target/release/link-p2p connect --to "$EP" --listen 127.0.0.1:19990 \
    --relay http://127.0.0.1:3340 --identity .fin-conn.key >/dev/null 2>&1 &
C=$!
sleep 5

timeout 30 python3 -c "
import socket, time
c = socket.create_connection(('127.0.0.1', 19990), timeout=5)
payload = b'x' * (1 << 20)
for _ in range(20):
    c.sendall(payload)
t_close = time.monotonic()
print(f'client sent 20MB, closing at {t_close:.2f}', flush=True)
c.shutdown(socket.SHUT_WR)
c.close()
print('client closed', flush=True)
" 2>&1
echo "client exit: $?"

echo "=== 等 sink EOF（最多 20s）==="
for i in $(seq 1 20); do
    sleep 1
    if grep -q "EOF\|NO EOF" .fin-sink.log; then break; fi
done
cat .fin-sink.log

kill $R $S $C $SINK 2>/dev/null
rm -f .fin-*.key .fin-*.log
