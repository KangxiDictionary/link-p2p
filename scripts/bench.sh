#!/usr/bin/env bash
# Manual benchmark driver (outputs progressively so we can see where it hangs).
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

DURATION="${1:-8}"
LISTEN_PORT=19990

pkill -f 'link-p2p' 2>/dev/null
pkill -f iroh-relay 2>/dev/null
sleep 1

echo "[1/5] relay"
tools/iroh-relay --dev >/dev/null 2>&1 &
R=$!
sleep 2

echo "[2/5] serve"
./target/release/link-p2p serve --forward 127.0.0.1:19012 \
    --relay http://127.0.0.1:3340 --identity .bench-serve.key >.bench-serve.log 2>&1 &
S=$!
sleep 7
EP=$(parse_endpoint_id .bench-serve.log)
echo "      EndpointId: ${EP:0:12}..."

echo "[3/5] connect"
./target/release/link-p2p connect --to "$EP" --listen 127.0.0.1:$LISTEN_PORT \
    --relay http://127.0.0.1:3340 --identity .bench-conn.key >.bench-conn.log 2>&1 &
C=$!
sleep 5

P="${2:-4}"  # parallel streams, mirrors iperf3 -P

echo "[4/5] raw + tunnel baseline (${DURATION}s, P=$P)"
python3 -u scripts/bench.py $LISTEN_PORT $S $C $DURATION $P

echo "[5/5] done, cleaning up"
kill $R $S $C 2>/dev/null
rm -f .bench-*.key .bench-*.log
