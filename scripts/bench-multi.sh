#!/usr/bin/env bash
# Multi-connection scaling experiment: N fully independent serve+connect
# pairs (own identity, own UDP socket, own QUIC connection), aggregate
# throughput measured for k = 1, 2, N pairs.
#
# Question: does throughput scale with the number of INDEPENDENT QUIC
# connections? (Single connection with many streams plateaued at ~330 MB/s
# while CPU climbed.) Linear scaling => per-connection state-machine
# seriality; flat => deeper bottleneck (crypto / UDP socket / poll loop).
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."

N="${1:-4}"
DURATION="${2:-6}"
SINK_BASE=19200
LISTEN_BASE=29200

pkill -f 'link-p2p' 2>/dev/null
pkill -f iroh-relay 2>/dev/null
sleep 1

tools/iroh-relay --dev >/dev/null 2>&1 &
R=$!
sleep 2

PIDS=""
for i in $(seq 1 $N); do
    ./target/release/link-p2p serve --forward 127.0.0.1:$((SINK_BASE + i - 1)) \
        --relay http://127.0.0.1:3340 --identity .bm-serve-$i.key >.bm-serve-$i.log 2>&1 &
    PIDS="$PIDS $!"
done
sleep 8

# collect each serve's EndpointId
for i in $(seq 1 $N); do
    EP=$(sed -n 's/^    \([0-9a-f]\{52,\}\)$/\1/p' .bm-serve-$i.log | head -1)
    eval "EP_$i=$EP"
done
echo "pairs: $N, endpoints: ${EP_1:0:8}.. ${EP_2:0:8}.. ${EP_3:0:8}.. ${EP_4:0:8}.."

for i in $(seq 1 $N); do
    EP="$(eval echo \$EP_$i)"
    ./target/release/link-p2p connect --to "$EP" \
        --listen 127.0.0.1:$((LISTEN_BASE + i - 1)) \
        --relay http://127.0.0.1:3340 --identity .bm-conn-$i.key >/dev/null 2>&1 &
    PIDS="$PIDS $!"
done
sleep 6

echo "=== 聚合吞吐（k=1, 2, $N 对独立 QUIC 连接）==="
python3 -u scripts/bench-multi.py $N $SINK_BASE $LISTEN_BASE $DURATION $PIDS

# cleanup
kill $R $PIDS 2>/dev/null
rm -f .bm-*.key .bm-*.log
