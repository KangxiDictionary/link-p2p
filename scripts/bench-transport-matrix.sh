#!/usr/bin/env bash
# One-session loopback A/B matrix for transport / buffer attribution.
#
# Groups: baseline | sysctl | bbr3 | bbr3+windows
#
# Loopback-only. Window/CC conclusions need real-RTT (two-machine or
# `tc netem`); treat these numbers as config-exclusion, not protocol proof.
#
# GSO: to verify noq-udp GSO is on, try RUST_LOG including `noq_udp=debug`
# (confirm crate/target name against the locked noq-udp dependency —
# Linux GSO disable uses `crate::log::warn!` there).
set -euo pipefail

export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="127.0.0.1,localhost,::1"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/parse-endpoint-id.sh
source ./scripts/parse-endpoint-id.sh

DURATION="${1:-8}"
PARALLEL="${2:-4}"
LISTEN_PORT=19990
BIN=./target/release/link-p2p

if [[ ! -x "$BIN" ]]; then
    echo "error: need release binary at $BIN (cargo build --release)" >&2
    exit 1
fi

# --- sysctl restore (only if we changed anything) -------------------------
SYSCTL_KEYS=(
    net.core.rmem_max
    net.core.wmem_max
    net.core.rmem_default
    net.core.wmem_default
)
declare -A SYSCTL_OLD=()
SYSCTL_APPLIED=0

restore_sysctl() {
    if [[ "$SYSCTL_APPLIED" -eq 0 ]]; then
        return 0
    fi
    echo "[sysctl] restoring previous values"
    for k in "${SYSCTL_KEYS[@]}"; do
        if [[ -n "${SYSCTL_OLD[$k]:-}" ]]; then
            sudo sysctl -w "$k=${SYSCTL_OLD[$k]}" >/dev/null || true
        fi
    done
    SYSCTL_APPLIED=0
}

cleanup_procs() {
    # shellcheck disable=SC2086
    [[ -n "${RELAY_PID:-}" ]] && kill "$RELAY_PID" 2>/dev/null || true
    [[ -n "${SERVE_PID:-}" ]] && kill "$SERVE_PID" 2>/dev/null || true
    [[ -n "${CONN_PID:-}" ]] && kill "$CONN_PID" 2>/dev/null || true
    RELAY_PID= SERVE_PID= CONN_PID=
    rm -f .btm-*.key .btm-*.log
}

on_exit() {
    cleanup_procs
    restore_sysctl
}
trap on_exit EXIT

raise_sysctl() {
    echo "[sysctl] raising rmem/wmem (needs sudo)"
    echo "         caveat: iroh Builder does not setsockopt SO_RCVBUF/SO_SNDBUF;"
    echo "         effect on this process may be ~0 even if sysctl succeeds."
    for k in "${SYSCTL_KEYS[@]}"; do
        SYSCTL_OLD[$k]=$(sysctl -n "$k")
    done
    # Generous ceilings; exact values matter less than “raised vs default.”
    sudo sysctl -w net.core.rmem_max=134217728 >/dev/null
    sudo sysctl -w net.core.wmem_max=134217728 >/dev/null
    sudo sysctl -w net.core.rmem_default=16777216 >/dev/null
    sudo sysctl -w net.core.wmem_default=16777216 >/dev/null
    SYSCTL_APPLIED=1
}

unset_transport_env() {
    unset LINK_P2P_CC LINK_P2P_SEND_WINDOW LINK_P2P_STREAM_RECV_WINDOW || true
}

# Run one group: start relay+serve+connect under current env, bench, print MB/s.
# Echoes tunnel MB/s on stdout as the last line for capture; chatter on stderr.
run_group() {
    local group="$1"
    cleanup_procs
    pkill -f 'link-p2p' 2>/dev/null || true
    pkill -f iroh-relay 2>/dev/null || true
    sleep 1

    echo "[$group] relay" >&2
    tools/iroh-relay --dev >/dev/null 2>&1 &
    RELAY_PID=$!
    sleep 2

    echo "[$group] serve (CC=${LINK_P2P_CC:-default} send_win=${LINK_P2P_SEND_WINDOW:-default} recv_win=${LINK_P2P_STREAM_RECV_WINDOW:-default})" >&2
    "$BIN" serve --forward 127.0.0.1:19012 \
        --relay http://127.0.0.1:3340 --identity .btm-serve.key >.btm-serve.log 2>&1 &
    SERVE_PID=$!
    sleep 7
    local ep
    ep=$(parse_endpoint_id .btm-serve.log)
    echo "[$group] EndpointId: ${ep:0:12}..." >&2

    echo "[$group] connect" >&2
    "$BIN" connect --to "$ep" --listen 127.0.0.1:$LISTEN_PORT \
        --relay http://127.0.0.1:3340 --identity .btm-conn.key >.btm-conn.log 2>&1 &
    CONN_PID=$!
    sleep 5

    echo "[$group] bench (${DURATION}s, P=$PARALLEL)" >&2
    local out mbs
    out=$(python3 -u scripts/bench.py "$LISTEN_PORT" "$SERVE_PID" "$CONN_PID" "$DURATION" "$PARALLEL" | tee /dev/stderr)
    # Match: tunnel x4  :    330.0 MB/s
    mbs=$(echo "$out" | sed -n 's/^tunnel[^:]*:[[:space:]]*\([0-9.]*\) MB\/s.*/\1/p' | tail -1)
    if [[ -z "$mbs" ]]; then
        mbs="?"
    fi
    echo "$mbs"

    cleanup_procs
}

echo "=== link-p2p transport matrix (LOOPBACK ONLY) ==="
echo "NOTE: Window/CC conclusions need real-RTT (two-machine or tc netem)."
echo "      Loopback results below are for config exclusion, not protocol claims."
echo

declare -A RESULTS=()

# 1) baseline — defaults (CUBIC, stock buffers, no window overrides)
unset_transport_env
RESULTS[baseline]=$(run_group baseline)

# 2) sysctl — raised kernel defaults; same process env as baseline
raise_sysctl
unset_transport_env
RESULTS[sysctl]=$(run_group sysctl)
restore_sysctl

# 3) bbr3
unset_transport_env
export LINK_P2P_CC=bbr3
RESULTS[bbr3]=$(run_group bbr3)

# 4) bbr3 + large windows
export LINK_P2P_CC=bbr3
export LINK_P2P_SEND_WINDOW=67108864
export LINK_P2P_STREAM_RECV_WINDOW=33554432
RESULTS[bbr3+windows]=$(run_group bbr3+windows)
unset_transport_env

echo
echo "| group | tunnel MB/s (loopback) |"
echo "|---|---|"
for g in baseline sysctl bbr3 bbr3+windows; do
    echo "| $g | ${RESULTS[$g]} |"
done
echo
echo "Again: label these as **loopback**. Real-RTT required before trusting window/CC deltas."
