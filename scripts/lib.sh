#!/usr/bin/env bash
# Shared helpers for link-p2p test/bench scripts.
# Usage: source "$(dirname "$0")/lib.sh"   (from a script in scripts/)
#
# shellcheck shell=bash

# Repo root = parent of scripts/
: "${REPO_ROOT:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT"

# shellcheck source=scripts/parse-endpoint-id.sh
source "$REPO_ROOT/scripts/parse-endpoint-id.sh"

export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"
export LANG=C LC_ALL=C LANGUAGE=

# Readable status lines (no color if not a TTY).
if [[ -t 1 ]]; then
    _C_OK=$'\033[32m'
    _C_FAIL=$'\033[31m'
    _C_SKIP=$'\033[33m'
    _C_DIM=$'\033[2m'
    _C_RST=$'\033[0m'
else
    _C_OK= _C_FAIL= _C_SKIP= _C_DIM= _C_RST=
fi

pass() { printf '%sPASS%s  %s\n' "$_C_OK" "$_C_RST" "$*"; }
fail() { printf '%sFAIL%s  %s\n' "$_C_FAIL" "$_C_RST" "$*" >&2; }
skip() { printf '%sSKIP%s  %s\n' "$_C_SKIP" "$_C_RST" "$*"; }
info() { printf '%s·%s %s\n' "$_C_DIM" "$_C_RST" "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

require_bin() {
    local path="$1" hint="${2:-}"
    if [[ ! -x "$path" ]]; then
        fail "missing executable: $path${hint:+ ($hint)}"
        return 1
    fi
}

require_release() {
    require_bin target/release/link-p2p "run: cargo build --release"
}

require_relay() {
    local bin="${1:-tools/iroh-relay}"
    require_bin "$bin" "cargo install iroh-relay --features server && copy to tools/"
}

# Kill only our test binaries (Tailscale / other tmux sessions untouched).
cleanup_link_p2p_procs() {
    pkill -f '[t]arget/release/link-p2p' 2>/dev/null || true
    pkill -f '[i]roh-relay --dev' 2>/dev/null || true
    sleep 0.5
}

wait_endpoint_id() {
    local log="$1" timeout_s="${2:-60}" ep=""
    local i=0
    while (( i < timeout_s )); do
        ep=$(parse_endpoint_id "$log" 2>/dev/null || true)
        if [[ -n "$ep" ]]; then
            printf '%s' "$ep"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# Summary line for a suite: pass_count fail_count
summary() {
    local ok="$1" bad="$2"
    echo
    if (( bad == 0 )); then
        pass "all checks passed ($ok)"
        return 0
    fi
    fail "$bad failed, $ok passed"
    return 1
}
