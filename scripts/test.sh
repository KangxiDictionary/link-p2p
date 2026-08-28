#!/usr/bin/env bash
# Unified local test entry — readable PASS/FAIL summary.
#
# Usage:
#   ./scripts/test.sh              # unit + stream smoke + socks5
#   ./scripts/test.sh unit         # cargo test only
#   ./scripts/test.sh smoke        # local-test.sh (needs release + iroh-relay)
#   ./scripts/test.sh socks5       # test-socks5.sh
#   ./scripts/test.sh all          # unit + smoke + socks5 (default)
#   ./scripts/test.sh --help
#
# TUN / two-machine / bench are separate (need root or a peer):
#   sudo ./scripts/tun-loopback-test.sh
#   ./scripts/long-stability-test.sh {serve|client}
#   ./scripts/bench-transport-matrix.sh
#   ./scripts/phase0-*.sh / phase1-*.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

run_unit() {
    section "cargo test"
    if cargo test --quiet; then
        pass "unit tests"
        return 0
    fi
    fail "unit tests"
    return 1
}

run_smoke() {
    section "stream smoke (local-test)"
    if ! require_release || ! require_relay; then
        skip "smoke (build release + tools/iroh-relay first)"
        return 0
    fi
    if "$SCRIPT_DIR/local-test.sh"; then
        pass "stream smoke"
        return 0
    fi
    fail "stream smoke"
    return 1
}

run_socks5() {
    section "socks5 proxy"
    if ! require_release || ! require_relay; then
        skip "socks5 (build release + tools/iroh-relay first)"
        return 0
    fi
    if "$SCRIPT_DIR/test-socks5.sh"; then
        pass "socks5"
        return 0
    fi
    fail "socks5"
    return 1
}

MODE="${1:-all}"
case "$MODE" in
-h|--help|help) usage; exit 0 ;;
unit|smoke|socks5|all) ;;
*)
    fail "unknown mode: $MODE"
    usage >&2
    exit 2
    ;;
esac

ok=0
bad=0
run_one() {
    if "$@"; then
        ok=$((ok + 1))
    else
        bad=$((bad + 1))
    fi
}

case "$MODE" in
unit)   run_one run_unit ;;
smoke)  run_one run_smoke ;;
socks5) run_one run_socks5 ;;
all)
    run_one run_unit
    run_one run_smoke
    run_one run_socks5
    ;;
esac

summary "$ok" "$bad"
