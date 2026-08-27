#!/usr/bin/env bash
# Shared EndpointId extraction for scripts/e2e harnesses.
#
# Prefer the machine line emitted by serve/tun serve (`ENDPOINT_ID=<hex>`,
# never localized). Fall back to the legacy indented hex line for older
# binaries still in the field.
#
# Usage:
#   source ./scripts/parse-endpoint-id.sh
#   ep="$(parse_endpoint_id "$logfile")"
#
# shellcheck disable=SC2034  # used when sourced

parse_endpoint_id() {
    local log="$1"
    local ep
    ep=$(sed -n 's/^ENDPOINT_ID=\([0-9a-f]\{64\}\)$/\1/p' "$log" | head -1)
    if [ -z "$ep" ]; then
        ep=$(sed -n 's/^    \([0-9a-f]\{64\}\)$/\1/p' "$log" | head -1)
    fi
    printf '%s' "$ep"
}

wait_for_endpoint_id() {
    local log="$1"
    grep -q '^ENDPOINT_ID=' "$log" 2>/dev/null \
        || grep -qE '^    [0-9a-f]{64}$' "$log" 2>/dev/null
}
