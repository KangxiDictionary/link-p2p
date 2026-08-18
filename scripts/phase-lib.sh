#!/usr/bin/env bash
# Shared bootstrap for the two-machine phase tests (NAT matrix, relay bench,
# WiFi<->4G migration). Sourced by scripts/phase*-{server,client}.sh.
#
# Both sides run `tun serve`/`tun connect` with the N0 preset (no --relay:
# real n0 STUN/relay, which is what the NAT tests are about) and
# RUST_LOG=iroh=debug so the logs carry the path-negotiation evidence the
# verdicts are based on.
#
# All sub-processes are started with LANG=C so banner parsing is stable
# regardless of the machine's locale (the app output is localized via
# gettext, so on zh_CN machines the English msgids only come out under
# LANG=C).

set -u

PHASE_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Overridable, e.g. to stub the binary in tests.
PHASE_BIN="${PHASE_BIN:-$PHASE_REPO_DIR/target/release/link-p2p}"
PHASE_RUST_LOG="${PHASE_RUST_LOG:-iroh=debug,link_p2p=debug}"
PHASE_SERVE_PID=""
PHASE_CONN_PID=""
# Extra daemons the caller started (iperf3 servers, ...), space-separated.
PHASE_HELPER_PIDS=""

[ -x "$PHASE_BIN" ] || {
    echo "release binary not built: run 'cargo build --release' first" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    echo "warning: not running as root — TUN device creation will fail unless you have CAP_NET_ADMIN" >&2
    echo "         these phase tests need TUN mode; run them with sudo." >&2
fi

# Start `tun serve` with the N0 preset and poll for the banner (n0 online can
# take up to ~30s on real networks, so this is a poll, not a fixed sleep).
#   phase_serve <key-file> <log-file>
# Sets: PHASE_SERVE_PID, PHASE_SERVE_EP, PHASE_SERVE_VIP.
phase_serve() {
    local key="$1" log="$2"
    rm -f "$key" "$log"
    env LANG=C RUST_LOG="$PHASE_RUST_LOG" \
        "$PHASE_BIN" tun serve --identity "$key" >"$log" 2>&1 &
    PHASE_SERVE_PID=$!
    local deadline=$((SECONDS + 90))
    while [ $SECONDS -lt $deadline ]; do
        grep -q "your EndpointId" "$log" 2>/dev/null && break
        sleep 2
    done
    grep -q "your EndpointId" "$log" 2>/dev/null || {
        echo "serve: no EndpointId banner within 90s — see $log" >&2
        exit 1
    }
    PHASE_SERVE_EP=$(awk '/your EndpointId/{getline; gsub(/[[:space:]]+/, ""); print}' "$log" | tail -1)
    PHASE_SERVE_VIP=$(awk '/your virtual IP/{getline; gsub(/[[:space:]]+/, ""); print}' "$log" | tail -1)
    [ -n "${PHASE_SERVE_EP:-}" ] || {
        echo "serve: EndpointId parse failed — see $log" >&2
        exit 1
    }
    echo "serve ready: VIP=${PHASE_SERVE_VIP:-?}, EndpointId=${PHASE_SERVE_EP:0:12}.."
}

# Print the values the connect side needs, clearly.
phase_share_box() {
    echo ""
    echo "  ======================================================="
    echo "   share these with the connect side:"
    echo "     EndpointId: ${PHASE_SERVE_EP}"
    echo "     virtual IP: ${PHASE_SERVE_VIP:-?}"
    echo "  ======================================================="
    echo ""
}

# Start `tun connect` and poll for the app's "connected." banner.
#   phase_connect <key-file> <log-file> <endpoint-id>
# Sets: PHASE_CONN_PID, PHASE_CONN_VIP (this side's own VIP),
#       PHASE_PEER_VIP (the serve side's VIP).
phase_connect() {
    local key="$1" log="$2" ep="$3"
    rm -f "$key" "$log"
    env LANG=C RUST_LOG="$PHASE_RUST_LOG" \
        "$PHASE_BIN" tun connect --to "$ep" --identity "$key" >"$log" 2>&1 &
    PHASE_CONN_PID=$!
    local deadline=$((SECONDS + 90))
    while [ $SECONDS -lt $deadline ]; do
        grep -q "connected. your virtual IP" "$log" 2>/dev/null && break
        sleep 2
    done
    grep -q "connected. your virtual IP" "$log" 2>/dev/null || {
        echo "connect: no 'connected' banner within 90s — see $log" >&2
        exit 1
    }
    PHASE_CONN_VIP=$(grep -oP 'connected\. your virtual IP: \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$log" | tail -1)
    PHASE_PEER_VIP=$(grep -oP 'reachable at \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$log" | tail -1)
    [ -n "${PHASE_PEER_VIP:-}" ] || {
        echo "connect: peer VIP parse failed — see $log" >&2
        exit 1
    }
    echo "connect ready: own VIP=$PHASE_CONN_VIP, peer VIP=$PHASE_PEER_VIP"
}

# Stop whatever this side started. link-p2p gets SIGINT so its graceful
# shutdown (endpoint.close / route cleanup) runs; helpers get SIGTERM.
phase_cleanup() {
    local p
    for p in "$PHASE_SERVE_PID" "$PHASE_CONN_PID"; do
        [ -n "$p" ] && kill -INT "$p" 2>/dev/null
    done
    for p in ${PHASE_HELPER_PIDS:-}; do
        kill "$p" 2>/dev/null
    done
    wait 2>/dev/null
    return 0
}

# Classify the negotiated path from an iroh debug log, based on the LAST
# path::selected event (so a forced-relay run that failed over is reported as
# relayed even though a direct path was logged earlier).
phase_path_verdict() {
    local log="$1"
    echo "=== path evidence ($(basename "$log")) ==="
    if grep -q "path::selected" "$log" 2>/dev/null; then
        grep -E "path::selected|Established" "$log" | tail -3 || true
        local last cur
        last=$(grep "path::selected" "$log" 2>/dev/null | tail -1 || true)
        # The current path is the FIRST network_path= in the line; the second
        # one (prev_network_path=...) must not influence the verdict.
        cur=$(printf '%s\n' "$last" | grep -oP 'network_path=(?:Ip|Relay)\(' | head -1 || true)
        case "$cur" in
            "network_path=Ip(")
                echo "  → DIRECT connection (hole-punch succeeded)"
                ;;
            "network_path=Relay(")
                echo "  → RELAYED path (NAT did not allow a direct connection)"
                ;;
            *)
                echo "  → path state unclear (see last event above)"
                ;;
        esac
    else
        echo "  (no path-negotiation events logged yet)"
    fi
}

# This side's STUN-probed public IP from an iroh debug log (direct_addrs
# entries with typ: Qad). Empty if not discovered yet.
phase_public_ip() {
    local log="$1"
    grep -oP 'addr: \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=:[0-9]+, typ: Qad)' "$log" 2>/dev/null | tail -1
}

# The peer's public IP from a direct-path line in an iroh debug log:
#   path::selected ... network_path=Ip(192.168.2.11->223.74.153.47:9067)
# Empty if no direct path was ever established.
phase_peer_public_ip() {
    local log="$1"
    grep -oP 'Ip\([0-9.]+->\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$log" 2>/dev/null | tail -1
}

# Force the relay path by DROPping inbound UDP from a peer's public IP
# (root needed). Run on BOTH machines with the other side's public IP.
phase_force_relay() {
    local ip="$1"
    iptables -I INPUT -p udp -s "$ip" -j DROP
    echo "applied: iptables -I INPUT -p udp -s $ip -j DROP (relay forced locally)"
}
phase_clear_relay() {
    local ip="$1"
    iptables -D INPUT -p udp -s "$ip" -j DROP 2>/dev/null || true
    echo "removed DROP rule for $ip"
}
