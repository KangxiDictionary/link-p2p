#!/usr/bin/env bash
# link-p2p TUN loopback smoke test.
#
# Starts a local relay (--dev on :3340), a `tun serve` and a `tun connect`
# all on the same machine, then runs bidirectional ping tests through the
# QUIC datagram tunnel.  Requires root (TUNSETIFF).  All state goes to /tmp;
# cleanup is automatic on exit (SIGINT / EXIT trap).
#
# Usage:
#   sudo scripts/tun-loopback-test.sh
#
# Optional overrides:
#   LINK_P2P=/elsewhere/link-p2p RELAY_BIN=/elsewhere/iroh-relay sudo scripts/tun-loopback-test.sh
#
# NOTE: this loopback test can NOT validate the tunnel's datagram data path.
# Both VIPs live on the same machine, so the kernel's `local` routing table
# (priority 0) beats the main-table /32 routes into the TUN devices: ping
# traffic is delivered locally and never enters the TUN. A passing ping here
# proves nothing about the datagram pump, and a failing one usually means the
# address range is being filtered by local netfilter rules (e.g. Tailscale
# DROPs 100.64/10 sources not arriving on tailscale0 — this machine hit
# exactly that). The script validates process startup, connection
# establishment and MTU negotiation only. The real data-path check is a ping
# across two machines.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/.."
LINK_P2P="${LINK_P2P:-$REPO_DIR/target/release/link-p2p}"
RELAY_BIN="${RELAY_BIN:-$REPO_DIR/tools/iroh-relay}"
RELAY_URL="http://127.0.0.1:3340"

ID_SERVE=$(mktemp -u /tmp/lp-tun-serve.key.XXXX)
ID_CONN=$(mktemp -u /tmp/lp-tun-conn.key.XXXX)
ID_CONN2=$(mktemp -u /tmp/lp-tun-conn2.key.XXXX)

# Prevent any proxy from intercepting loopback relay traffic.
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"

RED='\033[1;31m'; GREEN='\033[1;32m'; CYAN='\033[1;36m'; DIM='\033[2m'; NC='\033[0m'

RELAY_PID=""; SERVE_PID=""; CONN_PID=""
cleanup() {
    set +e
    echo; echo -e "${CYAN}--- cleanup ---${NC}"
    kill $CONN_PID 2>/dev/null || true
    kill $SERVE_PID 2>/dev/null || true
    kill $RELAY_PID 2>/dev/null || true
    wait 2>/dev/null
    rm -f "$ID_SERVE" "$ID_CONN" "$ID_CONN2"
    # Interfaces auto-destroyed when the link-p2p processes exit (fd close).
    echo -e "${CYAN}TUN interfaces auto-destroyed on fd close.${NC}"
}
trap cleanup EXIT INT TERM

# --- prerequisites ---
[ "$(id -u)" -eq 0 ] || { echo -e "${RED}Must be root.  Run: sudo $0${NC}"; exit 1; }
[ -x "$LINK_P2P"  ] || { echo -e "${RED}$LINK_P2P not built.  Run: cargo build --release${NC}"; exit 1; }
[ -x "$RELAY_BIN" ] || { echo -e "${RED}$RELAY_BIN not found.  Build iroh-relay first.${NC}"; exit 1; }
[ -c /dev/net/tun ] || { echo -e "${RED}/dev/net/tun missing.  modprobe tun?${NC}"; exit 1; }

echo -e "${CYAN}=== link-p2p TUN loopback smoke test ===${NC}"

# Warn if the binary predates the last commit (stale release build).
BUILD_TIME=$(stat -c %Y "$LINK_P2P" 2>/dev/null || echo 0)
if [ -f "$REPO_DIR/src/tun.rs" ]; then
    SRC_TIME=$(stat -c %Y "$REPO_DIR/src/tun.rs" 2>/dev/null || echo 0)
    if [ "$BUILD_TIME" -lt "$SRC_TIME" ]; then
        echo -e "${DIM}Source ($REPO_DIR/src/tun.rs) is newer than $LINK_P2P.${NC}"
        echo -e "${DIM}Consider: cargo build --release${NC}"
        echo ""
    fi
fi

echo ""

# --- 1. relay ---
echo -e "${DIM}Starting relay (--dev, port 3340)…${NC}"
"$RELAY_BIN" --dev >/tmp/lp-tun-relay.log 2>&1 &
RELAY_PID=$!
sleep 2
kill -0 "$RELAY_PID" 2>/dev/null || {
    echo -e "${RED}Relay failed to start.  Log: /tmp/lp-tun-relay.log${NC}"
    cat /tmp/lp-tun-relay.log
    exit 1
}
echo -e "  relay PID: $RELAY_PID"
echo ""

# --- 2. tun serve ---
echo -e "${DIM}Starting tun serve …${NC}"
LANG=C "$LINK_P2P" tun serve \
    --relay "$RELAY_URL" --identity "$ID_SERVE" \
    >/tmp/lp-tun-serve.log 2>&1 &
SERVE_PID=$!

SECONDS=0
while [ $SECONDS -lt 20 ]; do
    if grep -q "your EndpointId" /tmp/lp-tun-serve.log 2>/dev/null; then break; fi
    if ! kill -0 "$SERVE_PID" 2>/dev/null; then
        echo -e "${RED}tun serve died.  Log:${NC}"
        cat /tmp/lp-tun-serve.log
        exit 1
    fi
    sleep 1
done

# Extract EndpointId — id printed on its own line immediately after the
# "your EndpointId" prompt.  Read the line after the marker with awk.
SERVE_ID=$(awk '/your EndpointId/{getline; gsub(/[[:space:]]+/, ""); if(length($0)>=50) print}' /tmp/lp-tun-serve.log || true)
if [ -z "$SERVE_ID" ]; then
    echo -e "${RED}Could not extract EndpointId from serve output.${NC}"
    echo "  last serve lines:"
    tail -5 /tmp/lp-tun-serve.log
    exit 1
fi
echo "  serve PID  : $SERVE_PID"
echo -e "  EndpointId : ${GREEN}$SERVE_ID${NC}"
echo ""

# --- 3. tun connect ---
echo -e "${DIM}Starting tun connect …${NC}"
LANG=C "$LINK_P2P" tun connect \
    --to "$SERVE_ID" --relay "$RELAY_URL" --identity "$ID_CONN" \
    >/tmp/lp-tun-conn.log 2>&1 &
CONN_PID=$!

SECONDS=0
while [ $SECONDS -lt 20 ]; do
    if grep -q "connected\." /tmp/lp-tun-conn.log 2>/dev/null; then break; fi
    if ! kill -0 "$CONN_PID" 2>/dev/null; then
        echo -e "${RED}tun connect died.  Log:${NC}"
        cat /tmp/lp-tun-conn.log
        exit 1
    fi
    sleep 1
done
echo -e "  connect PID: $CONN_PID"
echo ""

# --- 4. extract VIPs from ip addr (kernel is the authority, not our logs) ---
sleep 1  # let ip route/addr settle

# link-p2p%d: first device = serve, second = connect.
SERVE_VIP=$(ip -o -4 addr show 2>/dev/null \
    | awk -F'[ /]+' '/link-p2p0[[:space:]]*inet/{print $4}' || true)
CONN_VIP=$(ip -o -4 addr show 2>/dev/null \
    | awk -F'[ /]+' '/link-p2p1[[:space:]]*inet/{print $4}' || true)

if [ -z "$SERVE_VIP" ] || [ -z "$CONN_VIP" ]; then
    echo -e "${RED}Could not find TUN interface IPs from 'ip addr'.${NC}"
    echo "  ip -o -4 addr show | grep link-p2p:"
    ip -o -4 addr show 2>/dev/null | grep -i link-p2p || echo "  (none)"
    exit 1
fi

echo -e "  serve VIP  : ${GREEN}$SERVE_VIP${NC}   (on link-p2p0)"
echo -e "  connect VIP: ${GREEN}$CONN_VIP${NC}   (on link-p2p1)"
echo ""

# --- 5. MTU negotiation ---
echo -e "${CYAN}=== MTU negotiation ===${NC}"
for log in /tmp/lp-tun-serve.log /tmp/lp-tun-conn.log; do
    grep -i "TUN datagram negotiation" "$log" 2>/dev/null || true
done
echo ""

# --- 6. ping serve → connect ---
echo -e "${CYAN}=== ping  serve (link-p2p0) → connect (${CONN_VIP}) ===${NC}"

echo -e "${DIM}# bare${NC}"
ping -c 4 -W 2 "$CONN_VIP" || echo -e "${RED}^^ FAILED${NC}"
echo ""

echo -e "${DIM}# -s 1200 -M do (inside 1280 clamp)${NC}"
ping -c 4 -W 2 -s 1200 -M do "$CONN_VIP" || echo -e "${RED}^^ FAILED${NC}"
echo ""

echo -e "${DIM}# -s 1500 -M do (EXCEEDS 1280 — expected to FAIL)${NC}"
ping -c 4 -W 2 -s 1500 -M do "$CONN_VIP" \
    && echo -e "${RED}^^ UNEXPECTED success — MTU clamp not enforced?${NC}" \
    || echo -e "${GREEN}^^ Expected: kernel refusal = clamp working${NC}"
echo ""

# --- 7. ping connect → serve (reverse direction) ---
echo -e "${CYAN}=== ping  connect (link-p2p1) → serve (${SERVE_VIP}) ===${NC}"

echo -e "${DIM}# bare${NC}"
ping -c 4 -W 2 "$SERVE_VIP" || echo -e "${RED}^^ FAILED${NC}"
echo ""

echo -e "${DIM}# -s 1200 -M do${NC}"
ping -c 4 -W 2 -s 1200 -M do "$SERVE_VIP" || echo -e "${RED}^^ FAILED${NC}"
echo ""

# --- 7.5 peer-exit route cleanup + reconnect (regression) ---
# The serve side must drop the peer's /32 route when the session ends, and a
# reconnect with a different virtual IP must not leave the old route behind.
echo -e "${CYAN}=== peer-exit route cleanup + reconnect ===${NC}"
OLD_CONN_VIP=$CONN_VIP

echo -e "${DIM}# SIGINT the connect; serve should remove its route...${NC}"
kill -INT $CONN_PID 2>/dev/null
sleep 3
if ip route show | grep -qF "$OLD_CONN_VIP dev link-p2p0"; then
    echo -e "${RED}FAIL: stale route $OLD_CONN_VIP still on link-p2p0 after peer exit${NC}"
    exit 1
fi
echo -e "${GREEN}OK: route $OLD_CONN_VIP removed after peer exit${NC}"

echo -e "${DIM}# reconnect with a fresh identity (different VIP)...${NC}"
ID_CONN2=$(mktemp -u /tmp/lp-tun-conn2.key.XXXX)
LANG=C "$LINK_P2P" tun connect \
    --to "$SERVE_ID" --relay "$RELAY_URL" --identity "$ID_CONN2" \
    >/tmp/lp-tun-conn2.log 2>&1 &
CONN_PID=$!

SECONDS=0
while [ $SECONDS -lt 20 ]; do
    if grep -q "connected\." /tmp/lp-tun-conn2.log 2>/dev/null; then break; fi
    if ! kill -0 "$CONN_PID" 2>/dev/null; then
        echo -e "${RED}second tun connect died. Log:${NC}"
        cat /tmp/lp-tun-conn2.log
        exit 1
    fi
    sleep 1
done
sleep 1
# The new connect may get link-p2p1 or a higher index once the old device is
# destroyed; match any link-p2p address that isn't the serve's.
NEW_CONN_VIP=$(ip -o -4 addr show 2>/dev/null \
    | awk -F'[ /]+' '/link-p2p[0-9]+[[:space:]]*inet/{print $4}' \
    | grep -v "^$SERVE_VIP$" | head -1 || true)
if [ -z "$NEW_CONN_VIP" ]; then
    echo -e "${RED}no connect VIP after reconnect${NC}"
    exit 1
fi
echo -e "  new connect VIP: ${GREEN}$NEW_CONN_VIP${NC}"

if ip route show | grep -qF "$OLD_CONN_VIP dev link-p2p0"; then
    echo -e "${RED}FAIL: old route $OLD_CONN_VIP reappeared after reconnect${NC}"
    exit 1
fi
if ip route show | grep -qF "$NEW_CONN_VIP dev link-p2p0"; then
    echo -e "${GREEN}OK: route to new peer VIP $NEW_CONN_VIP installed, no stale routes${NC}"
else
    echo -e "${RED}FAIL: no route to new peer VIP $NEW_CONN_VIP${NC}"
    exit 1
fi
echo ""

# --- 8. interface state ---
echo -e "${CYAN}=== Interfaces ===${NC}"
ip -o -4 addr show 2>/dev/null | grep -i link-p2p || echo "(none)"
echo ""
ip route show | grep -i link-p2p || echo "(no link-p2p routes)"
echo ""

echo -e "${DIM}Full logs: /tmp/lp-tun-{relay,serve,conn,conn2}.log${NC}"
echo -e "${GREEN}=== test complete ===${NC}"
