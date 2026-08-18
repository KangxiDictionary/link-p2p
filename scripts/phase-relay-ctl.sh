#!/usr/bin/env bash
# Force (or un-force) the relay path for a phase test by DROPping inbound UDP
# from a peer's public IP. Needs root. Run on BOTH machines, with the other
# machine's public IP.
#
#   sudo ./phase-relay-ctl.sh force-relay <peer-public-ip>
#   sudo ./phase-relay-ctl.sh clear-relay <peer-public-ip>
#
# Why this works: the relay connection is a TCP/WebSocket to the relay node,
# so it is unaffected by an inbound-UDP DROP; only the direct hole-punched
# QUIC path dies, forcing all traffic through the relay.
set -eu

usage() {
    echo "usage: sudo $0 force-relay <peer-public-ip>" >&2
    echo "       sudo $0 clear-relay <peer-public-ip>" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || {
    echo "error: needs root (iptables)" >&2
    exit 1
}

case "${1:-}" in
    force-relay)
        IP="${2:-}"
        [ -n "$IP" ] || usage
        iptables -I INPUT -p udp -s "$IP" -j DROP
        echo "applied: iptables -I INPUT -p udp -s $IP -j DROP"
        echo "run 'sudo $0 clear-relay $IP' after the test to restore"
        ;;
    clear-relay)
        IP="${2:-}"
        [ -n "$IP" ] || usage
        iptables -D INPUT -p udp -s "$IP" -j DROP 2>/dev/null || {
            echo "no DROP rule found for $IP (nothing to clear)" >&2
            exit 1
        }
        echo "removed DROP rule for $IP"
        ;;
    *)
        usage
        ;;
esac
