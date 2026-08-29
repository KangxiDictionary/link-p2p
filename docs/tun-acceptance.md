# TUN acceptance checklist (desktop)

Manual checks before shipping a release that touches `src/tun.rs` or platform
routing/MTU helpers. Linux is the maintainer baseline; **macOS and Windows are
best-effort** — please open an issue with OS build, command line, and logs if
anything here fails.

Privileges: root / `CAP_NET_ADMIN` (Linux, macOS); Administrator + `wintun.dll`
beside the binary (Windows). VIPs are **IPv4 only** (`172.24.0.0/16` by default).

## Matrix

Run each row on every platform you care about for this release.

| # | Check | How | Pass if |
|---|---|---|---|
| 1 | Serve starts | `sudo link-p2p tun serve` (elevated on Windows) | Prints VIP + `ENDPOINT_ID=…`; interface up |
| 2 | Connect + ICMP | Peer: `tun connect --to <id>`; both sides `ping <peer VIP>` | RTT replies both ways |
| 3 | TCP over VIP | e.g. `nc -l` / `nc` or `ssh user@<peer VIP>` | Payload round-trips |
| 4 | Reconnect / route cleanup | Stop serve (Ctrl+C), restart serve (new or same identity), connect again | Old peer `/32` gone; new session works; no stale host route |
| 5 | MTU raise | `RUST_LOG=link_p2p=info`; watch `TUN datagram negotiation` then optional `TUN interface MTU raised` | No outer fragmentation; large `ping -s 1200` eventually ok |
| 6 | MTU shrink path | Force a lower path MTU if you can (VPN/relay), or rely on oversize drops | Log shows lowered MTU and/or ICMP Frag Needed; TCP recovers (not a permanent black hole) |
| 7 | Ctrl+C teardown | Ctrl+C on both sides | Interface removed (or Wintun adapter released); peer route deleted |
| 8 | VIP collision | Assign the same `--tun-ip` to a real local iface, then start tun | Clear error; process exits without creating a second binding |
| 9 | Exit codes | Block UDP / refuse peer; run `tun serve` / first `tun connect` | Online wait → exit **4**; bind/connect hard fail → exit **3** (locale-independent) |

## Windows-specific

- Confirm `wintun.dll` architecture matches the exe.
- After MTU changes, `netsh interface ipv4 show subinterfaces` should reflect the
  requested MTU when `netsh … set subinterface` succeeded; if it did not, ICMP
  injection is the only PMTUD signal — re-test with a firewall that drops ICMP
  to see whether TCP stalls (known residual risk; report if you hit it).

## macOS-specific

- Interface name is `utunN` (kernel-assigned).
- Reconnect should not leave a window where `route -n get <peer VIP>` fails
  longer than a single failed `route add` retry.
