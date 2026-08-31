# TUN mode

Whole-machine IP mesh: hub coordination, spoke↔spoke direct paths, and hub
fallback forwarding over unreliable QUIC datagrams.

Stream modes (`serve`/`connect`) and TUN mode **coexist**; neither replaces the other.
Short recipes and install: [README](../../README.md) and [usage guide](../user-guide/usage.md).

---

## Topology

```
spoke A ──QUIC──┐                    ┌── spoke B
                ├── hub (roster +      │
spoke C ──QUIC──┘    fallback)        │
         A↔B prefer direct; else via hub
```

| Role | Command | Responsibility |
|---|---|---|
| Hub | `tun serve` | Accept peers, broadcast VIP↔EndpointId roster, forward when direct path missing |
| Spoke | `tun connect --to <hub>` | Join mesh, install `/16` route, dial other spokes when roster updates |

**Behavior:**

1. Hub accepts multiple sessions; demuxes TUN traffic by destination VIP.
2. After VIP handshake, hub broadcasts roster on a reliable control stream
   (ALPN `link-p2p/tun/2`; `/1` had VIP exchange only, no roster).
3. Spokes dial new peers with `endpoint.connect(..., TUN_ALPN)`; use direct path
   when available, else send via hub.
4. Hub keeps spoke↔spoke forwarding as **fallback** (symmetric NAT, etc.).
5. Hub send path uses **per-peer mpsc** so one blocked `send_datagram_wait` does
   not stall the whole read loop.

**Security:**

- Drop packets whose source VIP ≠ handshake VIP (spoof guard).
- Reject duplicate VIP on second join.
- Break simultaneous dial ties with EndpointId lexicographic order.
- `--allow` / `LINK_P2P_ALLOW`: allowlist EndpointId; deny → exit code **5** (`DENIED`).

---

## Virtual IP allocation

Default VIP = deterministic function of `EndpointId`; **actual bound address
exchanged at handshake** (supports `--tun-ip` overrides). **IPv4 only**
(`172.24.0.0/16`).

```
vip(ep) = 172.24.0.0/16 | (blake3(ep) low 16 bits as host)
```

| Rule | Rationale |
|---|---|
| Avoid `100.64.0.0/10` | Tailscale netfilter drops non-`tailscale0` 100.64/10 sources |
| Spoke installs `/16`; hub installs `/32` per peer | Full mesh reachability from spokes |
| Collision check at startup | Refuse if VIP conflicts with a local interface |
| `--tun-ip` | Override derived address |

---

## MTU and PMTUD

Final MTU = `min(--mtu, max_datagram_size())`. Default cap **1280**.

- Oversize packets: inject ICMP Fragmentation Needed.
- MTU raise/lower uses hysteresis to avoid flapping.
- Ops clamp when path is lossy: `--mtu 1162`.
- `--cc bbr3` often helps on lossy or relay-heavy paths — compare before filing
  throughput bugs (see [`architecture/performance.md`](../architecture/performance.md)).

### Transport layer

- Inner IP rides QUIC **datagrams** (unreliable).
- Roster uses reliable control stream (`LPR2` frames).
- Stream-mode `LPF1` hello belongs to `link-p2p/tcp-forward/1` — not used in TUN ALPN.

---

## CLI

```bash
link-p2p tun serve  [--tun-ip <addr>] [--mtu <mtu>] [--allow <id>]…
link-p2p tun connect --to <EndpointId> [--allow <id>]…
```

**Privileges:** root / `CAP_NET_ADMIN` (Linux, macOS); Administrator + signed
`wintun.dll` beside the binary (Windows). Linux shortcut:
`sudo setcap cap_net_admin+ep $(which link-p2p)`.

**Reconnect:** `tun connect` re-dials with exponential backoff; TUN interface and
`/16` route survive across sessions.

**Observability:** `link-p2p ping` reports initial and settled RTT/path. While on
relay, periodic `network_change` retries hole-punch; low relay throughput triggers
a yellow warning. For relay-only baseline, use `--relay-only` on both sides.

---

## Release acceptance checklist

Run before shipping a release that touches `src/tun.rs` or platform routing/MTU
helpers. Linux is the maintainer baseline; macOS and Windows are best-effort —
open an issue with OS, command line, and logs on failure.

| # | Check | How | Pass if |
|---|---|---|---|
| 1 | Serve starts | `sudo link-p2p tun serve` (elevated on Windows) | Prints VIP + `ENDPOINT_ID=…`; interface up |
| 2 | Connect + ICMP | Peer: `tun connect --to <id>`; both `ping <peer VIP>` | RTT both ways |
| 3 | TCP over VIP | e.g. `nc -l` / `nc` or `ssh user@<peer VIP>` | Payload round-trips |
| 4 | Reconnect / route cleanup | Stop serve, restart, connect again | Old `/32` gone; new session works |
| 5 | MTU raise | `RUST_LOG=link_p2p=info`; large `ping -s 1200` | No outer fragmentation; MTU raises when negotiated |
| 6 | MTU shrink | Lower path MTU if possible | Log shows lowered MTU and/or ICMP Frag Needed; TCP recovers |
| 7 | Ctrl+C teardown | Ctrl+C both sides | Interface removed; peer route deleted |
| 8 | VIP collision | Same `--tun-ip` on a real local iface, then start tun | Clear error; no second binding |
| 9 | Exit codes | Block UDP / refuse peer | Online wait → **4**; bind/connect hard fail → **3** |

### Platform notes

**Windows**

- `wintun.dll` architecture must match the exe (official signed `amd64\wintun.dll`).
- MTU: `netsh interface ipv4 set subinterface … mtu=` when path ceiling changes.
- Peer route: `netsh interface ipv4 add route <peer>/32 <WintunName>` — do not use
  `route add … <ownVIP>` (often blackholes traffic off Wintun).
- If `netsh` MTU fails, ICMP injection remains; re-test under strict ICMP drop policies.

**macOS**

- Interface name is kernel-assigned `utunN`.
- Reconnect should not leave `route -n get <peer VIP>` failing longer than one
  failed `route add` retry.

---

## Out of scope (roadmap)

Lazy dial-on-traffic, fine-grained ACL (per-port/CIDR), separate routing protocol,
public DHT (iroh covers discovery).
