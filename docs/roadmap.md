# Roadmap / Known Gaps

This document captures what link-p2p currently has (v1) and what it deliberately
does not yet have, organised by layer. The comparison baseline is what mature
mesh VPNs (Tailscale, ZeroTier) provide; the gaps are ordered roughly by how much
they block real-world deployability.

---

## Current state (v1)

| capability | status |
|---|---|
| Stream mode: TCP-over-QUIC port forwarding (`serve --forward` / `connect --listen`) | done |
| SOCKS5 proxy mode (`serve --proxy` / `connect --socks5-listen`) | done |
| TUN mode: point-to-point whole-machine IP bridging over QUIC datagrams, Linux only | done |
| Persistent identity (per-machine secret key → stable `EndpointId`) | done |
| Self-hosted relay (`--relay`) | done |
| iroh presets::N0 (n0's public relay + DNS/pkarr discovery) | done |
| Deterministic default VIP derivation (BLAKE3 → 172.24.0.0/16) | done |
| VIP exchange at handshake (so `--tun-ip` actually works for peer routing) | done |
| Session-end route cleanup + graceful `endpoint.close()` | done |
| i18n (zh_CN, ja_JP, es_ES), shell completions, styled output | done |
| Benchmarking scripts (loopback TCP control + tunnel throughput + multi-conn scaling) | done |
| Test scripts (local smoke test, SOCKS5 test, TUN loopback smoke test) | done |

---

## Layer 1: Core connectivity (blockers for real-world deployment)

### 1. NAT traversal success rate across common NAT types

**Problem:** Most home and enterprise networks sit behind NAT. A direct QUIC
connection only works when at least one side has a publicly reachable UDP port
(full-cone NAT, or port forwarding). Without that, the traffic goes through a
relay — which is fine for connectivity but costs throughput and latency.

**Current:** iroh performs relay/address discovery internally and announces
candidate addresses to the peer (`presets::N0` uses n0's public relay +
DNS/pkarr). In theory this includes STUN-like candidate gathering, but we have
never explicitly tested or measured NAT-traversal success rates across different
NAT mappings (full-cone, restricted-cone, port-restricted, symmetric). When both
sides use a custom relay (`--relay`), the README warns that "skipping
pkarr/DNS also skips one source of direct-address candidates" — the hole-punching
path effectively degrades.

**Needed:**
- Explicit NAT-type classification (STUN probing).
- Measure and document success rates across common NAT combinations (same-LAN,
  full-cone ↔ symmetric, double-NAT, CGNAT).
- Evaluate whether iroh's built-in candidate exchange is sufficient, or whether
  we need to implement application-layer STUN/ICE.
- Multiple relay endpoints for redundancy, and relay health monitoring.

---

### 2. Connection migration on network changes

**Problem:** When a mobile device switches from WiFi to 4G, its public IP changes.
Without connection migration the tunnel breaks and the user has to restart (or
the application must reconnect from scratch, which means a new QUIC handshake).

**Current:** QUIC supports connection migration at the protocol level and
iroh/quinn likely implement it, but we don't trigger, test, or verify it. The
TUN datagram loop would see a read/write error when the path disappears, return
`PeerGone`, and the serve side would re-accept — which means a new Endpoint
binding, a new TUN handshake, and a new VIP exchange. That's a full teardown and
rebuild, not a migration.

**Needed:**
- Design a migration path: detect local address changes, re-probe STUN
  candidates, and feed them to iroh's path so QUIC connection migration kicks
  in — all without tearing down the TUN interface or the session state.
- Test the WiFi→4G handover scenario end to end.
- Graceful fallback: if migration fails, the current reconnect-on-disconnect
  behaviour must still work.

---

### 3. Relay throughput and latency — measured, not assumed

**Problem:** Every real deployment that isn't same-LAN will spend some (or all)
of its time on the relay path. We need to know the relay cost before we can
decide whether we need relay optimisation, geographic relay placement, or a
WireGuard-style direct-only fallback.

**Current:** The design doc explicitly notes "datagram 在 relay 路径上的吞吐/
丢包实测（本沙箱无法测真机网络）" as not yet done. The benchmarking section of
the README measures same-machine loopback only. Zero numbers exist for real-hardware
relay throughput, relay RTT, or relay packet loss.

**Needed:** Real-machine benchmarks for relayed throughput (iperf3 through the
TUN tunnel with both machines behind NAT forcing a relay path), with the same
metrics the current bench scripts use for direct paths.

---

## Layer 2: Multi-node coordination (beyond point-to-point)

### 4. Device discovery — no more copying EndpointIds by hand

**Problem:** Every new peer needs the other side's EndpointId pasted into a
`--to` argument. This doesn't scale to 3+ devices, and it makes device addition/
removal a manual chore.

**Current:** Zero coordination server, zero automatic discovery, zero
rendezvous protocol. This was an explicit v1 decision ("TUN v1 无任何服务端
组件"). The stream modes have the same limitation.

**Needed:**
- A minimal coordination protocol: a server (or DHT) that knows which
  EndpointIds are currently online and provides a way to look them up.
- Ideally tied to a user/org identity so the discovery scope is bounded.
- Examples: Tailscale's coordination server (keyed by SSO identity), iroh's
  own gossipsub discovery (which could be a lighter-weight starting point).

---

### 5. Key distribution and trust model

**Problem:** Currently every device generates its own secret key, stores it in
a file, and has a self-sovereign `EndpointId` derived from it. There's no way
for a human or an organisation to say "this EndpointId belongs to Alice's
laptop", no central roster, no revocation, and no way to prevent a compromised
key from rejoining the network.

**Current:** The `identity.key` is the sole trust anchor. The XDG default path
improved discoverability, but the model is still purely local. There is no
notion of a user, an organisation, a device label, or a device lifecycle
(enroll, attest, revoke).

**Needed:**
- A coordination server that binds devices to a user/org identity (e.g. OIDC,
  mutual TLS with client certs, or a simpler shared-secret model for small
  groups).
- The ability to label devices, list them, and revoke by ID.
- The identity file should be a *proof* of enrollment, not the entire
  enrollment itself.

---

### 6. ACL / fine-grained access control

**Problem:** Right now `tun serve` accepts connections from *any* peer who knows
the EndpointId and speaks the right ALPN. There is no per-peer, per-port, or
per-protocol filtering. In the stream modes, anyone who can dial the serve's
EndpointId can open a stream to the forwarded target. This is fine for a
personal two-machine link but unacceptable for multi-user or multi-device
setups.

**Current:** No ACL layer at all. The `secure` connection model is purely at
the transport level (authenticated QUIC). `EndpointId` is the only identity;
there's no second-level authorisation.

**Needed:**
- Allowlists: configure which EndpointIds may connect to which services.
- For TUN mode: per-peer, per-port/IP-range rules ("Bob can only reach
  192.168.1.5:443 on Alice's LAN").
- Policy should be centrally defined (at the coordination server) and enforced
  locally by each node.

---

## Layer 3: Usability and platform breadth

| area | current | needed |
|---|---|---|
| TUN mode — macOS | Linux only | futun / utun backend |
| TUN mode — Windows | Linux only | wintun / tap-windows adapter |
| Mobile clients | none | Android/iOS with appropriate VPN APIs, battery-aware |
| GUI / TUI | CLI only | at minimum a TUI status dashboard; longer term a system tray app |
| MagicDNS | manual IPs | local DNS resolver mapping peer hostnames → VIPs |
| Auto-update / packages | `cargo build` | binary releases, package repos, auto-update daemon |
| Service integration | none | systemd unit files, Docker images, OpenWrt packages |

---

## Layer 4: Edge-case hardening (comes from real-world scale)

| area | current | needed |
|---|---|---|
| Enterprise firewalls that block UDP | assumed open | QUIC-over-DTLS/DERP style fallback, or TCP-fallback for the control channel |
| IPv6 | VIP derivation is IPv4-only; TUN is v4 only | extend VIP scheme to IPv6; test dual-stack paths |
| MTU black-holes | relies on QUIC PMTUD + app-level refresh loop | explicit low-level PMTUD probing at the application layer for paths where QUIC PMTUD fails silently |
| TLS-intercepting proxies | untested | QUIC cert-pinning or manual public-key trust to detect MITM; iroh may do some of this |
| High-latency / high-loss paths (satellite) | untested | QUIC should handle this better than TCP, but the current default transport parameters may need tuning |

---

## What is deliberately left for later

- **Mesh topology** (more than two peers on one TUN interface): this requires
  a routing table, per-peer connection pools, and inner-IP demux — a different
  architecture than point-to-point.
- **Per-stream QoS / priority**: stream-mode reliability is currently uniform
  (ordered bidi); the datagram path is uniform "best-effort".
- **GSO / io_uring performance work**: the loopback benchmarks showed the
  bottleneck is QUIC protocol processing, not the kernel I/O path, so kernel
  batching won't lift the ceiling until the QUIC overhead is addressed.
