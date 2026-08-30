# Roadmap / Known Gaps

This document captures what link-p2p currently has (v1) and what it deliberately
does not yet have, organised by layer. The comparison baseline is what mature
mesh VPNs (Tailscale, ZeroTier) provide; the gaps are ordered roughly by how much
they block real-world deployability.

---

## Research update & prioritized implementation path (2026-08)

Before re-ordering the gaps below, one finding changes the shape of this whole
roadmap enough that it's worth stating up front:

**iroh shipped 1.0 in June 2026, on its own QUIC fork ("noq"), which
implements the IETF `QUIC-NAT-TRAVERSAL` draft *inside* the QUIC connection
itself** rather than as a bolt-on STUN/ICE layer. In production this reports
~90% direct-connection rates across real-world NAT combinations, and its
`MagicSocket` layer already does continuous multi-path probing with
uninterrupted switchover — i.e. connection migration — because the congestion
controller is aware of the hole-punch/path-switch as a native QUIC operation,
not an application-level reconnect. Practically: **Layer 1, items 1 and 2 are
not "build this from scratch" tasks — they are "upgrade to iroh 1.0 (if not
already), then measure and integration-test what iroh already does."** That
turns two of the hardest, highest-risk items in this doc into calibration
work instead of protocol-design work. See the per-item notes in Layer 1 below.

This matters for sequencing, because it means the *actually* hard, novel work
that only this project can do is concentrated in Layer 2 (coordination/ACL)
and Layer 3/4 (platform breadth, edge cases) — and those two categories have
very different profiles for a solo-maintainer-plus-community project:

- Layer 2 (discovery, trust, ACL) is **design-sensitive** — get the model
  wrong and every client has to migrate later. Worth doing carefully,
  yourself, before a wide release.
- Layer 3/4 (macOS/Windows TUN backends, mobile clients, MTU/firewall edge
  cases) is **parallelizable and contribution-friendly** — self-contained,
  testable independently, and exactly the kind of "I need this on my OS" work
  that GitHub issues/PRs are good at surfacing and fixing. These are good
  candidates to explicitly leave as `good first issue` / `help wanted` once
  public, rather than something to pre-build solo.

### Recommended phase order

| Phase | Scope | Why here | Effort |
|---|---|---|---|
| **0 — Verify, don't rebuild** | Upgrade to iroh 1.0/noq if not already on it; run the NAT-matrix test plan from gap #1 against the *existing* stack before writing any new traversal code; do the real-hardware relay benchmark from gap #3 | Cheapest possible win — may close gaps #1 and #3 with zero new code, just measurement + a version bump | days |
| **1 — Confirm migration, add relay redundancy** | End-to-end WiFi↔4G migration test against iroh's MagicSocket (gap #2); configure/measure multiple relay endpoints for redundancy (gap #1's remaining item) | Builds on Phase 0's findings; still mostly integration testing, not new protocol code | 1–2 weeks |
| **2 — Lightweight discovery (no server)** | Replace manual `--to EndpointId` with `iroh-gossip`-based announce/lookup scoped to a shared network secret (passphrase → topic id). No coordination server, no hosting burden — stays true to the "throw it on GitHub, GPL-3" model | This is the item that most limits usability today (gap #4) and is achievable without taking on server-operator responsibility | 2–4 weeks |
| **3 — Local ACL enforcement** | Policy file (TOML), evaluated locally per node: `{peer EndpointId or tag} → {allowed ports/CIDRs}`, default-deny, checked at `accept()` in both socks5 and TUN paths | Directly answers gap #6 without needing gap #5's full trust-model overhaul first — start with local policy, centralize later if a coordination server ever exists | 1–2 weeks |
| **4 — (Optional, community-driven) coordination server** | A minimal Headscale-style control plane: device roster, revocation, OIDC login, policy push | Highest engineering cost, most infrastructure-operator burden, and exactly the kind of well-scoped, independently testable subsystem that's realistic to hand to a contributor once the project has users asking for it | open-ended — treat as a stretch goal, not v1 |
| **5 — Platform breadth** | macOS/Windows TUN backends, mobile clients, packaging | Mark these as `help wanted` from day one — they need platform-specific testing this project's maintainer(s) may not have hardware/time for | community-paced |
| **6 — Edge-case hardening** | IPv6, MTU black-holes, TLS-intercepting proxies, high-latency paths | Inherently needs real, diverse user traffic to surface — cannot be meaningfully pre-built solo; triage as issues arrive | ongoing |

The net effect of this reordering versus the original "blocker order" is: two
of the six Layer-1/2 blockers (NAT traversal, migration) likely collapse into
one verification phase, which frees up real time to get the discovery + ACL
design (Phase 2/3) right *before* opening the repo up — because that's the
part a later contributor can't easily fix without a breaking protocol change,
whereas TUN backends and edge cases can be bolted on incrementally forever.

---

## Current state (v1)

| capability | status |
|---|---|
| Stream mode: TCP-over-QUIC port forwarding (`serve --forward` / `connect --listen`); ALPN `link-p2p/tcp-forward/1` + fixed-forward `LPF1` stream hello | done |
| SOCKS5 proxy mode (`serve --proxy` / `connect --socks5-listen`) | done |
| TUN mode: hub-coordinated VIP mesh (`link-p2p/tun/2` roster + spoke direct + hub fallback; `--allow`); Linux/macOS/Windows backends | done (macOS/Windows unverified on maintainer hardware) |
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

**Implementation path (updated after research):** iroh 1.0 (June 2026) ships
its own QUIC fork ("noq") implementing the `QUIC-NAT-TRAVERSAL` IETF draft
natively inside the QUIC handshake, not as a separate STUN/ICE layer —
n0 reports ~90% direct-connection rates in production across real NAT
combinations, with congestion-control-aware hole-punch loss detection built
in. **This means "evaluate whether we need application-layer STUN/ICE" is
very likely answered "no" — don't build one.** The remaining real work is:
(1) confirm the crate is pinned to iroh ≥1.0 and using `noq`, not an older
Quinn-based version; (2) run the NAT-matrix test plan above against what's
already there, since it's now a measurement task, not a design task; (3) the
multiple-relay-endpoints item is still genuinely open and should be built as
config (a list of relay URLs with basic health-check/failover), independent
of the traversal question.

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

**Implementation path (updated after research):** as of iroh 1.0, `MagicSocket`
continuously probes multiple candidate paths (direct IPv4/IPv6, relay) and
switches to the lowest-latency one with no connection interruption — this is
exactly "migration" and is handled inside iroh, below the application. So the
"design a migration path" item is largely **not our code to write**; what
*is* our code is making sure the layers above the iroh `Connection` don't
defeat it — specifically, the TUN datagram loop's current behaviour of
treating a transient path error as `PeerGone` and tearing down the whole
session (full re-handshake + new VIP exchange) needs to change to: distinguish
a genuine peer-close from a recoverable path event, and only tear down on the
former. That's a scoped fix in the TUN read/write loop, not a new subsystem —
re-classify the error path, then do the WiFi→4G end-to-end test to confirm
iroh's migration is actually reaching the TUN layer transparently.

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

**Implementation path:** given the project's constraints (single/small
maintainer, no appetite for running or maintaining hosted infrastructure),
prefer the serverless option first: `iroh-gossip` (n0's own pub/sub overlay,
already part of the iroh ecosystem, scales down to phone-class devices) gives
a discovery mechanism with zero hosting burden. Design:
1. A "network" is defined by a shared secret (a passphrase, or a generated
   token distributed out-of-band — same trust model as a Tailscale authkey,
   minus the server).
2. `BLAKE3(secret)` derives a gossip topic id. Devices that know the secret
   join the same topic and periodically announce `{EndpointId, device label,
   VIP}`.
3. Each node keeps a local cache of the roster it has seen (replaces manual
   `--to` copy/paste); staleness = last-seen timeout.
4. Revocation, in this model, means rotating the secret and re-announcing —
   coarse (all-or-nothing), but matches the no-server constraint. A real
   per-device revocation list requires Phase 4's coordination server; don't
   block this phase on it.

This is the item most worth getting right before a public release, since a
later switch to a different discovery mechanism is a breaking protocol
change for every existing user.

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

**Current:** Stream `serve` and TUN `tun serve` / `tun connect` support a
coarse EndpointId `--allow` / `LINK_P2P_ALLOW` allowlist (deny unknown peers at
accept / direct-dial time). There is still no per-peer, per-port, or
per-protocol filtering. In the stream modes, an allowed peer who can dial can
open a stream to the forwarded target. This is fine for a personal few-machine
link but insufficient for multi-user setups that need port/CIDR rules.

**Needed:**
- Allowlists: configure which EndpointIds may connect to which services.
  *(coarse EndpointId allowlist: done for stream serve + TUN)*
- For TUN mode: per-peer, per-port/IP-range rules ("Bob can only reach
  192.168.1.5:443 on Alice's LAN").
- Policy should be centrally defined (at the coordination server) and enforced
  locally by each node.

**Implementation path:** don't wait for a coordination server (gap #5/Phase 4)
to ship a first version of this — Tailscale's own model separates policy
*authorship* (their ACL/grants file) from policy *enforcement* (local, on
each node), and the enforcement half is independent and buildable now:
1. A local TOML policy file: rules of the form
   `{ src = "<EndpointId or tag>", dst_ports = [...], dst_cidr = "..." }`,
   default-deny.
2. Enforced at the two places connections currently get accepted
   unconditionally: `ForwardHandler::accept()`'s stream-open in `main.rs`,
   and the SOCKS5 `Target` resolution in `socks5.rs` before dialing out.
3. Once Phase 4's coordination server exists (if it ever does), it becomes a
   *distributor* of this same policy file format to all nodes — the local
   enforcement code doesn't need to change, only where the file comes from.
This gets real access control into the tool immediately instead of gating it
behind the much larger trust-model project in gap #5.

---

## Layer 3: Usability and platform breadth

| area | current | needed |
|---|---|---|
| TUN mode — macOS | utun backend (best-effort; report issues) | real-hardware CI / polish |
| TUN mode — Windows | Wintun backend (best-effort; report issues) | ship wintun.dll with releases; CI |
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

- **Stream-mode mesh** (multi-hop port forwarding): `serve`/`connect` stay
  point-to-point. TUN hub mesh (roster, spoke↔spoke direct, hub fallback) is
  done — see `docs/tun-design.md`.
- **Per-stream QoS / priority**: stream-mode reliability is currently uniform
  (ordered bidi); the datagram path is uniform "best-effort".
- **GSO / io_uring performance work**: the loopback benchmarks showed the
  bottleneck is QUIC protocol processing, not the kernel I/O path, so kernel
  batching won't lift the ceiling until the QUIC overhead is addressed.

---

## Release strategy notes

For a GPL-3.0, community-supported release (no dedicated hosted
infrastructure, no full-time maintainer team), the phase order above implies
a rough "what to finish before `git push --tags v0.x` and posting it" line:

- **Before release:** Phase 0–3 (verify NAT/migration on iroh 1.0, relay
  redundancy, gossip-based discovery, local ACL). These are the parts a
  breaking change is expensive to make later, once real users have adopted a
  given discovery/trust model.
- **Fine to release without, and better sourced from real users:** everything
  in Phase 5/6 (non-Linux TUN backends, mobile, IPv6, MTU/proxy edge cases).
  Label these clearly in the README/issue templates as known gaps and
  `help wanted` — that's an honest and genuinely useful way to use a
  community, versus discovering later that core protocol assumptions need to
  change.
- **Explicitly optional / stretch:** Phase 4 (hosted coordination server).
  It's the one piece of this roadmap that turns "run a CLI tool" into "run
  and secure a server," which is a meaningfully bigger ask of a solo/small
  maintainer — fine to scope it as a separate sub-project or leave to
  whoever in the community wants centralized/enterprise features badly
  enough to build and run it.
