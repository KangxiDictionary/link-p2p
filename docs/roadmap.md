# Roadmap / known gaps

What link-p2p has today and what it deliberately does not. Baseline comparison:
mature mesh VPNs (Tailscale, ZeroTier). Ordered roughly by deployability impact.

**Context:** link-p2p builds on [iroh 1.0](https://github.com/n0-computer/iroh)
(noq QUIC, MagicSocket path probing, NAT traversal in the stack). Layer 1 items
below are largely **measure and integrate**, not greenfield protocol design.

---

## Current state

| capability | status |
|---|---|
| Stream mode: TCP-over-QUIC (`serve --forward` / `connect --listen`); ALPN `link-p2p/tcp-forward/1` + `LPF1` hello | done |
| SOCKS5 proxy (`serve --proxy` / `connect --socks5-listen`) | done |
| TUN: hub VIP mesh (`link-p2p/tun/2`, spoke direct + hub fallback; `--allow`); Linux/macOS/Windows | done (macOS/Windows best-effort) |
| TUN daemon (`tun up/down/status/peers`) | **done** (ad-hoc Unix; `--system` paths Step 0) |
| Persistent identity, self-hosted relay, multi-relay failover, `--relay-only` | done |
| `call` + contacts / short codes, `config.toml` | done |
| i18n, shell completions, benchmark/test scripts | done |
| Mesh-native relay (peer forwards for unreachable peers) | backlog |

Full TUN design: [subsystems/tun.md](subsystems/tun.md).

---

## Priorities

| phase | scope | effort |
|---|---|---|
| **0 — Verify** | NAT-matrix on iroh 1.0; real-hardware relay benchmark; confirm noq/MagicSocket behaviour | days |
| **1 — Migration + relay redundancy** | WiFi↔4G migration test; multiple relay URLs with failover | 1–2 weeks |
| **2 — Discovery (no server)** | `iroh-gossip` announce/lookup from shared network secret | 2–4 weeks |
| **3 — Local ACL** | TOML policy: peer → allowed ports/CIDRs, default-deny | 1–2 weeks |
| **4 — Coordination server (optional)** | Headscale-style roster, revocation, OIDC — stretch goal | open-ended |
| **5 — Platform breadth** | macOS/Windows TUN polish, mobile, packaging — community-driven | ongoing |
| **6 — Edge cases** | IPv6, MTU black-holes, TLS-intercepting proxies, satellite paths | ongoing |

Hard protocol choices (discovery model, ACL format) should settle before wide
release. Platform backends and edge cases can land incrementally via issues/PRs.

---

## Layer 1: Core connectivity

### 1. NAT traversal across NAT types

**Problem:** Without a reachable UDP path, traffic uses relay — lower throughput
and higher latency.

**Current:** iroh handles candidate exchange via `presets::N0`. Custom-only
`--relay` may reduce direct candidates on hostile NAT.

**Needed:**

- NAT-type classification and documented success rates (same-LAN, symmetric, CGNAT).
- Confirm iroh ≥1.0 / noq is sufficient — avoid duplicating STUN/ICE in-app.
- Multiple relay endpoints with health-check/failover (partially done via multi `--relay`).

### 2. Connection migration

**Problem:** IP change (e.g. WiFi → 4G) should not require full session teardown.

**Current:** iroh MagicSocket probes and switches paths. TUN datagram loop may
still treat transient errors as `PeerGone` and force full re-handshake.

**Needed:**

- Distinguish peer-close from recoverable path events in TUN read/write loop.
- End-to-end WiFi↔4G test; keep reconnect fallback when migration fails.

### 3. Relay throughput — measured

**Problem:** Real deployments spend time on relay; cost must be quantified.

**Current:** Loopback benches exist; structured real-network relay iperf3 through
TUN is still open.

**Needed:** Real-machine relay benchmarks (phase harness); see
[architecture/performance.md](architecture/performance.md).

---

## Layer 2: Multi-node coordination

### 4. Device discovery

**Problem:** Manual `--to EndpointId` copy/paste does not scale.

**Needed:** Serverless first — gossip topic from shared secret; announce
`{EndpointId, label, VIP}`; local roster cache with staleness timeout.

### 5. Key distribution and trust

**Problem:** Local `identity.key` only; no org roster or revocation.

**Needed (longer term):** coordination server binding devices to identity; labels;
revocation. Optional — see phase 4.

### 6. ACL / fine-grained access control

**Problem:** `--allow` is EndpointId-only; no per-port/CIDR rules.

**Current:** Coarse allowlist on stream serve and TUN.

**Needed:** Local TOML policy enforced at accept and SOCKS5 dial; later push from
coordination server without changing enforcement code.

---

## Layer 3: Usability and platform breadth

| area | current | needed |
|---|---|---|
| TUN daemon control plane | foreground `tun serve` / `tun connect` only | `tun up/down/status/peers` — see below |
| TUN macOS / Windows | backends shipped, best-effort | real-hardware CI, polish |
| Mobile | none | Android/iOS VPN APIs |
| GUI / TUI | CLI only | status dashboard / tray (same control socket) |
| MagicDNS | manual VIPs | local DNS → VIP |
| Mesh-native relay | hub TUN forward only | opt-in peer relay |
| Packages | GitHub releases | distros, auto-update |

### TUN daemon (TUN-only; stream/call/SOCKS5 unchanged)

**Why:** roster + TUN + privilege are long-lived mesh state, not a one-shot
session. Keep `tun serve` / `tun connect` as foreground debug; new commands talk
to a local daemon.

**Design SSOT:** [subsystems/tun.md](subsystems/tun.md) (Daemon control plane).

**Checklist:**

| # | Task | Notes |
|---|---|---|
| 1 | `src/tun_ctl.rs` — `LPC1` + version + length-prefixed JSON | **done** |
| 2 | Paths + flock + timed socket probe + session in pid file | **done** (`tun_daemon`) |
| 3 | Daemon spawn + TCP ready signal + skeleton worker | **done** (no TUN yet; multi-process tests) |
| 4 | Wire real TUN + roster into worker | **done** (`TunHooks` + live worker; skeleton tests stay unprivileged; live test `#[ignore]`) |
| 5 | CLI: `tun up/down/status/peers` + i18n help | **done** (`--foreground` aliases serve/connect; JSON status/peers; Windows background gated) |
| 6 | `tun down` wait-for-exit + kill fallback | **done** (soft warn on teardown timeout; `request_shutdown` keeps kill fallback for tests) |
| 7 | Document foreground ≡ `tun up --foreground` | **done** (help + platforms + tun.md) |

Do **not** daemonize the whole CLI. GUI/tray later attaches to the same socket.

### TUN system service (Layer 4 — in progress)

Ad-hoc `tun up` and supervisor-managed services use **different control paths**.
Mode is selected only via `--system` (CLI flag, not env).

| # | Task | Notes |
|---|---|---|
| 0 | `RuntimeMode` + path SSOT + `--system` CLI | **done** (pure path tests; system skips pid/log; session in Status) |
| 1 | Linux `tun service install/uninstall` | **done** (`link-p2p-tun.service`, binary path gate, identity bootstrap) |
| 2 | macOS LaunchDaemon + log rotation docs | **implemented** (plist + newsyslog note; `launchctl` path not verified on real macOS) |
| 3 | Windows SCM + named pipe ACL | **implemented** (LocalSystem, SDDL, Event Log, firewall rule on install, ProgramData identity; verify on real Windows) |
| — | `bring_endpoint_online` order | **fixed** (install custom `--relay` before `wait_online`; was hanging when n0 blocked) |

Service `ExecStart` must use `tun up --foreground --role … --system --identity …`
— never background fork. Binary must live in an admin-only path (install-time check).

---

## Layer 5: Edge-case hardening

| area | current | needed |
|---|---|---|
| UDP-blocked networks | assumed open | QUIC-over-TCP / DERP-style fallback |
| IPv6 | VIP v4 only | dual-stack VIP scheme |
| MTU black-holes | QUIC PMTUD + app refresh | extra app-layer PMTUD where needed |
| TLS-intercepting proxies | untested | pin/trust model |
| High-loss paths | untested | transport parameter tuning |

---

## Deliberately later

- **Stream-mode mesh** (multi-hop port forward): point-to-point only. TUN hub mesh is done.
- **Per-stream QoS**: uniform reliability in stream mode; uniform best-effort datagrams in TUN.
- **GSO / io_uring**: loopback shows QUIC processing dominates; kernel batching alone won't lift the ~650 MB/s aggregate ceiling — see [architecture/performance.md](architecture/performance.md).
