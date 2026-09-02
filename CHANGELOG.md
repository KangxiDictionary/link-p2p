# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Docs

- **Install**: README prebuilt steps include download URL + `sha256sum` for
  `v0.4.0`, copy `locales/` beside the binary, and point at `tun service install`.
  TUN service snippets and platforms guide no longer omit catalogs; `tun_service`
  warns when `locales/` is missing next to the service binary.

## [0.4.0] - 2026-09-02

### Added

- **TUN dual-stack VIPs**: each node gets IPv4 in `172.24.0.0/16` and IPv6 ULA
  in `fd24:ac18::/64` (`--tun-ip` / `--tun-ip6`; omit either to auto-pick on
  collision). **Breaking:** ALPN `link-p2p/tun/2` → `tun/3`, roster magic
  `LPR3` (52-byte entries with `vip` + `vip6`). Upgrade both sides together.
- **`tun call` / `tun join` / phone mode**: day-to-day TUN UX via the local
  daemon (`tun ring`, accept/reject); `tun serve` / `tun connect` remain
  foreground debug aliases of `tun up --foreground --role …`.
- **Windows TUN system service**: SCM + named-pipe control, Event Log, firewall
  rule on install (verify on real Windows). See
  `docs/user-guide/windows-service-setup.md`.
- **Library target** (`link_p2p`) so ctl frame decode can be fuzzed; opt-in
  `cargo +nightly fuzz run ctl_frame` (see `docs/testing.md`; lives in repo-root
  `fuzz/`, not under `src/`).
- **Relay RTT cache** (`~/.config/link-p2p/relay-rtt.json`): fresh samples
  (<24h) skip a blocking TCP probe on startup; background refresh keeps the
  file warm.
- **`SessionPhase` state machine** for daemon `Status` (Starting / Idle / Dialing
  / Ringing / Connected) with explicit illegal-transition logging.
- **Path-stats soft preference**: roster dial order and path-monitor nudge cadence
  informed by local `path-stats.jsonl` direct hit rates (does not pick individual
  QUIC paths — iroh owns that).

### Fixed

- **SSRF** (`serve --proxy`): also block RFC 3068 6to4 relay anycast
  `192.88.99.0/24`.
- **`--identity-passphrase`**: warn that the flag is visible in `ps` / shell
  history; prefer `LINK_P2P_PASSPHRASE`.
- **TUN hub `try_claim_peer`**: arc-swap `rcu` returns the pre-CAS snapshot —
  verify ownership with `load_full()` after update (first claim was always failing).
- **TUN hub reconnect race**: per-spoke session generation; stale teardown no
  longer removes a live peer's route or index entry.
- **TUN spoke `lookup_out`**: hub VIP traffic always uses the dedicated hub
  connection; roster-learned hub entry cannot shadow it with a dead direct link.
- **Linux TUN MTU**: floor interface MTU at **1280** so the kernel does not
  disable IPv6 when QUIC PMTUD reports a ceiling below 1280.

### Changed

- Identity passphrase is held in `zeroize::Zeroizing` from CLI/env through
  load (best-effort wipe on Drop). Derived keys were already zeroized.
- Proxy dial path uses a `CheckedTarget` newtype so SSRF check and connect
  cannot diverge via a second DNS resolve.
- TUN control privileged ops (`Shutdown` / `Accept` / `Reject`) require a
  `PrivilegedPeer` capability token (no bare `bool`).
- `tokio` dependency drops `features = ["full"]` for an explicit feature list
  (`rt-multi-thread`, `net`, `io-util`, `io-std`, `sync`, `time`, `signal`,
  `macros`).
- TUN datagram / control mpsc depths are named constants (`TUN_PKT_QUEUE` /
  `TUN_CTRL_QUEUE`) instead of scattered `256` / `32` literals.
- OS TUN device/route/MTU ops live behind `tun::platform::TunPlatform`
  (`linux` / `macos` / `windows`); `tun/mod.rs` keeps thin wrappers only.
- `tun_daemon` split into shared `mod.rs` plus `ctl_sock/` and
  `unix` / `windows` / `unsupported` platform modules.
- `contact` / `config` subcommands moved to `commands/` (alongside serve/
  connect/ping).
- TUN recv path reads into a reusable `BytesMut` (no per-packet
  `copy_from_slice`); peer sender and key spawn tasks get tracing spans.
- `TunCommand` dispatch moved to `commands/tun.rs` (pre-identity service/
  selftest stay in `main`).
- Unix: prefer `rustix` for kill/setsid/geteuid/chown/umask; `nix` retained
  only for `User::from_name` (passwd) on service install.
- **`win_pipe.rs`**: documented why hand-rolled named pipes stay (custom SDDL,
  impersonation, `TokenElevation`) instead of the `interprocess` crate.

### Docs

- README and platforms guide: TUN on macOS/Windows is **best-effort** (no
  dedicated CI); Linux is the maintainer baseline.
- Release acceptance checklist lives in `docs/subsystems/tun.md` (replaces stale
  references to removed `docs/tun-acceptance.md` / `docs/tun-design.md`).
- Daemon / dual-stack / Linux MTU≥1280 docs aligned with current code.

## [0.3.0] - 2026-08-31

### Fixed

- **`-q/--quiet` ignored by `serve` and `tun`**: banners and path-upgrade
  notices now go through `Ui` / real `ui.quiet` (was hardcoded `false`).
  Machine lines (`ENDPOINT_ID=`, `contact list` TSV, `contact code`) stay on
  stdout under `-q`.
- **`help <bad>` exit path**: localized + `exit::USAGE` (no bare `eprintln!` /
  hardcoded `2`).
- **Config parse failures no longer silent**: bad `config.toml` warns and
  falls back to defaults (`config::load_or_default`).
- **SSRF**: also block RFC 6598 CGNAT `100.64.0.0/10`.
- **`tun_roster` errors localized** (were the only module with bare English
  `bail!` strings).
- **`call` dialer hung after `open_bi`**: dial-side `call` no longer registers
  `alpns` / `Router` (same shape as `connect`). Waiter keeps serve-like accept;
  dialer `--forward` accepts streams on the outbound connection. Also
  `call --stdio` UI banners go to stderr so stdout stays data-only.
- **`open_bi` hang no longer silent**: stream open waits at most 5s, then logs
  connection stats/paths/`close_reason`, closes **only that connection**, and
  waits for redial. `call` dialer now runs a reconnect watcher (like
  `connect`) so redial actually happens; waiter accepts replace the slot on
  every new inbound connection. Reconnect aborts the previous path-monitor /
  forward-accept tasks so stats logs are not duplicated.

### Added

- **`config init` / `config path`**: write/show `~/.config/link-p2p/config.toml`
  (was save-only / hand-edit only).
- **Short-code check digit**: Crockford codes get a trailing check character
  (typo detection); legacy 52-char codes still parse.
- **Multi-relay TCP latency ordering** for all commands (was `call`-only).

### Changed

- **Breaking (stream ALPN `tcp-forward/0` → `/1`)**: fixed-forward streams
  (`serve --forward` with `connect --listen` / `--stdio`) now exchange a
  4-byte `LPF1` hello so the dialer's `open_bi()` is visible on the wire.
  QUIC has no stream-open control frame; without this, download-first /
  server-banner flows hung in `accept_bi` until the local client FIN'd.
  **Upgrade serve and connect together** — mixed versions fail ALPN
  negotiation instead of mis-framing. Proxy/SOCKS5 and TUN unchanged.
- **`--relay` merges with n0 by default** (keeps discovery); `--no-n0-relays`
  restores replace-only. `config.toml` / `call` use the same rule.

### Added

- **`call` / `contact` / `config.toml`**: phone-like symmetric dial, local
  contacts + short codes, persistent relay defaults.
- **Multi `--relay`**: repeatable URLs / comma-separated `LINK_P2P_RELAY`.
- **`--relay-only`** / `LINK_P2P_RELAY_ONLY`: disable IP transports
  (`clear_ip_transports` + relay-only addr filter) so traffic cannot
  hole-punch to direct. Set on both peers for a true relay baseline.
  Conflicts with `--to-addr`. `--relay` alone still allows direct upgrade.

- **TUN mode on macOS and Windows** (alongside Linux): `utun` / Wintun backends
  for device I/O, with platform-specific address/route/MTU setup. Windows needs
  Administrator + `wintun.dll` next to the binary (`docs/user-guide/platforms.md`). macOS and
  Windows are best-effort without dedicated CI — please open issues for host
  failures. Manual release checklist: `docs/subsystems/tun.md` (acceptance table).

- **TUN hub mesh**: `tun serve` accepts many concurrent peers, demuxes by
  destination VIP, and forwards spoke↔spoke so every `172.24.0.0/16` virtual IP
  can reach every other. Spokes install a `/16` route (not only the hub `/32`).
  See `docs/subsystems/tun.md`.
- **TUN hub I/O**: a dedicated TUN actor (channel in/out) so spoke→hub delivery
  is not starved by holding a mutex across `recv`.
- **TUN mesh v2 (`link-p2p/tun/2`)**: hub broadcasts VIP↔EndpointId roster on a
  reliable control stream; spokes try direct peer links and prefer them over
  hub forward. Per-destination send queues avoid head-of-line blocking on
  `send_datagram_wait`. `tun serve` / `tun connect --allow` (and
  `LINK_P2P_ALLOW`) gate who may join. Prefer global `--cc bbr3` on lossy
  paths.

### Fixed

- **`ping` RTT vs path timing**: measure and report **initial** RTT/path right
  after connect, then wait up to 2s for relay→direct, then measure **settled**
  again. JSON `rtt_us`/`path` are settled; `initial_*` diagnose the magicsock
  upgrade race (avoids “path: direct” with a still-relay 600ms+ RTT).
- **Path monitor**: while a session stays on relay, periodically
  `Endpoint::network_change` to retry hole-punch; warn once (user-facing) when
  active throughput stays in a relay-shaped ceiling (under ~128 KB/s). Announce
  when the path upgrades to direct. No IP candidate for several samples →
  relay-permanent (upgrade interval 5m) and a user warning.
- **Path classification**: `ping` / TUN session logs / path-stats no longer
  treat Quinn `udp_tx/rx > 0` as "direct". iroh magicsock feeds relay as UDP
  too; we now use `Connection::paths()` (`is_selected` / `is_ip` /
  `is_relay`).
- **Fixed-forward silent hang**: download-first TCP (and any case where the
  dialer sends no bytes until the server speaks) no longer leaves serve
  stuck in `accept_bi`. Invalid/missing hellos fail immediately with a
  logged error instead of hanging forever.
- **Reconnect backoff**: only reset after a session lived ≥ 5s. Handshake-
  then-instant-drop no longer clears backoff, so the watcher sleeps and
  doubles instead of tight-loop redialing (same for TUN connect).
- **Serve/connect wait-point logs**: `debug` around connection-permit acquire,
  `accept_bi`, and local TCP accept — so a healthy QUIC session with nobody
  dialing the connect listen port is distinguishable from a stuck handler.
- **Proxy SSRF**: IPv4-mapped IPv6 (`::ffff:…`), deprecated IPv4-compatible
  (`::a.b.c.d`), NAT64 well-known, 6to4, and Teredo no longer bypass the
  private/loopback blocklist in `serve --proxy`.
- **Exit codes**: `wait_online`, TUN bind/connect, and TUN VIP-exchange timeout
  use `exit::coded` so codes 3/4 stay correct under non-English locales.
  Windows TUN VIP collision check uses `Get-NetIPAddress` when it returns at
  least one address (empty success falls back to `netsh`), not raw `ipconfig`
  substring search. Windows interface MTU updates via `netsh` when possible;
  macOS/Windows peer routes prefer add-then-replace to avoid a delete gap.
- **Windows TUN**: load `wintun.dll` only from beside the exe (not PATH); clearer
  errors for missing/unsigned DLL; `Endpoint::close` on early TUN failures
  (stops the ungraceful-drop log). Peer VIP routes use
  `netsh interface ipv4 add route …` on-link via the Wintun adapter (not
  `route add` with the local VIP as gateway, which blackholed ICMP).
- **i18n on Windows**: fall back to the OS UI language via `sys-locale` when
  `LANG`/`LANGUAGE` are unset; document that `locales/` must ship next to the exe.

## [0.2.0] - 2026-08-29

### Added

- **Unix-style UX** (**`cfg(unix)` builds only**):
  `connect --stdio`, `--to -` (EndpointId from stdin), `link-p2p man`.
  Cross-platform: `ping --format json`, stable exit codes (0–5), `-q`/`-v`/`-vv`,
  `LINK_P2P_*` env defaults (flags win), shell completions. Windows notes:
  `docs/user-guide/platforms.md`.
- **Transport tune** env/flags: `LINK_P2P_CC` / `--cc`,
  `LINK_P2P_SEND_WINDOW` / `--send-window`,
  `LINK_P2P_STREAM_RECV_WINDOW` / `--stream-recv-window` (see
  `docs/architecture/performance.md`).
- `scripts/bench-transport-matrix.sh`: one-session loopback matrix
  (baseline | sysctl | bbr3 | bbr3+windows) for config exclusion before
  protocol-wall claims.
- `contrib/systemd/iroh-relay.service` template unit to run a self-hosted
  relay as a service. Pointing both ends at `--relay http://<your-relay>:3340`
  replaces n0's public relay — the source of the recurring
  `Lost connection to relay server: Ping timeout` / `TLS close_notify`
  warnings (iroh internals, not this tool's bug), which only stop when the
  relay link itself is stable.
- **Peer authorization** (`serve --allow <EndpointId>`, repeatable): only
  whitelisted peers may connect; iroh authenticates the peer's key during
  the handshake, and a non-whitelisted peer's connection is closed
  immediately. Also bounds concurrent QUIC *connections* (not just
  streams) via `--max-conns`.
- **Proxy SSRF guard** (`serve --proxy`): targets in private/loopback/
  link-local ranges are rejected by default (checked on the resolved
  address, so domains can't smuggle a private IP past it);
  `--allow-private` lifts the guard for trusted setups.
- `--to-addr <ip:port>` (repeatable) on `connect`, `tun connect` and
  `ping`: pin direct addresses for the peer, dialed straight through with
  no DNS/pkarr lookup — faster reconnects and no public discovery of the
  peer's address. Combines with `--relay` as a fallback.
- `--keepalive <secs>` / `--idle-timeout <secs>`: the QUIC transport
  params (defaults 5s / 30s) are now CLI-tunable for per-network tuning.
- Key material (identity hex/bytes) is zeroized in memory after loading
  (`zeroize`), on top of the existing 0600 file permissions.
- **Passphrase-encrypted identity files** (`--identity-passphrase` or
  `LINK_P2P_PASSPHRASE`): the key file is stored Argon2id + XChaCha20-
  Poly1305 encrypted instead of plaintext hex, so a disk/backup leak
  doesn't expose the key. Pure opt-in; a legacy plaintext file is
  transparently re-encrypted when loaded with a passphrase, and loading an
  encrypted file without one fails with a clear error.
- Periodic `path stats` debug logging (30s interval): cumulative UDP
  datagram counters + loss per connection, so a running tunnel's path
  quality is diagnosable without waiting for a failure.
- Unified test entry `./scripts/test.sh` (`unit`/`smoke`/`socks5`/`all`) with
  shared `scripts/lib.sh` for readable PASS/FAIL output.

### Changed

- `-h` vs `--help`: `-h` lists commands and the quick-start examples only
  (options use `hide_short_help`); `--help` shows full option text with
  **hard** newlines at sentence/clause boundaries (not terminal soft-wrap).
  clap `wrap_help` + `max_term_width(100)` remains a safety net for leftovers.
- Dependencies: iroh/noq 1.1/1.2, argon2 0.6, chacha20poly1305 0.11; identity
  KDF keeps PHC-B64 salt encoding so existing encrypted keys still open.
- Split SSRF and bidirectional pipe helpers into `ssrf` / `pipe` modules;
  CLI serve/connect modes encoded as enums so illegal flag combos are not
  representable after validation.
- Clippy: `unsafe_code` forbidden; correctness/suspicious denied; pedantic
  noise allow-listed where intentional (wire casts, clap/i18n docs).
- SOCKS5 `write_target` batches the header into one `write_all` and omits
  `.flush()` so callers can keep an unbuffered iroh QUIC `SendStream`
  (BufWriter without flush would hang; documented in `docs/architecture/performance.md`).
- Reconnect wakeups are event-driven (`tokio::sync::watch`) instead of
  200ms polling: a local client arriving during a reconnect window is
  served the instant the new connection lands, not up to 200ms later.
- Removed one-off `scripts/fin-test.sh` / `scripts/raw-multi.py`.

### Fixed

- Install path consistency: systemd unit now matches README
  (`/usr/local/bin/link-p2p`); `build.rs` mirrors `.mo` catalogs to
  `target/<profile>/locales` for packaging; README documents that
  `cargo install` does not install locales by itself.
- `ping` to a `tun serve` node now works: `run_tun_serve` only registered
  `TUN_ALPN` on its endpoint, and iroh rejects connections whose ALPN is not
  in `Builder::alpns` at TLS negotiation — so the ping dispatch was dead
  code. `PING_ALPN` is now registered alongside `TUN_ALPN`.
- TUN mode no longer spams a per-packet `warn!` for oversized datagrams
  after an MTU drop. Drops are counted and flushed as one summary line on
  the existing 2s refresh tick; each drop also injects an ICMP Type 3
  Code 4 (Fragmentation Needed) back into the TUN so local TCP PMTUD
  shrinks MSS immediately instead of waiting for black-hole timeouts.
  Raising the interface MTU is held off for 15s after a shrink so path
  ceiling flicker (e.g. Tailscale vs relay) cannot oscillate
  raise→drop→shrink.

## [0.1.0] - 2026-08-21

First release. A minimal TCP-over-QUIC forwarder on iroh 1.0 with a
point-to-point TUN mode for whole-machine IP reachability.

### Added

- **Stream modes**: `serve --forward` / `connect --listen` port forwarding
  over a single dialed QUIC connection (one stream per local TCP connection).
- **SOCKS5 proxy**: `serve --proxy` + `connect --socks5-listen` — the target
  comes from each stream's header (reusing SOCKS5's address encoding), with
  domain names resolved on the serve side. RFC 1928-strict method
  negotiation (no-auth only, 0xFF when not offered).
- **TUN mode**: `tun serve` / `tun connect` bridge two whole machines at the
  IP layer over unreliable QUIC datagrams (Linux, root/CAP_NET_ADMIN).
  Deterministic virtual IP derivation in `172.24.0.0/16` (BLAKE3), VIP
  exchange at handshake so `--tun-ip` overrides route correctly, MTU
  negotiation (default 1280) that tracks the path datagram ceiling in both
  directions, and automatic reconnect with exponential backoff.
- **`ping` subcommand**: RTT + direct/relay path report against any `serve`
  or `tun serve` node.
- **Identity**: persistent secret key at the XDG config path
  (`--identity` overrides, legacy `./identity.key` migrated), or
  `--ephemeral` for in-memory throwaway identities.
- **Reconnect**: `connect` and `tun connect` re-dial lost QUIC connections
  with exponential backoff (1s → 30s cap) without restarting.
- **Transport**: explicit 5s keepalive + 30s idle timeout on all endpoints;
  explicit QUIC RESET/STOP on aborted pipes so the peer learns immediately.
- **Self-hosted relay**: `--relay <url>` skips n0 discovery and dials
  directly through your own relay.
- **Observability**: `--log-format json` (logs on stderr, jq-parseable),
  structured spans with per-stream byte counts and dial timing,
  `RUST_LOG`-driven iroh internals.
- **Internationalization**: full localization of help, status lines, logs
  and shell completions (zh_CN / ja_JP / es_ES). Language is read from the
  environment (`LANGUAGE` > `LC_ALL` > `LC_MESSAGES` > `LANG`) with no
  dependency on installed OS locales; the `.mo` catalogs are parsed at
  runtime, so prebuilt binaries stay multilingual.
- **Packaging**: `contrib/systemd/link-p2p@.service` template unit;
  GitHub Actions release workflow building a prebuilt tarball (binary +
  catalogs) on `v*` tags.
- **Testing**: unit tests for the SOCKS5 wire protocol and i18n catalog
  handling, e2e tests (`cargo test -- --ignored`), two-machine phase test
  harness in `scripts/phase*-{server,client}.sh`.

### Fixed

- Tailscale netfilter rules blackholing the original `100.64.0.0/10` VIP
  range — moved to `172.24.0.0/16`.
- `tun` datagram "too large" storms after migrating to a path with a
  smaller PMTUD ceiling — the interface MTU now tracks the path ceiling
  downward on actual oversize packets, not just upward on a timer.
- `connect` printing a misleading "connected" banner before the local
  listener actually bound (port-in-use case).
- Untranslated clap built-ins (`help` subcommand, `-h/--help`,
  `-V/--version`) — replaced with localizable equivalents; a test now
  guards against any arg/subcommand shipping English help.
