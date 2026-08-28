# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Unified test entry `./scripts/test.sh` (`unit`/`smoke`/`socks5`/`all`) with
  shared `scripts/lib.sh` for readable PASS/FAIL output; removed one-off
  `fin-test.sh` / `raw-multi.py`.
- Split SSRF and bidirectional pipe helpers into `ssrf` / `pipe` modules;
  CLI serve/connect modes encoded as enums so illegal flag combos are not
  representable after validation.
- Clippy: `unsafe_code` forbidden; correctness/suspicious denied; pedantic
  noise allow-listed where intentional (wire casts, clap/i18n docs).

### Added

- **Unix-style UX** (`docs/unix.md`, **`cfg(unix)` builds only**):
  `connect --stdio`, `--to -` (EndpointId from stdin), `link-p2p man`.
  Cross-platform: `ping --format json`, stable exit codes (0–5), `-q`/`-v`/`-vv`,
  `LINK_P2P_*` env defaults (flags win), shell completions. Windows notes:
  `docs/windows.md`.
- **Transport tune** env/flags: `LINK_P2P_CC` / `--cc`,
  `LINK_P2P_SEND_WINDOW` / `--send-window`,
  `LINK_P2P_STREAM_RECV_WINDOW` / `--stream-recv-window` (see
  `docs/performance.md`).
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

### Changed

- SOCKS5 `write_target` batches the header into one `write_all` and omits
  `.flush()` so callers can keep an unbuffered iroh QUIC `SendStream`
  (BufWriter without flush would hang; documented in `docs/performance.md`).
- Reconnect wakeups are event-driven (`tokio::sync::watch`) instead of
  200ms polling: a local client arriving during a reconnect window is
  served the instant the new connection lands, not up to 200ms later.

### Fixed

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
