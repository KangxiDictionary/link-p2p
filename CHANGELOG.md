# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
