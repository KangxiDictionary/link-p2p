# link-p2p (MVP)

A minimal TCP-over-QUIC port forwarder on top of [iroh](https://github.com/n0-computer/iroh) 1.0.
This is step 1 of the roadmap discussed earlier — get one real P2P hop working
and measured before adding SOCKS5, QoS policy, LD_PRELOAD interception, GSO/io_uring, etc.

## What this does

- `serve` binds an iroh Endpoint, prints its `EndpointId`, and forwards every
  incoming QUIC stream either to a fixed local TCP address (`--forward`, e.g.
  your game server, SSH, whatever you're exposing) or, in `--proxy` mode, to
  whatever address the stream's header asks for.
- `connect` dials a remote `EndpointId` once, then opens a fresh QUIC stream
  per local TCP connection you make to it, on the *same* underlying
  connection (so NAT traversal / relay negotiation only happens once). It
  exposes either a plain forward (`--listen`) or a SOCKS5 server
  (`--socks5-listen`).

### SOCKS5 proxy (`serve --proxy` + `connect --socks5-listen`)

Instead of pinning a single destination, the `serve` side can act as a
generic proxy: each stream carries a tiny target header (reusing SOCKS5's own
address encoding), and `serve` dials wherever it points. Domain names are
resolved on the `serve` side, so you can reach hosts that only the remote
network can resolve — same as a real VPN:

```bash
# machine A: generic proxy endpoint
link-p2p serve --proxy

# machine B: local SOCKS5 server for browsers / curl / tun2socks
link-p2p connect --socks5-listen 127.0.0.1:1080 --to <EndpointId from A>

curl --socks5 127.0.0.1:1080 http://anything/            # IP target
curl --socks5-hostname 127.0.0.1:1080 http://internal-x/ # resolved on A
```

The SOCKS5 implementation is minimal by design: no-auth, CONNECT only. That
is fine bound to 127.0.0.1; don't expose `--socks5-listen` on a real
interface without adding username/password auth first.

The old single-port modes still exist unchanged (`serve --forward` + `connect
--listen`) — the proxy is an addition, not a replacement.

Both directions use iroh's default `presets::N0` config, which enables n0's
public relay + discovery infrastructure — so this will generally work even
across two machines behind NAT, without you manually exchanging IPs.

### Self-hosted relay (`--relay`)

Pass `--relay http://your-relay:3340` on both sides to use your own relay
instead of n0's, e.g. `iroh-relay --dev` for local testing. This skips
DNS/pkarr discovery entirely and dials the peer directly through that relay.

Direct connections still get attempted and usually succeed when NAT allows
it — the relay isn't a permanent detour, it's how the two sides bootstrap
and exchange candidate addresses before upgrading to a direct path. Run with
`RUST_LOG=iroh=trace` and look for `Established` / `path_remote=Ip` in the
logs to confirm whether a given session actually went direct or stayed on
the relay — that distinction matters when you're reading throughput numbers
off it (see benchmarking section below).

One real caveat: skipping pkarr/DNS also skips one source of direct-address
candidates, so on especially hostile NATs (symmetric NAT on both ends) a
custom relay may hole-punch less reliably than the default n0 path. Not a
concern for same-LAN or typical home-NAT testing.

### Logging

`RUST_LOG` controls both this tool's own logs and iroh's internal ones, e.g.:

```bash
RUST_LOG=iroh=debug ./target/release/link-p2p serve --forward 127.0.0.1:22
RUST_LOG=iroh=trace ./target/release/link-p2p connect --relay http://127.0.0.1:3340 --to <id> --listen 127.0.0.1:9090
```

Default (no `RUST_LOG` set) is `link_p2p=info,iroh=warn` — you'll see
connection open/close events but not iroh's internal relay/discovery
chatter. Colors are automatically disabled when stdout isn't a terminal
(piped to a file, etc).

### Shell completions

```bash
link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish
link-p2p completions bash > /etc/bash_completion.d/link-p2p   # or wherever your distro loads them from
link-p2p completions zsh  > "${fpath[1]}/_link-p2p"
```
Also supports `powershell` and `elvish`. Re-run after upgrading if flags change.

## What this deliberately does NOT do yet

- SOCKS5 is there but minimal: no username/password auth, no UDP
  ASSOCIATE, no bind. Only CONNECT over 127.0.0.1.
- No transparent interception (LD_PRELOAD / TUN) — clients must speak
  SOCKS5 or use the fixed-port modes.
- No per-stream QoS / datagram mode for "unreliable" traffic — every stream
  is a reliable QUIC stream (bidi, ordered).
- No GSO/io_uring tuning — this is the naive `tokio::io::copy` path. Note
  that UDP GSO (batch sends) is already handled automatically by iroh's UDP
  stack (noq-udp) when the kernel supports it (4.18+, via `UDP_SEGMENT`); on
  this machine it's active. That's different from the app-level GSO/io_uring
  work that a benchmark would tell you whether to pursue. Measure first, then
  decide if that's actually your bottleneck.
- No "full mesh" — this is one dialer, one listener, one forwarded target.
- **No tokio runtime/scheduling tuning** — `#[tokio::main]` uses the default
  multi-thread runtime (one OS thread per core), and it's one spawned task
  per stream. That's the right default for an I/O-bound forwarder and there's
  no profiling data yet suggesting otherwise. Tuning worker thread count,
  switching to a current-thread runtime, or anything like that is a change
  you make *in response to* a CPU/latency number from the benchmarks below —
  not something to guess at ahead of time.

## Build

Requires network access to crates.io (iroh, tokio, etc. pull in a fair number
of transitive deps — first build will take a few minutes). Building the
translation catalogs requires `msgfmt` (part of GNU gettext); if it's missing
the build still succeeds and everything falls back to English.

```bash
cargo build --release
```

If something doesn't compile: iroh 1.0 is young and its API has moved a lot
release to release. Run `cargo doc -p iroh --open` and check the `Endpoint`,
`SecretKey`, and `protocol::Router` docs for the exact current signatures —
the overall approach (persistent SecretKey, ALPN-routed Router, accept_bi/open_bi
per logical connection) should still hold even if a method name shifted.

## Internationalization & styling

Help text, runtime messages, and connection logs are localized via gettext
(`gettext-rs`, with catalogs under `locales/`). The binary follows the
environment locale:

```bash
LANG=zh_CN.utf8 link-p2p --help   # Chinese help
LANG=ja_JP.utf8 link-p2p --help   # Japanese help
LANG=es_ES.utf8 link-p2p --help   # Spanish help
LANG=C link-p2p --help            # English help (fallback)
```

Catalog selection follows the environment: `LANG`/`LC_ALL` pick the locale,
and GNU gettext's `LANGUAGE` variable (e.g. `LANGUAGE=ja_JP link-p2p`) can
select a language without the system locale being installed.

To add a language, copy `locales/zh_CN/LC_MESSAGES/link-p2p.po` to your
locale's directory, translate the `msgstr`s, and rebuild (build.rs compiles
`.po` → `.mo` via `msgfmt`). Set `LINK_P2P_LOCALEDIR` to point at a custom
catalog directory if you don't want the binary looking next to itself, in the
cwd, or in the cargo build output.

Output is styled (bold/color) when stdout is a terminal; `--color always|never`
forces it on/off for scripts and pipes (`auto` is the default and respects
`NO_COLOR`).

## Local smoke test

`scripts/local-test.sh` runs the full pipeline on localhost against a
self-hosted relay: relay → serve → connect → a python HTTP/echo target,
checking an HTTP get through the tunnel and a 100KB byte-identical echo
round-trip. It expects a release build and an `iroh-relay` server binary
(default `tools/iroh-relay`, build one with
`cargo install iroh-relay --features server` and copy it there, or pass the
path as an argument).

## Run

On machine A (the side being exposed, e.g. forwarding to a local SSH server):

```bash
./target/release/link-p2p serve --forward 127.0.0.1:22
```

This prints an `EndpointId` — copy it.

On machine B:

```bash
./target/release/link-p2p connect --to <EndpointId from machine A> --listen 127.0.0.1:2222
```

Now `ssh -p 2222 localhost` on machine B goes over the P2P QUIC link to
machine A's SSH server.

Both sides persist their identity to `identity.key` in the working directory
by default (`--identity` to change the path), so `EndpointId` stays stable
across restarts — don't commit that file, it's a private key. On Unix the
key file is created with mode `0600` (owner-only) and existing files are
tightened to `0600` on every start.

### Resource limits

`--max-conns <N>` caps how many connections are forwarded concurrently
(default 1024, `0` = unlimited). This matters on `serve` endpoints exposed
to the network: without a cap, a peer flooding streams could exhaust file
descriptors/CPU. When at capacity, extra streams/connections queue up
instead of being dropped.

## Benchmarking against WireGuard/Tailscale (the actual point of this MVP)

This is the part that matters more than the code: get real numbers before
building anything else.

1. **Throughput**: run `iperf3 -s` behind `serve --forward 127.0.0.1:5201`,
   then `iperf3 -c 127.0.0.1 -p <listen port>` through `connect`. Compare
   against the same two machines connected via Tailscale/WireGuard directly.
2. **Latency**: `ping` doesn't work through this (it's TCP-only, not IP-layer),
   so use something like `nc`-based round-trip timing, or a tiny echo
   client/server, and compare against `ping` over the Tailscale interface as
   a rough proxy for base latency.
3. **CPU**: `top`/`htop` on both ends during the iperf3 run — this is where
   you'll actually see whether the "no TUN, no context switch" theory holds
   up, or whether QUIC's own userspace crypto overhead eats the savings.
4. **NAT traversal**: test with both machines on the same LAN (should hole-punch
   direct) and with one behind CGNAT / symmetric NAT (will likely fall back
   to n0's relay) — note which one you're actually measuring, since relayed
   throughput is a different number than direct.

### Loopback baseline (architecture ceiling)

`scripts/bench.sh` measures the stream-forwarding path on a single machine
(`serve --forward` + `connect --listen`, no SOCKS5 layer) against raw
loopback TCP, with CPU sampling of both processes. Baseline on this machine
(kernel 7.1.6, iroh 1.0.3):

| measurement | result |
|---|---|
| raw loopback TCP (1 stream) | ~3.9 GB/s |
| tunnel, 1 stream | ~340-380 MB/s |
| tunnel, 4 streams (`-P 4`) | ~330 MB/s, but CPU climbs ~1.9 → ~2.9 cores |
| CPU at 4 streams | serve ~155%, connect ~135% |

Readings: throughput is roughly flat from 1 → 4 streams while CPU keeps
climbing, which points at a shared per-connection bottleneck (QUIC crypto /
flow control on one connection) rather than a parallelism problem. In other
words, on this stack the tunnel sustains ~2.6-3 Gbps per QUIC connection at
the cost of roughly 2-3 cores of user-space CPU — fine behind a 1 Gbps link,
the bottleneck on 10 Gbps+. This is exactly the number to re-measure after
any architecture change (TUN/datagram, io_uring) and on real hardware
across a real network.

Whatever you find, that's the real basis for deciding whether GSO/io_uring/
LD_PRELOAD work is worth doing next, rather than assuming it from an
architecture diagram.
