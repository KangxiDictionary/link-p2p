# link-p2p (MVP)

A minimal TCP-over-QUIC port forwarder on top of [iroh](https://github.com/n0-computer/iroh) 1.0,
with a TUN mode for whole-machine IP mesh reachability (hub coordination +
optional spoke↔spoke direct paths).
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
- **Stream ALPN (breaking)**: `serve`/`connect` negotiate
  `link-p2p/tcp-forward/1`. Fixed-forward streams (`--forward` /
  `--listen` / `--stdio`) exchange a 4-byte `LPF1` hello so QUIC stream open
  is visible on the wire. **Upgrade both sides together** — mixed `/0` and
  `/1` fail at handshake. Proxy/SOCKS5 and TUN use separate ALPNs and are
  unaffected.
- `tun` (privileged: root / CAP_NET_ADMIN, or Administrator + `wintun.dll`
  on Windows) joins machines into a `172.24.0.0/16` virtual IP mesh over
  unreliable QUIC datagrams — one coordination hub (`tun serve`), many spokes
  (`tun connect`). Spokes learn the roster, try direct links, and fall back to
  hub forward. Linux, macOS, and Windows. See below.

### Whole-machine TUN mode (`tun serve` / `tun connect`)

The stream modes forward one TCP port. `tun` bridges whole machines at the IP
layer: each side gets a TUN interface and a virtual IP in `172.24.0.0/16`.
`tun serve` is the **hub** (roster broadcast + fallback forward); `tun connect`
dials it, installs a `/16` route, and attempts direct spoke↔spoke QUIC links
when the roster lists other peers. Packets prefer a direct path; otherwise the
hub demuxes by destination VIP. Inner traffic rides *unreliable* QUIC
datagrams (inner TCP/UDP keep their own reliability).

```bash
# hub (needs root / CAP_NET_ADMIN)
sudo link-p2p tun serve
# -> prints your virtual IP and EndpointId, e.g. 172.24.0.21

# spoke B (optional: --cc bbr3 on lossy links)
sudo link-p2p --cc bbr3 tun connect --to <EndpointId from hub>

# spoke C (same hub — both stay connected; B↔C prefer direct)
sudo link-p2p tun connect --to <EndpointId from hub>

# optional allowlist (hub and/or spokes)
# sudo link-p2p tun serve --allow <id> --allow <id2>

# on any machine:
ping 172.24.x.y        # hub or another spoke's virtual IP
ssh user@172.24.x.y    # any service, any port
```

Each side's virtual IP defaults to a deterministic BLAKE3 derivation from
its EndpointId (`172.24.0.0/16`, **IPv4 only** — there is no IPv6 VIP in this
mode), and peers exchange the address
each one actually bound during the handshake — so routes always point at
the peer's real VIP, including `--tun-ip` overrides. The range deliberately
avoids RFC 6598's `100.64.0.0/10`: Tailscale's netfilter rules drop any
packet with a 100.64/10 source that doesn't arrive on `tailscale0`, which
blackholes a tunnel in that range in both directions (measured on real
hardware). A startup check refuses to run if the address collides with a
local interface — that check, not the range choice, is the universal
fallback against third-party address conflicts. `--tun-ip` overrides the
derivation, and `--mtu` (default 1280, values above 1280 refused) bounds the
interface MTU — the final MTU is `min(--mtu, the negotiated QUIC datagram
max)`, and a connection that didn't negotiate datagrams is refused outright
rather than silently falling back to streams.

**TUN mode is a privileged mode**: creating the interface and installing the
route needs `root` / `CAP_NET_ADMIN` (Linux, macOS) or an elevated process plus
`wintun.dll` next to the binary (Windows). Stream modes remain unprivileged;
the two coexist and don't replace each other. Desktop backends are Linux
(`/dev/net/tun` + `ip`), macOS (`utun`), and Windows (Wintun). macOS/Windows
are best-effort until reported on real hardware — open an issue if something
breaks. Before releases that touch TUN, run `docs/tun-acceptance.md`. On Linux,
`sudo setcap cap_net_admin+ep $(which link-p2p)` covers the
network bits without a full root shell. Full design rationale and the
acceptance checklist live in `docs/tun-design.md`.

Two operational behaviors worth knowing:

- **`tun connect` reconnects automatically.** When the session ends (peer
  went away, network blip, or the serve side restarted), it re-dials with the
  same exponential backoff the stream mode uses (1s → 30s cap) instead of
  exiting — the TUN interface and the mesh `/16` route survive across sessions, so
  once the hub is back the tunnel resumes without restarting the process.
  Ctrl+C during a backoff wait exits cleanly.
- **`ping` works against TUN nodes too.** `tun serve` answers `link-p2p ping`
  probes alongside its tunnel duty (and while other peers are connected), so
  you can measure RTT/path to a TUN node without needing a separate `serve`.
- **`--max-conns` does not apply to TUN mode** — the hub accepts peers until
  you stop it; the flag only caps stream-mode fan-out (with a notice on
  startup if you set it).

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
off it (see `docs/benchmarks.md`).

One real caveat: skipping pkarr/DNS also skips one source of direct-address
candidates, so on especially hostile NATs (symmetric NAT on both ends) a
custom relay may hole-punch less reliably than the default n0 path. Not a
concern for same-LAN or typical home-NAT testing.

**Why self-host?** n0's public relay is a free shared service; on a flaky
link the relay WebSocket is the first thing to drop, and iroh logs it as
`Lost connection to relay server: Ping timeout` / `peer closed connection
without sending TLS close_notify`. Those `WARN` lines are iroh's internals,
not a bug in this tool, and they stop only when the relay link itself is
stable. Pointing both ends at your own relay (a box with a steady uplink)
is the real fix — see `contrib/systemd/iroh-relay.service` for a one-liner
way to run one as a service. `--relay http://<that-box>:3340` then replaces
n0 entirely.

### Logging

`RUST_LOG` controls both this tool's own logs and iroh's internal ones, e.g.:

```bash
RUST_LOG=iroh=debug ./target/release/link-p2p serve --forward 127.0.0.1:22
RUST_LOG=iroh=trace ./target/release/link-p2p connect --relay http://127.0.0.1:3340 --to <id> --listen 127.0.0.1:9090
```

Default (no `RUST_LOG` set) is `link_p2p=info,iroh=warn` — you'll see
connection open/close events but not iroh's internal relay/discovery
chatter.

Logs (both `text` and `json` formats) go to **stderr**; stdout carries only
the user-facing status lines (banner, "connected.", ping results). Colors are
automatically disabled when stderr isn't a terminal (piped to a file, etc).

`--log-format json` switches the tracing output to structured JSON, one
object per line. Redirect stderr to get a clean, `jq`-parseable stream:

```bash
./target/release/link-p2p serve --forward 127.0.0.1:22 --log-format json 2>serve.jsonl
jq -r 'select(.message == "connection opened") | .peer' serve.jsonl
```

`RUST_LOG=link_p2p=debug` additionally surfaces structured spans/events: a
`pipe` span with `sent_bytes`/`recv_bytes` per forwarded stream, and a
`dial completed` event with `elapsed_ms` for the QUIC handshake.

### Transport defaults

All endpoints share one QUIC transport config (see `transport_config` in
`src/main.rs`): a keepalive every 5s and a 30s idle timeout. The keepalive
keeps NAT UDP mappings alive on idle tunnels (they typically expire after
20-30s, silently dropping the connection); 5s also happens to be iroh's own
default, stated here so the contract is explicit. The 30s idle window is
relaxed from iroh's 15s default so brief path switches (connection
migration) don't kill an otherwise-healthy connection.

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
- No LD_PRELOAD-style transparent interception — clients must speak SOCKS5,
  use the fixed-port modes, or use TUN mode.
- TUN mode (Linux / macOS / Windows): hub coordinates a VIP roster; spokes try
  direct links and fall back to hub forward. Fine-grained ACLs (per-port/CIDR)
  and lazy dial-on-demand are still out of scope. Datagram behavior over a
  *relay* path is unmeasured so far (the sandbox can't force a relay-only
  path); the design doc treats direct-path behavior as assumed and relay-path
  as a real-hardware follow-up.
- No per-stream QoS / datagram mode for "unreliable" traffic in the stream
  modes — every stream is a reliable QUIC stream (bidi, ordered). TUN mode
  does use unreliable datagrams, but that's a separate path.
- No GSO/io_uring tuning — this is the naive `tokio::io::copy` path. Note
  that UDP GSO (batch sends) is already handled automatically by iroh's UDP
  stack (noq-udp) when the kernel supports it (4.18+, via `UDP_SEGMENT`); on
  this machine it's active. That's different from the app-level GSO/io_uring
  work that a benchmark would tell you whether to pursue. Measure first, then
  decide if that's actually your bottleneck.
- Stream modes remain one dialer / one listener (no multi-hop stream mesh).
- **No tokio runtime/scheduling tuning** — `#[tokio::main]` uses the default
  multi-thread runtime (one OS thread per core), and it's one spawned task
  per stream. That's the right default for an I/O-bound forwarder and there's
  no profiling data yet suggesting otherwise. Tuning worker thread count,
  switching to a current-thread runtime, or anything like that is a change
  you make *in response to* a CPU/latency number from `docs/benchmarks.md` —
  not something to guess at ahead of time.

## Unix-style CLI, Windows notes, and transport tuning

Windows stream notes and TUN/Wintun setup (signed `wintun.dll`, translations):
[`docs/windows.md`](docs/windows.md). Preferred Linux→Windows build:

```bash
cargo build --release --target x86_64-pc-windows-gnu
# then copy link-p2p.exe + locales/ (+ official wintun.dll for TUN)
```

Unix-only shell plumbing (`connect --stdio`, `--to -`, `link-p2p man`) is behind
`cfg(unix)`; see [`docs/unix.md`](docs/unix.md). Cross-platform: `ping --format json`,
exit codes, `-q`/`-v`, `LINK_P2P_*` env defaults, shell completions.

Before treating loopback benches as a QUIC “protocol wall”, run the one-session
config matrix in [`scripts/bench-transport-matrix.sh`](scripts/bench-transport-matrix.sh)
and read [`docs/performance.md`](docs/performance.md) (GSO defaults, CUBIC vs BBR3,
windows, sysctl caveats).

## Install

**Prebuilt binary (no Rust toolchain needed)** — download
`link-p2p-x86_64-unknown-linux-gnu.tar.gz` from the GitHub Releases page
(any `v*` tag builds it automatically via GitHub Actions), then:

```bash
tar -xzf link-p2p-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 link-p2p-x86_64-unknown-linux-gnu/link-p2p /usr/local/bin/
# keep the catalogs next to the binary so every language works:
sudo cp -r link-p2p-x86_64-unknown-linux-gnu/locales /usr/local/bin/
```

Verify with `link-p2p --version`. For running tunnels as services,
`contrib/systemd/link-p2p@.service` (see "Running as a service" below).

**From source**: `cargo build --release` (see Build), then either copy
`target/release/link-p2p` **and** `target/release/locales/` next to each
other onto your PATH (same layout as the prebuilt tarball), or:

```bash
cargo install --path .
# cargo only installs the binary — copy catalogs next to it for i18n:
cp -a target/release/locales ~/.cargo/bin/
# or: export LINK_P2P_LOCALEDIR=/path/to/locales
```

Without `locales/` beside the binary (or `LINK_P2P_LOCALEDIR`), the UI
falls back to English after the build tree is gone.

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

Help text, runtime messages, and connection logs are localized (catalogs
under `locales/`, compiled to `.mo` by build.rs and read at runtime). This
applies everywhere text reaches a user — `--help`, every subcommand help,
status lines, logs, and **shell completions** (each entry's description
follows the same language).

The language is read from the environment directly (no dependency on which
locales the OS has installed):

```bash
LANG=zh_CN.utf8 link-p2p --help              # Chinese
LANG=ja_JP.UTF-8 link-p2p completions fish    # Japanese — works even if the
                                               # system only has zh_CN installed
LANGUAGE=es_ES link-p2p --help                # Spanish — LANGUAGE overrides
                                               # any locale setting
LANG=C link-p2p --help                        # English (fallback)
```

Priority is `LANGUAGE` > `LC_ALL` > `LC_MESSAGES` > `LANG` (GNU gettext
semantics; `LANGUAGE` may be a colon-separated list). `C`/`POSIX` or an
unsupported language falls back to English.

To add a language, copy `locales/zh_CN/LC_MESSAGES/link-p2p.po` to your
locale's directory, translate the `msgstr`s, and rebuild (build.rs compiles
`.po` → `.mo` via `msgfmt`). Set `LINK_P2P_LOCALEDIR` to point at a custom
catalog directory if you don't want the binary looking next to itself, in the
cwd, or in the cargo build output.

Output is styled (bold/color) when stdout is a terminal; `--color always|never`
forces it on/off for scripts and pipes (`auto` is the default and respects
`NO_COLOR`).

## Testing

```bash
./scripts/test.sh          # unit + smoke + socks5 (default)
./scripts/test.sh unit     # cargo test only
./scripts/test.sh smoke    # localhost stream pipeline vs self-hosted relay
./scripts/test.sh socks5   # SOCKS5 proxy smoke
```

- `sudo scripts/tun-loopback-test.sh` — TUN startup, MTU negotiation and
  route lifecycle on one machine (does **not** exercise the datagram data
  path; that needs two machines).
- `cargo test -- --ignored` — e2e tests against a local relay (byte-identical
  round trip, SIGINT drain, listener port release).
- `scripts/phase*-{server,client}.sh` — optional two-machine real-network
  harness (NAT / relay / migration); see `docs/testing.md`.

Prerequisites and full instructions: `docs/testing.md`.

Commit, versioning and release conventions for contributors:
`docs/development.md`.

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

Both sides persist their identity to the XDG config dir by default —
`$XDG_CONFIG_HOME/link-p2p/identity.key` (usually
`~/.config/link-p2p/identity.key`); `--identity` overrides the path. A legacy
`identity.key` in the working directory is migrated to the XDG location on
first run, so existing `EndpointId`s stay stable. `EndpointId` stays stable
across restarts because the key is persisted — don't commit that file, it's
a private key. On Unix the key file is created with mode `0600` (owner-only)
and existing files are tightened to `0600` on every start. **Never run two
processes with the same `--identity` file** (iroh treats that as one peer;
relay/discovery will bounce connections between them). Give each role its
own file, e.g. `--identity ~/.config/link-p2p/serve-22.key`.

**Optional passphrase encryption** (`--identity-passphrase`, or the
`LINK_P2P_PASSPHRASE` environment variable — prefer the env var, the flag
value shows up in `ps` and shell history): the key file is then stored
encrypted (Argon2id + XChaCha20-Poly1305) instead of plaintext hex, so a
disk or backup leak no longer exposes the key material. Purely opt-in —
without it, behaviour is exactly as above. A legacy plaintext file loaded
with a passphrase is transparently re-encrypted on disk; loading an
encrypted file without the passphrase fails with a clear error.
Example:

```bash
# create/load an encrypted identity
LINK_P2P_PASSPHRASE='long random phrase' link-p2p serve --forward 127.0.0.1:22
```

### Operational flags and behaviors

- `--ephemeral` / `-e`: generate an in-memory identity that is never written
to disk. The `EndpointId` differs on every start; useful for throwaway
nodes and tests. Conflicts with `--identity`.
- `--to-addr <ip:port>` (repeatable): pin one or more direct addresses for
the peer instead of relying on discovery. `connect`, `tun connect` and
`ping` dial them directly — no DNS/pkarr lookup — which is both faster to
(re)connect and private: nothing about the peer has to be resolvable
publicly. Works alongside `--relay` (the relay then stays as the fallback
path). Exchange addresses out-of-band (a chat message, a paste), e.g.
`connect --to <id> --to-addr 203.0.113.9:43303 --listen 127.0.0.1:2222`.
- `--keepalive <secs>` / `--idle-timeout <secs>`: transport tuning.
  Defaults 5s / 30s. The keepalive keeps NAT UDP mappings alive (they
  typically expire after 20-30s idle); the idle timeout is how long a
  silent peer may be before it's declared dead and re-dialed. Raise the
  idle timeout on lossy/high-latency links so a brief outage doesn't tear
  the tunnel down.
- **Reconnect**: `connect` re-dials automatically when the underlying QUIC
connection dies, with exponential backoff (1s → 30s cap). The local listener
stays up throughout — clients arriving during a reconnect queue and succeed
once the peer is back. `tun connect` reconnects the same way (the whole
session re-establishes: dial, VIP exchange, route). Run with
`RUST_LOG=link_p2p=debug` to watch `reconnect failed; retrying in ...` /
`reconnected to peer` (stream mode) or `reconnecting in ...` (TUN mode).
- **Link-quality observability**: at `RUST_LOG=link_p2p=debug`, every 30s a
  `path stats` line logs iroh's selected path kind (`direct` / `relay` /
  `relay+direct-candidate` from `Connection::paths`) plus Quinn loss
  counters. **Do not** treat Quinn `udp_tx/rx` as proof of hole-punch —
  magicsock feeds relay traffic to Quinn as UDP too.
- `ping`: `link-p2p ping <EndpointId>` measures RTT to a running `serve`
  (the serve side answers ping probes alongside its normal forwarding) or
  `tun serve` node, and reports the selected path from iroh (waits up to
  ~2s for a relay→direct upgrade after handshake):

```bash
$ link-p2p ping <EndpointId>
pinging 5f7d5db174a7...
pong from 5f7d5db174a7: RTT 1912µs
  path: direct (IP)
```

JSON `path` values: `direct`, `relay`, `relay+direct-candidate`, `unknown`.
On lossy relay paths, try `--cc bbr3` before changing topology.
### Resource limits

`--max-conns <N>` caps how many connections are forwarded concurrently
(default 1024, `0` = unlimited). This matters on `serve` endpoints exposed
to the network: without a cap, a peer flooding streams could exhaust file
descriptors/CPU. When at capacity, extra streams/connections queue up
instead of being dropped.

TUN mode is a hub with many QUIC peer sessions and is not affected by
`--max-conns` (the flag only caps stream-mode fan-out).

### Security

- **Peer whitelist**: `serve --allow <EndpointId>` (repeatable) restricts
  who may connect. iroh authenticates every peer during the QUIC handshake,
  so the check is real — a peer not on the list gets its connection closed
  immediately. Without it, anyone who knows your `EndpointId` can connect
  and (in `--proxy` mode) make your machine dial arbitrary destinations.
  Recommended whenever the node is reachable from an untrusted network.
- **Proxy SSRF guard**: `serve --proxy` rejects targets in private,
  loopback and link-local ranges by default — a malicious peer could
  otherwise use your node as a proxy into your LAN or cloud metadata
  endpoints (`169.254.169.254`). The check runs on the *resolved* address,
  so domains can't smuggle a private IP past it. `--allow-private` lifts
  the guard for trusted peers.

### Running as a service (systemd)

`contrib/systemd/link-p2p@.service` is a template unit: one instance per
tunnel, the instance name selects the config. Create
`/etc/link-p2p/<name>.conf` with the arguments on one line, e.g.:

```
serve --forward 127.0.0.1:22 --relay http://relay.example.com:3340
```

```
sudo systemctl enable --now link-p2p@<name>
```

The unit restarts on failure (5s backoff), keeps state in a private
`/var/lib/link-p2p` (the identity key lands in
`/var/lib/link-p2p/.config/link-p2p/identity.key`), and grants
`CAP_NET_ADMIN` for TUN mode (harmless for the stream modes). Pin the
identity per instance with `--identity /etc/link-p2p/<name>.key` in the
config line.

This complements — does not replace — the in-process reconnect: systemd
restarts a crashed process; the binary itself re-dials a lost QUIC
connection with exponential backoff without restarting.

To also self-host the relay (so the `--relay` URLs above point at a machine
*you* control instead of n0's public relay), use the sibling unit
`contrib/systemd/iroh-relay.service` — `cargo install iroh-relay --features
server`, copy the unit in, `systemctl enable --now iroh-relay`, then put
`--relay http://<relay-host>:3340` in your `link-p2p@<name>.conf` lines.

## Performance

Loopback baseline and multi-connection scaling numbers (throughput, CPU, and
the "is the ~650 MB/s wall crypto?" analysis) live in `docs/benchmarks.md`.
Short version: ~2.6-3 Gbps per QUIC connection at the cost of ~2-3
user-space cores, and connection sharding does **not** lift that ceiling.
Re-measure after any data-plane change and on real hardware.
