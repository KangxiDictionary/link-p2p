# link-p2p

TCP-over-QUIC port forwarder and optional whole-machine IP mesh, built on
[iroh](https://github.com/n0-computer/iroh) 1.0.

| Mode | What you get | Privilege |
|---|---|---|
| `call` (or `serve` / `connect`) | Forward one TCP port, or SOCKS5 proxy | none |
| `tun join` / `tun call` | Dual-stack VIP mesh (`172.24.0.0/16` + `fd24:ac18::/64`) | root / `CAP_NET_ADMIN`, or Admin + `wintun.dll` on Windows |

Works across NAT via iroh relays; upgrades to a direct path when hole-punch
succeeds. Prebuilt Linux binary: [GitHub Releases](https://github.com/KangxiDictionary/link-p2p/releases).

**Platform maturity:** Linux is the TUN maintainer baseline (real-hardware tested).
macOS and Windows TUN backends ship in-tree but are **best-effort without dedicated
CI** — run the [TUN release checklist](docs/subsystems/tun.md#release-acceptance-checklist)
on each target OS before relying on them in production. Stream / `call` / SOCKS5
use the same code path on all platforms.

---

## Install

**Prebuilt** (no Rust toolchain):

```bash
tar -xzf link-p2p-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 link-p2p-x86_64-unknown-linux-gnu/link-p2p /usr/local/bin/
sudo cp -r link-p2p-x86_64-unknown-linux-gnu/locales /usr/local/bin/
link-p2p --version
```

**From source:**

```bash
cargo build --release
# then put target/release/link-p2p and target/release/locales/ on PATH together
# or: cargo install --path . && cp -a target/release/locales ~/.cargo/bin/
```

Without `locales/` beside the binary (or `LINK_P2P_LOCALEDIR`), UI falls back to English.

---

## Quick start

**Port forward** (same command on both peers — EndpointId tie-break picks who
dials). Each side prints `SHORT_CODE=` / `ENDPOINT_ID=` at start:

```bash
# both machines (example: forward local SSH)
link-p2p call --to <peer SHORT_CODE or EndpointId> \
  --listen 127.0.0.1:2222 --forward 127.0.0.1:22
# save the peer once:
link-p2p contact add alice <their SHORT_CODE>
# forever after:
link-p2p call --to alice --listen 127.0.0.1:2222 --forward 127.0.0.1:22
```

**Whole-machine mesh** (TUN):

```bash
# 1:1 "phone"
sudo link-p2p tun call <contact-or-id>

# Join a hub "channel"
sudo link-p2p tun join <hub EndpointId>
ping 172.24.x.y
```

**SOCKS5 proxy:**

```bash
link-p2p serve --proxy
link-p2p connect --socks5-listen 127.0.0.1:1080 --to <EndpointId>
```

### Explicit roles (optional)

When you want fixed hub/spoke or serve/connect roles instead of symmetric
`call` / `tun join`:

```bash
link-p2p serve --forward 127.0.0.1:22
link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222

sudo link-p2p tun serve                          # = tun up --foreground --role hub
sudo link-p2p tun connect --to <hub EndpointId>  # = tun up --foreground --role spoke
```

Breaking note: stream ALPN is `link-p2p/tcp-forward/1` — **upgrade both sides
together**. TUN mesh ALPN is `link-p2p/tun/3`. Details and more recipes:
[usage guide](docs/user-guide/usage.md).

---

## Documentation

| Doc | Audience |
|---|---|
| [docs/README.md](docs/README.md) | Index |
| [docs/user-guide/usage.md](docs/user-guide/usage.md) | Stream / SOCKS5 / identity / security / systemd / logging |
| [docs/user-guide/platforms.md](docs/user-guide/platforms.md) | Linux / macOS / Windows differences |
| [docs/subsystems/tun.md](docs/subsystems/tun.md) | TUN design + release checklist |
| [docs/architecture/performance.md](docs/architecture/performance.md) | Throughput, relay limits, benches |
| [docs/testing.md](docs/testing.md) | Test scripts |
| [docs/roadmap.md](docs/roadmap.md) | Known gaps |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Commits, SemVer, releases, build |

Short performance picture: ~2.6–3 Gbps per QUIC connection on loopback at ~2–3
user-space cores; connection sharding does not lift that ceiling. Measure on
real paths before tuning — public relays rate-limit (~tens of KB/s).

---

## License

GPL-3.0. See [CONTRIBUTING.md](CONTRIBUTING.md) to build, test, or cut a release.
