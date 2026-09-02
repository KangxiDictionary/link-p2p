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

**Prebuilt Linux** (no Rust toolchain). Replace `0.4.1` with a newer tag from
[Releases](https://github.com/KangxiDictionary/link-p2p/releases) if needed:

```bash
VER=0.4.1
curl -fsSL -O "https://github.com/KangxiDictionary/link-p2p/releases/download/v${VER}/link-p2p-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSL -O "https://github.com/KangxiDictionary/link-p2p/releases/download/v${VER}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf link-p2p-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 link-p2p-x86_64-unknown-linux-gnu/link-p2p /usr/local/bin/
# Catalogs must sit next to the binary (or set LINK_P2P_LOCALEDIR).
sudo cp -a link-p2p-x86_64-unknown-linux-gnu/locales /usr/local/bin/
link-p2p --version   # expect link-p2p 0.4.1 (or the VER you picked)
```

**From source:**

```bash
cargo build --release
sudo install -m 0755 target/release/link-p2p /usr/local/bin/
sudo cp -a target/release/locales /usr/local/bin/
# or for a user install:
# cargo install --path .
# cp -a target/release/locales ~/.cargo/bin/
```

Without `locales/` beside the binary (or `LINK_P2P_LOCALEDIR`), UI falls back to English.

**Shell completions** (includes `tun` / controller subcommands; dynamic mode
also completes contact nicknames for `--to` / `tun call` / `contact remove`):

```bash
# Recommended — re-source on each shell start (bash / zsh / fish)
echo 'source <(COMPLETE=bash link-p2p)' >> ~/.bashrc
echo 'source <(COMPLETE=zsh link-p2p)'  >> ~/.zshrc
echo 'COMPLETE=fish link-p2p | source'  >> ~/.config/fish/completions/link-p2p.fish
```

```powershell
# PowerShell ($PROFILE); needs ExecutionPolicy RemoteSigned at minimum
Add-Content $PROFILE '$env:COMPLETE = "powershell"; link-p2p | Out-String | Invoke-Expression; Remove-Item Env:\COMPLETE'
```

Static AOT scripts (packaging): `link-p2p completions bash|fish|zsh|powershell|elvish`.

**System TUN service** (after the binary + locales are on a trusted path):

```bash
sudo link-p2p tun service install --role hub   # or --role spoke --to <hub>
link-p2p tun status --system
```

Details: [platforms](docs/user-guide/platforms.md), [TUN / systemd](docs/subsystems/tun.md),
[Windows SCM](docs/user-guide/windows-service-setup.md),
[usage / completions](docs/user-guide/usage.md#completions-and-man).

---

## Quick start

**Phone-mode port forward** (standing callee + dial — same verbs as TUN phone,
without a TUN device). Each side prints `SHORT_CODE=` / `ENDPOINT_ID=` at start:

```bash
# machine A — leave the callee up
link-p2p call up --listen 127.0.0.1:2222 --forward 127.0.0.1:22

# machine B — dial A (auto-spawns a standing daemon on B if needed)
link-p2p call <peer SHORT_CODE or EndpointId> \
  --listen 127.0.0.1:2222 --forward 127.0.0.1:22

# save the peer once (known contacts auto-accept next time):
link-p2p contact add alice <their SHORT_CODE>
# forever after:
link-p2p call alice --listen 127.0.0.1:2222 --forward 127.0.0.1:22
# strangers ring until: call accept <peer> / call reject <peer>
```

**Whole-machine mesh** (TUN — same phone verbs, VIP mesh):

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

When you want fixed hub/spoke or serve/connect roles instead of phone-mode
`call` / `tun call` / `tun join`:

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
