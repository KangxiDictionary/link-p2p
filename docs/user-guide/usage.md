# Usage guide

How to run link-p2p day to day: stream forward, SOCKS5, identity, relays,
ops flags, security, systemd, logging, and i18n.

For TUN mesh design and acceptance checks, see [subsystems/tun.md](../subsystems/tun.md).
For OS-specific setup, see [platforms.md](platforms.md).

---

## Stream forward

**Fastest first use** — same command on both peers (EndpointId tie-break picks
who dials). Each side prints `SHORT_CODE=` / `ENDPOINT_ID=` at start — exchange
those once out-of-band:

```bash
# both machines (example: forward local SSH)
link-p2p call --to <peer SHORT_CODE or EndpointId> \
  --listen 127.0.0.1:2222 --forward 127.0.0.1:22
# when connected, the CLI reminds you to save them:
link-p2p contact add alice <their SHORT_CODE>
# forever after:
link-p2p call --to alice --listen 127.0.0.1:2222 --forward 127.0.0.1:22
```

Before the first dial, `link-p2p selftest` TCP-probes `--relay` URLs (TCP ok ≠
UDP/QUIC). After a few sessions, `link-p2p stats` shows how often you got a
direct path vs relay (`~/.config/link-p2p/path-stats.jsonl`).

### Explicit roles (`serve` + `connect`)

`connect --to` also accepts contact names / short codes (same book as `call`).

Expose one local TCP port over a P2P QUIC link:

```bash
# machine A — side being exposed
link-p2p serve --forward 127.0.0.1:22

# machine B
link-p2p connect --to <EndpointId from A> --listen 127.0.0.1:2222
ssh -p 2222 localhost
```

- `serve` prints an `EndpointId` (also `ENDPOINT_ID=<hex>`, never localized).
- `connect` dials once, then opens one QUIC stream per local TCP connection on
  the same underlying connection (NAT/relay negotiation happens once).
- Stream ALPN: `link-p2p/tcp-forward/1`. Fixed-forward streams exchange a 4-byte
  `LPF1` hello. **Upgrade both sides together** — mixed `/0` and `/1` fail at
  handshake. Proxy/SOCKS5 and TUN use separate ALPNs.

Both sides use iroh `presets::N0` by default (public relay + discovery), so
sessions usually work across NAT without exchanging IPs by hand.

---

## SOCKS5 proxy

`serve --proxy` dials whatever target each stream header asks for (SOCKS5
address encoding). Domains resolve on the **serve** side:

```bash
link-p2p serve --proxy
link-p2p connect --socks5-listen 127.0.0.1:1080 --to <EndpointId>

curl --socks5 127.0.0.1:1080 http://anything/
curl --socks5-hostname 127.0.0.1:1080 http://internal-x/
```

Minimal by design: no-auth, CONNECT only. Fine on `127.0.0.1`; do not expose
`--socks5-listen` on a real interface without auth.

Fixed-port mode (`serve --forward` + `connect --listen`) still exists unchanged.

---

## TUN mesh (short)

Two day-to-day shapes (both use the local daemon as a remote control):

```bash
# 1:1 "phone" — known contacts auto-connect; strangers ring until accept/reject
sudo link-p2p tun call <contact-or-id>
link-p2p tun ring
link-p2p tun call accept <peer>   # or: tun call reject <peer>

# Join a hub "channel" (hub always knows you; --hidden hides you from other spokes)
sudo link-p2p tun join <hub EndpointId>
# sudo link-p2p tun join <hub> --hidden

# Foreground debug aliases still work:
sudo link-p2p tun serve
sudo link-p2p tun connect --to <hub EndpointId>
```

Each node gets a VIP in `172.24.0.0/16` (IPv4 only). Mesh spokes prefer direct
paths; hub forwards as fallback. Privileged mode — see
[platforms.md](platforms.md) and [subsystems/tun.md](../subsystems/tun.md).

`tun connect` / spoke reconnects automatically (same backoff as stream mode).
The TUN interface and `/16` route survive across sessions. `link-p2p ping` works
against `tun serve`. `--max-conns` does **not** apply to TUN. Diagnose failures
in the daemon log (`tun.log`), not the short CLI remote.

---

## Identity

Default path: `$XDG_CONFIG_HOME/link-p2p/identity.key` (usually
`~/.config/link-p2p/identity.key`). Override with `--identity`.

| Rule | Why |
|---|---|
| Do not commit the key file | It is a private key |
| One process per identity file | Same key = same peer to iroh; connections bounce |
| Unix mode `0600` | Created and tightened on every start |
| Legacy cwd `identity.key` | Migrated to XDG on first run |

Optional encryption: `--identity-passphrase` or prefer `LINK_P2P_PASSPHRASE`
(flag shows up in `ps` / history). Argon2id + XChaCha20-Poly1305; plaintext
files loaded with a passphrase are re-encrypted on disk.

`--ephemeral` / `-e`: in-memory identity, never written; conflicts with `--identity`.

---

## Relays

Default: n0 public relay map. Custom map (skips DNS/pkarr discovery):

```bash
link-p2p serve --forward 127.0.0.1:22 \
  --relay http://vps.example:3340 \
  --relay https://use1-1.relay.n0.iroh.link
```

| Flag / env | Effect |
|---|---|
| `--relay` (repeatable) / `LINK_P2P_RELAY` | Custom relay URL(s); magicsock picks among them |
| `--no-n0-relays` | Custom relay(s) only (skip n0 public map). Prefer this when n0 is blocked |
| `--relay-only` / `LINK_P2P_RELAY_ONLY=1` | Force relay-only (no direct upgrade); both peers; conflicts with `--to-addr` |
| `--to-addr <ip:port>` | Pin direct address(es); skip discovery for that peer |

**Why self-host:** public n0 relays rate-limit per client (~tens of KB/s when
stuck on relay). Raise `limits.client.rx` in iroh-relay config. See
`contrib/systemd/iroh-relay.service` and
[architecture/performance.md](../architecture/performance.md).

Confirm path with `RUST_LOG=iroh=trace` (`Established` / `path_remote=Ip`) or
`link-p2p ping` settled path. Prefer global IPv6 with `--to-addr [v6]:port`
when available — TCP probe failure on IPv4 does not prove UDP hole-punch is
impossible.

Custom-only maps may hole-punch less reliably on double-symmetric NAT (fewer
direct candidates without pkarr/DNS).

---

## Operational flags

| Flag | Role |
|---|---|
| `--keepalive` / `--idle-timeout` | Defaults 5s / 30s. Keepalive holds NAT UDP mappings; idle timeout declares peer dead |
| Reconnect | `connect` and `tun connect` re-dial with backoff 1s → 30s; local listener stays up |
| `--max-conns <N>` | Cap concurrent stream forwards (default 1024, `0` = unlimited). Stream mode only |
| `--cc bbr3` / `LINK_P2P_CC` | Congestion control; A/B on **direct** paths only |
| `ping` | RTT + path to `serve` or `tun serve`; reports **initial** and **settled** (trust settled) |

At `RUST_LOG=link_p2p=debug`, periodic `path stats` logs path kind and loss
counters. Do **not** treat Quinn `udp_tx/rx` as proof of hole-punch — relay
traffic also appears as UDP to Quinn.

Transport config lives in `transport_config` (`src/main.rs`): 5s keepalive,
30s idle (relaxed from iroh's 15s so brief path switches do not kill the session).

---

## Security

| Control | Behavior |
|---|---|
| `serve --allow <EndpointId>` (repeatable) | Peer allowlist; unknown peers closed at handshake |
| `serve --proxy` SSRF guard | Blocks private / loopback / link-local / CGNAT `100.64/10` on **resolved** address |
| `--allow-private` | Lifts SSRF guard for trusted peers |

Without `--allow`, anyone who knows your EndpointId can connect; in `--proxy`
mode they can make your machine dial arbitrary targets.

---

## systemd

Template unit: `contrib/systemd/link-p2p@.service`.

```bash
# /etc/link-p2p/<name>.conf — one line of args
serve --forward 127.0.0.1:22 --relay http://relay.example:3340

sudo systemctl enable --now link-p2p@<name>
```

State under `/var/lib/link-p2p`; grants `CAP_NET_ADMIN` for TUN. Pin identity
with `--identity /etc/link-p2p/<name>.key`. systemd restarts crashed processes;
in-process reconnect handles lost QUIC without a restart.

Self-hosted relay: `contrib/systemd/iroh-relay.service` after
`cargo install iroh-relay --features server`.

---

## Logging

| Setting | Effect |
|---|---|
| (default) | `link_p2p=info,iroh=warn` |
| `RUST_LOG=iroh=debug` | iroh relay/discovery chatter |
| `--log-format json` | One JSON object per line on **stderr** |
| `-q` / `-v` | User-facing banner volume (independent of `RUST_LOG`) |

Stdout: status lines only (banner, `connected.`, ping). Colors off when stderr
is not a TTY. `RUST_LOG=link_p2p=debug` adds `pipe` spans (`sent_bytes` /
`recv_bytes`) and `dial completed` (`elapsed_ms`).

```bash
link-p2p serve --forward 127.0.0.1:22 --log-format json 2>serve.jsonl
jq -r 'select(.message == "connection opened") | .peer' serve.jsonl
```

---

## Completions and man

```bash
link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish
link-p2p completions bash > /etc/bash_completion.d/link-p2p
link-p2p completions zsh  > "${fpath[1]}/_link-p2p"
# also: powershell, elvish
link-p2p man | gzip -c > /usr/local/share/man/man1/link-p2p.1.gz   # Unix only
```

---

## Internationalization

Catalogs under `locales/`, compiled by `build.rs` via `msgfmt`. Language from
env: `LANGUAGE` > `LC_ALL` > `LC_MESSAGES` > `LANG`.

```bash
LANG=zh_CN.utf8 link-p2p --help
LANGUAGE=es_ES link-p2p --help
LANG=C link-p2p --help          # English fallback
```

`--color always|never|auto` (respects `NO_COLOR`). To add a language: copy a
`.po`, translate, rebuild. Override catalog dir with `LINK_P2P_LOCALEDIR`.

---

## Out of scope (today)

See [roadmap.md](../roadmap.md). Highlights: SOCKS5 is CONNECT-only / no-auth;
no LD_PRELOAD interception; no fine-grained TUN ACL; no stream-mode multi-hop
mesh; no app-level GSO/io_uring rewrite until benches say so.
