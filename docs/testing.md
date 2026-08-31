# Testing link-p2p

One entry for everyday checks; everything else is opt-in (root / second machine / bench).

```bash
cargo build --release          # once
# optional: put iroh-relay at tools/iroh-relay for smoke/socks5
./scripts/test.sh              # unit + stream smoke + socks5
./scripts/test.sh unit         # cargo test only
```

Output is `PASS` / `FAIL` / `SKIP` lines plus a final summary.

| Mode | What it runs | Needs |
|---|---|---|
| `unit` | `cargo test` | toolchain |
| `smoke` | `local-test.sh` (HTTP + 100KB echo over stream) | release + `tools/iroh-relay` |
| `socks5` | `test-socks5.sh` (proxy + curl + binary echo) | release + `tools/iroh-relay` |
| `all` (default) | unit → smoke → socks5 | as above; missing relay → SKIP not FAIL |

Shared helpers live in `scripts/lib.sh` (`pass`/`fail`, `wait_endpoint_id`, locale pin).

`ENDPOINT_ID=<64 hex>` on serve stdout is never localized — scripts parse it via
`parse-endpoint-id.sh`.

---

## Opt-in (not in `test.sh`)

| Script / test | Purpose |
|---|---|
| `cargo test -- --ignored` (bin) | Live TUN daemon status (needs `CAP_NET_ADMIN`) |
| `cargo test --test e2e -- --ignored` | Stream forward round-trip + clean shutdown (release + relay) |
| `cargo test --test integration_call -- --ignored` | `call` persistent-identity kill/restart reconnect |
| `link-p2p tun selftest` | Relay TCP probe + loopback echo drain (no python/nc) |
| `sudo ./scripts/tun-loopback-test.sh` | TUN startup / MTU / route cleanup (same-host; not the datagram path) |
| `./scripts/long-stability-test.sh {serve\|client}` | Long-lived stream samples (HTTP + ping); set `PEER=` / `DURATION=` |
| `./scripts/remote-cleanup-link-p2p.sh` | Kill leftover `link-p2p` tmux/binaries only (not Tailscale) |
| `./scripts/bench-transport-matrix.sh` | Transport config matrix — see [architecture/performance.md](architecture/performance.md) |
| `./scripts/bench.sh` / `bench-multi.sh` | Throughput benches — see [architecture/performance.md](architecture/performance.md) |
| `./scripts/phase0-*.sh` / `phase1-*.sh` | Two-machine NAT / relay / migration — see below |

TUN ICMP PMTUD and ops clamp (`--mtu 1162`): [subsystems/tun.md](subsystems/tun.md).

---

## Two-machine phase harness

```text
NAT matrix     sudo phase0-nat-matrix-{server,client}.sh
Relay iperf3   sudo phase0-relay-bench-{server,client}.sh
WiFi↔4G        sudo phase1-migration-{server,client}.sh
```

Both sides: `RUST_LOG=iroh=debug`, `LANG=C LANGUAGE=`. Force relay with
`phase-relay-ctl.sh force-relay <peer-public-ip>` on **both** ends.

Scoped sudoers example (do **not** use `NOPASSWD: ALL`):

```
kangxi ALL=(root) NOPASSWD: /path/to/link-p2p/scripts/tun-loopback-test.sh, \
  /path/to/link-p2p/scripts/phase0-nat-matrix-server.sh, \
  /path/to/link-p2p/scripts/phase0-relay-bench-server.sh, \
  /path/to/link-p2p/scripts/phase1-migration-server.sh
```

If both hosts run Tailscale, run the NAT matrix twice (Tailscale up / down) —
iroh may pick the Tailscale path first.
