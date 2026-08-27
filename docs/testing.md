# Testing link-p2p

Two layers: fast local checks (no second machine, mostly no root) and the
real-network harness that needs two machines on different networks.

**Recorded run:** see [`docs/server-test-results.md`](server-test-results.md)
for a 2026-08-26 session against `kangxi@server` (SSH, unit/smoke/e2e, and a
cross-network stream + ping check).

## Local smoke test

`scripts/local-test.sh` runs the full pipeline on localhost against a
self-hosted relay: relay → serve → connect → a python HTTP/echo target,
checking an HTTP get through the tunnel and a 100KB byte-identical echo
round-trip. It expects a release build and an `iroh-relay` server binary
(default `tools/iroh-relay`, build one with
`cargo install iroh-relay --features server` and copy it there, or pass the
path as an argument).

For TUN mode, `sudo scripts/tun-loopback-test.sh` starts a local relay plus
`tun serve`/`tun connect` on one machine and checks MTU negotiation plus the
peer-exit route lifecycle (route removed on disconnect, no stale route after
reconnecting with a different identity). Caveat: both virtual IPs live on
the same machine, so the kernel's local routing table answers the pings
without entering the TUN — the script validates process startup, connection
and MTU negotiation, and route cleanup, but **not** the datagram data path;
that needs a ping across two machines.

`cargo test -- --ignored` runs `tests/e2e.rs`: it spawns the real
serve/connect binaries against a local relay with `--ephemeral` identities,
checks a 128KiB byte-identical round trip through the tunnel, sends SIGINT
and asserts both processes exit within the drain window (and the listener
port is released). It's `#[ignore]`d because it needs a release build and
the `tools/iroh-relay` binary — missing prerequisites are reported and
skipped, not failed.

`serve` and `tun serve` print a machine-parseable identity line on stdout:

```
ENDPOINT_ID=<64 hex chars>
```

This line is never localized. Scripts source `scripts/parse-endpoint-id.sh`
to read it; e2e parses the same format. Human-facing banner text stays
translated. The e2e harness also clears `LANGUAGE` when spawning binaries
(belt-and-suspenders on older builds that lack the machine line).

## Real-machine phase tests (two machines)

`scripts/phase*-{server,client}.sh` are the harness for the real-network
tests in `docs/roadmap.md` — NAT traversal (Phase 0), relay throughput
(Phase 0), and WiFi↔4G migration (Phase 1). Each pair replaces the manual
"start, sleep, grep, copy the ID" dance that kept breaking on slow n0
online times and non-English locales:

- the **server** side polls the log until the banner appears (n0 online can
take up to ~30s — a poll, not a fixed sleep), prints a share box with the
EndpointId + virtual IP, and stays up until Ctrl+C;
- the **client** side connects, runs the measurement, and prints a verdict;
- both sides run with `RUST_LOG=iroh=debug` and `LANG=C LC_ALL=C LANGUAGE=`
(the app output is localized; clearing `LANGUAGE` is what makes banner
parsing locale-independent on gettext-based systems).

Build a release binary first and run everything with `sudo` (TUN mode):

| test | machine A (serve) | machine B (connect) |
|---|---|---|
| NAT matrix — direct or relayed? | `sudo ./scripts/phase0-nat-matrix-server.sh` | `sudo ./scripts/phase0-nat-matrix-client.sh <EndpointId>` |
| Relay throughput (iperf3) | `sudo ./scripts/phase0-relay-bench-server.sh` | `sudo ./scripts/phase0-relay-bench-client.sh <EndpointId> [serve-public-IP] [--force-relay <peer-ip>]` |
| WiFi↔4G migration | `sudo ./scripts/phase1-migration-server.sh` | `sudo ./scripts/phase1-migration-client.sh <EndpointId>` |

The bench server auto-starts the two iperf3 servers the client needs (port
5201 bound to the serve VIP for the tunnel test, port 5202 bound to the
STUN-detected public IP for the direct control test) and prints the public
IP it detected so you can pass it to the client.

To force the relay path (e.g. the NAT matrix said "direct" but you want the
relay numbers), DROP inbound UDP from the peer on both machines — the relay
connection is TCP, so only the direct hole-punched path dies:

```bash
# on both machines, with the other machine's public IP
sudo ./scripts/phase-relay-ctl.sh force-relay <peer-public-ip>
# ... after the test ...
sudo ./scripts/phase-relay-ctl.sh clear-relay <peer-public-ip>
```

The bench client also accepts `--force-relay <peer-public-ip>`, which applies
its own DROP automatically (and clears it on exit) while printing the exact
command to run on the serve machine. Caveat: the direct path must die and the
relay take over *while the session is up* — if iroh tears the session down
instead of failing over ("peer disconnected" in the logs), apply the DROP on
both sides *before* connecting for a clean relay-path measurement.

The migration client pings the serve VIP continuously for 40s while you
switch the connect machine's network (WiFi off/on or hotspot), then reports
the drop count, iroh's path events, and whether the session survived — a
handful of dropped pings is the expected migration cost; 100% loss means the
session was rebuilt, not migrated.

## Phase test setup (sudo, Tailscale, relay forcing)

### Scoped passwordless sudo (recommended)

Do **not** grant `NOPASSWD: ALL`. For a dedicated test machine, allow only
the phase/TUN scripts by absolute path:

```
# /etc/sudoers.d/link-p2p-test  (visudo -f ...)
kangxi ALL=(root) NOPASSWD: /home/kangxi/文档/link-p2p/scripts/tun-loopback-test.sh, \
                               /home/kangxi/文档/link-p2p/scripts/phase0-nat-matrix-server.sh, \
                               /home/kangxi/文档/link-p2p/scripts/phase0-relay-bench-server.sh, \
                               /home/kangxi/文档/link-p2p/scripts/phase1-migration-server.sh
```

Adjust the home path if the clone lives elsewhere. Remove the file to revoke.
Client-side phase scripts also need root on the connect machine — mirror the
same pattern there if both boxes are yours.

### NAT matrix: run two rounds when Tailscale is installed

If both machines run Tailscale, iroh may select Tailscale direct paths before
public UDP hole-punching — that is **not** a pure NAT-traversal measurement.
Run the matrix at least twice:

1. **Tailscale off** on both ends (`sudo tailscale down` or stop the daemon) —
   baseline for public NAT / n0 hole-punch.
2. **Tailscale on** (normal daily setup) — documents real-world coexistence.

Compare `path::selected` / `ping` path reports between the two runs.

### Relay throughput: force relay, don't wait for luck

For reproducible relay numbers, drop inbound UDP from the peer's public IP on
**both** machines while the session is up (relay is TCP/WebSocket; direct UDP
dies). The harness already documents this:

```bash
sudo ./scripts/phase-relay-ctl.sh force-relay <peer-public-ip>
# ... run phase0-relay-bench-{server,client}.sh ...
sudo ./scripts/phase-relay-ctl.sh clear-relay <peer-public-ip>
```

Apply the DROP on both sides **before** connecting if you need a clean
relay-only measurement from the first packet. The bench client's
`--force-relay <peer-ip>` flag applies its own DROP and prints the command
for the serve side.
