# Performance

How to measure link-p2p throughput, attribute bottlenecks correctly, and
interpret loopback numbers without over-reading them.

---

## Before you measure

Confirm configuration before blaming QUIC or the data plane.

| Check | What to do | If wrong |
|---|---|---|
| **Relay path** | `ping` settled path; yellow “low throughput while on relay” warning | Public n0 relays rate-limit (~20–50 KB/s). Self-host with `--relay`, raise iroh-relay `limits.client.rx`, or wait for direct. CC tuning will not help on relay. |
| **GSO** | Linux: kernel supports `UDP_SEGMENT`; iroh's noq-udp enables GSO by default | Fix GSO before claiming a protocol wall. See [GSO verification](#gso-verification) below. |
| **Congestion control** | A/B `--cc bbr3` / `LINK_P2P_CC=bbr3` on a **direct** path only | Do not A/B CC while stuck on a rate-limited public relay. |
| **Loopback vs real RTT** | Label loopback-only results; use two machines or `tc netem` for delay/loss | Window and CC differences often appear only with real RTT. |
| **Sysctl buffers** | iroh `Builder` does not expose socket buffer sizes | Raising `net.core.rmem_max` / `wmem_*` may be a no-op unless something calls `setsockopt`. |

### NAT and reachability

- Failed TCP probes (22, iperf3, ICMP) on CGNAT often mean **inbound TCP filtering**, not “UDP hole-punch is impossible”.
- Prefer **global IPv6** when available; pass `--to-addr [v6]:port`.
- Nodes with no global IPv6 and CGNAT IPv4 stay relay-dependent until the ISP provides a public path — protocol tweaks cannot invent inbound reachability.
- TCP hang ≠ P2P impossible; use `link-p2p ping` settled path plus outside `mtr`/`iperf3` to separate link quality from relay limits.

---

## Methodology

1. **Throughput**: `iperf3 -s` behind `serve --forward 127.0.0.1:5201`, then
   `iperf3 -c 127.0.0.1 -p <listen port>` through `connect`. Compare against
   Tailscale/WireGuard on the same pair when relevant.
2. **Latency**: stream mode is TCP-only — use echo timing or `link-p2p ping`
   for RTT; compare against base link latency separately.
3. **CPU**: sample both ends during iperf3 (`top`/`htop`) to see whether
   userspace QUIC cost dominates.
4. **Path**: note direct vs relay for each run. Relayed throughput is a
   different number than direct.

Scripts:

| Script | Purpose |
|---|---|
| [`scripts/bench.sh`](../scripts/bench.sh) | Single-machine stream throughput vs raw loopback |
| [`scripts/bench-multi.sh`](../scripts/bench-multi.sh) | N independent QUIC connections — does sharding help? |
| [`scripts/bench-transport-matrix.sh`](../scripts/bench-transport-matrix.sh) | Config matrix (baseline \| sysctl \| bbr3 \| bbr3+windows) |

Run the transport matrix before interpreting older single-shot numbers.

```bash
./scripts/bench-transport-matrix.sh          # default duration / streams
./scripts/bench-transport-matrix.sh 8 4      # seconds, parallel streams
```

Requires `./target/release/link-p2p`. Window/CC conclusions need real RTT; the
script states that explicitly.

---

## Loopback baseline (architecture ceiling)

`scripts/bench.sh` measures stream forwarding on one machine (`serve --forward` +
`connect --listen`) against raw loopback TCP. Example readings (kernel 7.1.6,
iroh 1.0.3 — **re-run on your hardware**):

| Measurement | Result |
|---|---|
| Raw loopback TCP (1 stream) | ~3.9 GB/s |
| Tunnel, 1 stream | ~340–380 MB/s |
| Tunnel, 4 streams (`-P 4`) | ~330 MB/s; CPU ~1.9 → ~2.9 cores |
| CPU at 4 streams | serve ~155%, connect ~135% |

Throughput is roughly flat from 1 → 4 streams while CPU keeps climbing — a
**per-connection** bottleneck (QUIC crypto / flow control), not a parallelism
problem. Typical cost: ~2.6–3 Gbps per QUIC connection at ~2–3 user-space cores.
Fine behind 1 Gbps; the limit on 10 Gbps+.

Re-measure after any data-plane change and on real hardware across a real network.

---

## Multi-connection scaling

`scripts/bench-multi.sh` runs N independent serve+connect pairs (separate identity,
UDP socket, QUIC connection). Same machine, raw-TCP control on the same interface:

| k connections | Tunnel aggregate | Per-connection | CPU | Raw TCP (same path) |
|---|---|---|---|---|
| 1 | 346 MB/s | 346 | ~2 cores | 3.4 GB/s |
| 2 | 538 MB/s | 269 | ~4.4 cores | — |
| 4 | 619 MB/s | 155 | ~7.9 cores | 3.7 GB/s |
| 8 | 647 MB/s | 81 | ~10.2 cores | 3.4 GB/s |

Raw TCP scales with parallel connections; QUIC aggregate plateaus near **~650 MB/s**
while CPU keeps climbing — shared data-path work (crypto / memory bandwidth).

**Connection sharding does not lift this ceiling.** Only a data-plane change
(e.g. WireGuard-style framing) would; the ~5 Gbps ceiling already exceeds typical
real links, so that rewrite was shelved on ROI grounds.

### Is ~650 MB/s the crypto wall?

No. On this CPU, OpenSSL speed shows AES-128-GCM ~2.3 GB/s/core and
ChaCha20-Poly1305 ~1.5 GB/s/core at 1300-byte packets. The wall is QUIC protocol
processing (ACK/congestion/stream state, userspace I/O), not AEAD.

Use these numbers to decide whether GSO/io_uring/LD_PRELOAD work is worth doing —
measure first, do not assume from an architecture diagram.

---

## Implementation notes

### SOCKS5 `write_target` batching

Proxy-mode stream headers are written as **one** `write_all` of the encoded target
bytes. There is **no** `.flush()` afterward: callers pass an unbuffered iroh QUIC
`SendStream`. Wrapping that stream in `BufWriter` without an explicit flush after
the header would hang until the buffer fills. Do not add buffering around
`write_target` without restoring flush.

### GSO verification

`noq-udp` logs GSO disable/fallback via the **`log`** crate, not `tracing`. A bare
`RUST_LOG=noq_udp=debug` may print nothing unless a log→tracing bridge is present.
Look for `GSO disabled`, `halting segmentation offload`, or `UDP_SEGMENT` in
process logs, or confirm kernel support with `setsockopt(UDP_SEGMENT)`.
