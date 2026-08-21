# Benchmarks: link-p2p vs the raw path

The actual point of this MVP was to get real numbers before building anything
else. This document keeps the methodology and the machine-specific numbers;
the README only points here.

## Methodology

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

## Loopback baseline (architecture ceiling)

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

## Multi-connection scaling (does sharding help?)

`scripts/bench-multi.sh` runs N fully independent serve+connect pairs (own
identity, own UDP socket, own QUIC connection, all confirmed on direct
paths) to test whether aggregate throughput scales with the number of
*connections* rather than streams. Same machine, with a raw-TCP control on
the same interface:

| k connections | tunnel aggregate | per-connection | CPU | raw TCP (same path) |
|---|---|---|---|---|
| 1 | 346 MB/s | 346 | ~2 cores | 3.4 GB/s |
| 2 | 538 MB/s | 269 | ~4.4 cores | — |
| 4 | 619 MB/s | 155 | ~7.9 cores | 3.7 GB/s |
| 8 | 647 MB/s | 81 | ~10.2 cores | 3.4 GB/s |

Raw TCP on the same interface scales fine with parallel connections (3.4+
GB/s at k=1, 4, 8), so the interface, the relay, and the kernel are not the
shared limit. The QUIC stack aggregate plateaus at ~650 MB/s while CPU keeps
climbing — a shared resource inside the data path (crypto/memory bandwidth)
that independent connections all compete for. Consequence: connection
sharding (MPTCP-style splitting into N QUIC connections) does **not** lift
this ceiling; only a data-plane change (e.g. WireGuard-style, or accepting
~5 Gbps) would. Numbers are machine-specific; re-run on real hardware.

Is the ~650 MB/s wall crypto? No — AEAD is cheap on this CPU
(`openssl speed`): AES-128-GCM ~2.3 GB/s/core and ChaCha20-Poly1305 ~1.5
GB/s/core at 1300-byte packets (realistic QUIC packet size). The wall is
QUIC protocol processing (ACK/congestion/stream state machines, userspace
I/O), not encryption. A WireGuard-style data plane (one AEAD per packet,
minimal protocol overhead) would almost certainly exceed it — but the ~5
Gbps ceiling already exceeds typical real links, so that rewrite was
shelved on ROI grounds, not feasibility. (boringtun could not be run in
this sandbox: TUN device creation needs CAP_NET_ADMIN.)

Whatever you find, that's the real basis for deciding whether GSO/io_uring/
LD_PRELOAD work is worth doing next, rather than assuming it from an
architecture diagram.
