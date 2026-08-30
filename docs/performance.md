# Performance notes

Working notes on throughput bottlenecks and how to attribute them.
Do **not** treat a “QUIC protocol wall” as settled from loopback numbers alone.

## Exclude config before blaming the protocol

Before concluding the ceiling is QUIC state-machine / crypto overhead:

1. **Are you on relay?** Public n0 relays **rate-limit** per client (token
   bucket). Sustained ~20–50 KB/s with cubic ≈ bbr3 is expected there —
   tuning CC will not help. Confirm with `ping` settled path / the yellow
   “low throughput while on relay” warning, then self-host (`--relay`) and
   raise iroh-relay `limits.client.rx`, or wait for direct.
2. **GSO is default-on** in iroh’s UDP stack (noq-udp) when the kernel supports
   `UDP_SEGMENT`. Confirm it is actually engaged (see GSO check below) rather
   than assuming a disable path.
3. **Congestion control defaults to CUBIC.** A/B with `--cc bbr3` /
   `LINK_P2P_CC=bbr3` (and optional window env vars) **on a direct path**
   before treating CUBIC behavior as “the stack.” TUN datagram paths on lossy
   links often show the same lift — compare before blaming hub-forward
   architecture. Do not A/B CC while stuck on a rate-limited public relay.
4. **Loopback benches are not RTT-bound.** Window and CC differences often
   show up only with real delay/loss (two machines, or `tc netem`). Label
   loopback-only results as such.
5. **Socket buffers are not exposed by iroh’s `Builder`.** Raising
   `net.core.rmem_max` / `wmem_*` via sysctl may be a **no-op** for this
   process unless something calls `setsockopt` — iroh currently does not.
6. Re-run the same machine with
   [`scripts/bench-transport-matrix.sh`](../scripts/bench-transport-matrix.sh)
   (baseline | sysctl | bbr3 | bbr3+windows) before interpreting older
   single-shot numbers in [`benchmarks.md`](benchmarks.md).

### NAT / reachability notes

- Failed TCP probes (22, iperf3, ICMP) on a home/CGNAT uplink often mean
  **inbound TCP filtering**, not “UDP hole-punch is impossible”. Magicsock
  coordinates simultaneous outbound UDP after relay signaling; what matters
  is whether the NAT mapping is endpoint-independent (same external port
  across STUN/relay observations) vs symmetric.
- Prefer checking **global IPv6** on the server (`ip -6 addr`); many ISP
  gateways give routable IPv6 even when IPv4 is CGNAT. Pass
  `--to-addr [v6]:port` when you have it.
- **Field note (maintainer lab, 2026-08):** the long-lived “Server” peer in
  our Windows↔Linux tests had **no global IPv6** and IPv4 behind CGNAT with
  inbound TCP filtered. Settled path stayed relay-shaped (~tens of KB/s on
  public n0) until a self-hosted relay or a true direct candidate appeared.
  That class of node is **structurally** relay-dependent until the ISP gives
  a public IPv4 or IPv6 — protocol tweaks will not invent an inbound path.
- TCP hang ≠ P2P impossible; use `link-p2p ping` settled path + outside
  `mtr`/`iperf3` (UDP and TCP) to separate link quality from relay limits.

## SOCKS5 `write_target` batching

Proxy-mode stream headers are written as **one** `write_all` of the encoded
target bytes. There is **no** `.flush()` afterward on purpose: callers pass an
unbuffered iroh QUIC `SendStream`. Wrapping that stream in `BufWriter` (or
any other buffering that only flushes when full) would hang until the buffer
fills. Do **not** add buffering around `write_target` without restoring an
explicit flush after the header.

## Transport A/B matrix

```bash
./scripts/bench-transport-matrix.sh          # default duration / streams
./scripts/bench-transport-matrix.sh 8 4      # seconds, parallel streams
```

Requires `./target/release/link-p2p`. Prints a markdown-ish MB/s table per
group. Window/CC conclusions need real-RTT; the script says so explicitly.

### GSO check

To verify Linux GSO status against noq-udp logging, try a `RUST_LOG` that
includes `noq_udp=debug` (confirm the exact target/crate name in the
dependency tree — Linux GSO disable uses `crate::log::warn!` in noq-udp).
If GSO is off, fix that before reading protocol-wall claims off the matrix.


## GSO downgrade logging

`noq-udp` records GSO disable / fallback with the **`log`** crate (`crate::log::warn!` /
`info!`), not `tracing`. A bare `RUST_LOG=noq_udp=debug` may print nothing unless a
`log`→`tracing` bridge is installed. Prefer looking for strings like
`GSO disabled` / `halting segmentation offload` / `UDP_SEGMENT` in process logs when
a bridge is present, or confirm kernel support with `setsockopt(UDP_SEGMENT)` as in
the earlier config check.
