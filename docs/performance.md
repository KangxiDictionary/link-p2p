# Performance notes

Working notes on throughput bottlenecks and how to attribute them.
Do **not** treat a “QUIC protocol wall” as settled from loopback numbers alone.

## Exclude config before blaming the protocol

Before concluding the ceiling is QUIC state-machine / crypto overhead:

1. **GSO is default-on** in iroh’s UDP stack (noq-udp) when the kernel supports
   `UDP_SEGMENT`. Confirm it is actually engaged (see GSO check below) rather
   than assuming a disable path.
2. **Congestion control defaults to CUBIC.** A/B with `--cc bbr3` /
   `LINK_P2P_CC=bbr3` (and optional window env vars) before treating CUBIC
   behavior as “the stack.” TUN datagram paths on lossy links often show the
   same lift — compare before blaming hub-forward architecture.
3. **Loopback benches are not RTT-bound.** Window and CC differences often
   show up only with real delay/loss (two machines, or `tc netem`). Label
   loopback-only results as such.
4. **Socket buffers are not exposed by iroh’s `Builder`.** Raising
   `net.core.rmem_max` / `wmem_*` via sysctl may be a **no-op** for this
   process unless something calls `setsockopt` — iroh currently does not.
5. Re-run the same machine with
   [`scripts/bench-transport-matrix.sh`](../scripts/bench-transport-matrix.sh)
   (baseline | sysctl | bbr3 | bbr3+windows) before interpreting older
   single-shot numbers in [`benchmarks.md`](benchmarks.md).

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
