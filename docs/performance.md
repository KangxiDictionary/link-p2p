# Performance: where zero-copy helps (and where it doesn't)

This doc maps link-p2p's data paths, what the loopback benchmarks say the
bottleneck is, and which local optimizations are worth doing without changing
wire behaviour. See `docs/benchmarks.md` for measured numbers.

## Bottleneck (measured)

On the reference machine, stream mode sustains ~340–380 MB/s per QUIC
connection while raw loopback TCP does ~3.9 GB/s. Sharding streams or
connections does not break a ~650 MB/s aggregate ceiling — CPU keeps climbing
while throughput plateaus. Profiling and `openssl speed` point at **QUIC
userspace protocol work** (ACK, flow control, stream state), not AEAD crypto
and not kernel syscall count alone.

Consequence: app-level changes (larger copy buffers, TCP tuning, fewer
allocations on the TUN path) may shave overhead and help packet rate, but
they will **not** turn this into a multi‑Gbps WireGuard-style dataplane
without replacing the transport. iroh already uses kernel UDP GSO (`UDP_SEGMENT`)
when available; duplicating that in link-p2p is not useful.

## Data paths

| Path | Hot functions | What happens today | Zero-copy? |
|---|---|---|---|
| Stream forward | `pipe_streams`, `copy` | TCP ↔ QUIC stream via userspace buffer | No — must bounce through app memory to reach iroh |
| TUN egress | `run_datagram_loop` | TUN `recv` → buffer → QUIC datagram send | No — one copy into owned `Bytes` before iroh |
| TUN ingress | `run_datagram_loop` | QUIC `read_datagram` → TUN `send` | No — kernel TUN write copies from `Bytes` |
| SOCKS5 / proxy header | `write_target`, `accept_handshake` | Once per connection (~ tens of bytes) | Irrelevant to throughput |
| Control plane | reconnect, ping, path stats | Not bulk | N/A |

True end-to-end zero-copy would need buffer APIs that hand ownership into
iroh/quinn (or a different dataplane). That is out of scope for this MVP.

## What we optimize (protocol-neutral)

### Stream mode (`pipe_streams`)

- **Larger pipe buffer** (64 KiB instead of Tokio `copy`'s 8 KiB): fewer
  read/write iterations through Tokio ↔ iroh ↔ syscalls. Cheap to try;
  re-benchmark after changes.
- **TCP tuning** on both legs (`TCP_NODELAY`, larger SO_RCVBUF/SO_SNDBUF
  hints): reduces small-write latency and can help bulk transfers; no wire
  format change.

### TUN mode (`run_datagram_loop`)

- **Reuse `BytesMut`** for datagram payloads instead of `Bytes::copy_from_slice`
  per packet: removes one allocation per packet; still one memcpy into the
  send buffer (unavoidable before iroh).
- **Keep** `send_datagram_wait`, biased `select!`, MTU shrink logic — already
  correct for migration and best-effort semantics.
- **Do not** switch to `send_datagram` without measuring: non-blocking drop
  behaviour differs under path migration.

### SOCKS5 / proxy setup

- **Batch header encoding** into one `write_all`: fewer async write syscalls
  at connection setup only — micro-optimization, not a throughput lever.

## What we deliberately do not do (yet)

| Idea | Why not |
|---|---|
| splice / sendfile between TCP and QUIC | QUIC endpoint is userspace; no kernel shortcut |
| io_uring on TUN fd | Benchmarks say QUIC dominates; large integration cost |
| LD_PRELOAD transparent proxy | Different product surface (README defers this) |
| Multiple QUIC connections for one flow | Benchmarks show ~650 MB/s aggregate cap anyway |
| WireGuard-style AEAD-per-packet rewrite | Would exceed ceiling but huge scope; shelved on ROI |
| `current_thread` runtime / fewer tasks | I/O-bound; no evidence task overhead is the limit |

## Async patterns already in good shape

- `pipe_streams`: concurrent half-duplex with correct FIN/RESET/STOP teardown.
- `ForwardHandler`: semaphore before `accept_bi` (backpressure).
- `open_stream_wait`: `watch` channel for reconnect (no poll sleep).
- `run_datagram_loop`: `biased` select, transient datagram errors ≠ session end.

## Re-measure after changes

```bash
scripts/bench.sh          # stream mode, loopback
scripts/bench-multi.sh    # connection scaling
# TUN throughput: phase0-relay-bench on two machines (see docs/testing.md)
```

Any change that claims a win should show up in those scripts (or `iperf3`
through the tunnel on real hardware), not just micro-benchmarks of `memcpy`.
