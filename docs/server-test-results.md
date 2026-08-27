# Server test results (2026-08-26)

Recorded after SSH access to `kangxi@server` and running the checks described
in `docs/testing.md`. The server clone lives at `~/文档/link-p2p` and was
reset to `origin/master` (`7dcaa4b`) before testing.

## Environment

| | Server (`kangxi@server`) | Client (local dev machine) |
|---|---|---|
| OS | Debian 13, kernel 6.12.101-amd64 | CachyOS, kernel 7.2.0 |
| link-p2p | `7dcaa4b`, `cargo build --release` | `target/release/link-p2p 0.1.0` (Aug 23 build) |
| iroh-relay | `1.1.0` at `tools/iroh-relay` | not used locally |
| Default locale | `LANG=zh_CN.UTF-8`, `LANGUAGE=zh_CN:zh` | `LANG` unset (English) |
| Public IPv4 (STUN) | `120.231.217.156` | `14.155.110.106` |
| Tailscale | yes (`100.65.25.57`, `172.24.219.89`) | yes (`100.123.130.118`) |
| Passwordless sudo | no (TUN phase scripts blocked) | — |

Both machines sit behind home NAT and also run Tailscale. That matters when
reading path logs: iroh may briefly select a Tailscale direct path before
falling back to relay or a public-UDP hole-punched path.

---

## Single-machine tests on the server

All commands run from `~/文档/link-p2p` unless noted.

### `cargo test` (unit tests)

```
27 passed; 0 failed
```

Covers SOCKS5 wire protocol, i18n catalog handling, SSRF guard, identity
encryption, CLI localization guards, etc.

### `scripts/local-test.sh`

**PASS** (~16s)

- Self-hosted relay on `:3340`
- `serve --forward` + `connect --listen`
- HTTP GET through tunnel → `200`
- 100 001-byte echo round-trip → byte-identical

### `scripts/test-socks5.sh`

**PARTIAL**

| check | result |
|---|---|
| `curl --socks5` (IP target) | HTTP 200 |
| `curl --socks5-hostname` (domain resolved on serve side) | HTTP 200 |
| Python TCP echo via SOCKS5 (2100 bytes) | **FAIL** — `MISMATCH 0/2100` (received 0 bytes) |

**Re-check (2026-08-27):** curl and echo both target loopback (`127.0.0.1:18082`
/ `localhost:18082` for curl; `127.0.0.1:<ephemeral>` for echo). Without
`--allow-private`, the serve log shows the SSRF guard rejecting those dials
(`stream error` / private-range blocked) — yet **curl still printed HTTP
200**. That status is misleading: SOCKS5 CONNECT succeeds on the connect side
before serve runs `check_proxy_target`, so curl is not proof the proxy pipe
reached the target. Echo's 0-byte result matches the blocked stream. The
startup banner warning (`proxy targets in private/loopback ranges are
blocked`) is unconditional in proxy mode, not per-request.

**Fix:** `test-socks5.sh` now passes `--allow-private`, drains the full
10-byte SOCKS5 CONNECT reply, sets recv timeouts, runs a direct echo baseline
first, and uses `[t]arget/release/link-p2p` in `pkill` patterns.

### `cargo test --release -- --ignored` (e2e)

**FAIL** with default server locale (`LANGUAGE=zh_CN:zh`): both tests time out
waiting for the English banner substring `your EndpointId`. Even `LANG=C` is
not enough when `LANGUAGE` is set — gettext semantics pick Chinese output
(`你的 EndpointId`).

**Update (2026-08-27):** fixed at the source — `serve`/`tun serve` now emit
`ENDPOINT_ID=<hex>` (never localized); scripts/e2e parse that line. e2e also
clears `LANGUAGE` when spawning. The SOCKS5 echo failure was primarily the
SSRF guard blocking loopback without `--allow-private` (echo 0 bytes matches
serve-side `stream error`); curl's HTTP 200 on the same loopback targets was
a false pass because SOCKS5 CONNECT succeeds before serve rejects the dial.
The script also had fragile CONNECT-reply reads and a self-matching `pkill`
pattern — all fixed in `test-socks5.sh`.

**PASS** when locale is fully pinned:

```bash
env LANG=C LC_ALL=C LANGUAGE= cargo test --release -- --ignored
# 2 passed in ~7s
```

The phase scripts already document `LANG=C`; e2e (and any automation parsing
banners) should also clear `LANGUAGE`, or parse the EndpointId line directly
instead of grepping for an English msgid.

### `sudo scripts/tun-loopback-test.sh`

**NOT RUN** — server requires a sudo password interactively.

### Phase 0 / Phase 1 harness (`scripts/phase*-{server,client}.sh`)

**NOT RUN** — same sudo requirement (TUN mode).

---

## Cross-network stream test (server serve + local connect)

Ad-hoc two-machine check using the default n0 preset (no `--relay`), stream
mode only:

1. **Server**: `python3 -m http.server 18081` + `link-p2p serve --forward 127.0.0.1:18081`
2. **Local**: `link-p2p connect --to <EndpointId> --listen 127.0.0.1:19998`
3. **Local**: `curl http://127.0.0.1:19998/` and `link-p2p ping --to <EndpointId>`

| measurement | result |
|---|---|
| Time to `connected.` banner | ~6 s (n0 online + dial) |
| HTTP GET through tunnel | **200**, ~0.30 s |
| `ping` RTT | **873 ms**, `path: direct (UDP)` |
| Server-side path (from `RUST_LOG=iroh=debug`) | Initial traffic on Tailscale (`100.65.25.57 ↔ 100.123.130.118`), then path abandoned (`TimedOut`) and switched to **relay** (`usw1-1.relay.n0.iroh.link`) for the long-lived forward session |
| Client-side `ping` path report | **direct (UDP)** on public addresses |

**Takeaway:** stream forwarding and `ping` both work across real networks
with a single manual EndpointId exchange. Path selection is non-trivial when
Tailscale is present on both ends — the forward session and a fresh `ping`
probe may not use the same path. Phase 0's dedicated NAT-matrix scripts are
still needed for a structured direct-vs-relay verdict.

---

## Summary

| test | status |
|---|---|
| Unit tests (`cargo test`) | pass |
| `local-test.sh` | pass |
| `test-socks5.sh` HTTP checks | pass (see SSRF caveat above — 200 alone is not enough) |
| `test-socks5.sh` binary echo | **fixed** (`--allow-private` + script recv/pkill fixes) |
| e2e (`--ignored`) with default `zh_CN` locale | **fixed** (`ENDPOINT_ID=` parse) |
| e2e with `LANG=C LC_ALL=C LANGUAGE=` | pass |
| TUN loopback / phase harness | blocked (no passwordless sudo) |
| Cross-network stream + ping | pass (direct UDP ping; mixed paths in debug logs) |

### Recommended follow-ups

1. ~~Clear `LANGUAGE` in e2e / parse EndpointId without English grep~~ — done
   (`ENDPOINT_ID=` line + `parse-endpoint-id.sh`).
2. ~~Fix `scripts/test-socks5.sh` echo stanza~~ — done.
3. Re-run Phase 0/1 on two machines with scoped sudo — especially NAT matrix
   (Tailscale off + on) and forced-relay throughput.
4. When validating `--proxy` against loopback targets, check serve logs for
   `stream error` / SSRF blocks — do not rely on curl's HTTP status alone.
