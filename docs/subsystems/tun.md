# TUN mode

Whole-machine IP mesh: hub coordination, spoke↔spoke direct paths, and hub
fallback forwarding over unreliable QUIC datagrams.

Stream modes (`serve`/`connect`) and TUN mode **coexist**; neither replaces the other.
Short recipes and install: [README](../../README.md) and [usage guide](../user-guide/usage.md).

---

## Topology

```
spoke A ──QUIC──┐                    ┌── spoke B
                ├── hub (roster +      │
spoke C ──QUIC──┘    fallback)        │
         A↔B prefer direct; else via hub
```

| Role | Command | Responsibility |
|---|---|---|
| Hub | `tun serve` / `tun up --role hub` | Accept peers, broadcast VIP↔EndpointId roster, forward when direct path missing |
| Spoke | `tun join <hub>` / `tun connect --to <hub>` | Join mesh, install `/16` route, dial other spokes when roster updates |
| Phone | `tun call <peer>` / `tun up --role phone` | 1:1 TUN; contacts auto-accept; unknowns ring → `tun call accept\|reject` |

**Spoke visibility:** `tun join --hidden` (or `tun up --to … --hidden`) tells the
hub not to put you on other spokes' rosters. The hub still routes your traffic;
other spokes cannot learn your VIP↔id to dial you directly.

**Behavior:**

1. Hub accepts multiple sessions; demuxes TUN traffic by destination VIP.
2. After VIP handshake, hub broadcasts roster on a reliable control stream
   (ALPN `link-p2p/tun/3`; `/2` was IPv4-only roster `LPR2`, `/1` had VIP exchange only).
3. Spokes dial new peers with `endpoint.connect(..., TUN_ALPN)`; use direct path
   when available, else send via hub.
4. Hub keeps spoke↔spoke forwarding as **fallback** (symmetric NAT, etc.).
5. Hub send path uses **per-peer mpsc** so one blocked `send_datagram_wait` does
   not stall the whole read loop.

**Security:**

- Drop packets whose source VIP ≠ handshake VIP (spoof guard).
- Reject duplicate VIP on second join.
- Break simultaneous dial ties with EndpointId lexicographic order.
- `--allow` / `LINK_P2P_ALLOW`: allowlist EndpointId; deny → exit code **5** (`DENIED`).

---

## Virtual IP allocation

Default VIPs = deterministic functions of `EndpointId`; **actual bound addresses
are exchanged at handshake** (supports `--tun-ip` / `--tun-ip6` overrides). Dual-stack:

| Family | Prefix | Host derivation |
|---|---|---|
| IPv4 | `172.24.0.0/16` | blake3(ep) low 16 bits |
| IPv6 | `fd24:ac18::/64` (ULA) | blake3(ep) next 64 bits |

ALPN `link-p2p/tun/3` exchanges both; roster magic is `LPR3` (52-byte entries).
Older `tun/2` peers are not compatible.

```
vip4(ep) = 172.24.0.0/16 | (blake3(ep) low 16 bits as host)
vip6(ep) = fd24:ac18::/64 | (blake3(ep) mid bits as interface id)
```

| Rule | Rationale |
|---|---|
| Avoid `100.64.0.0/10` | Tailscale netfilter drops non-`tailscale0` 100.64/10 sources |
| Spoke installs v4 `/16` + v6 `/64`; hub installs `/32` and `/128` per peer | Full mesh reachability from spokes |
| Auto-pick on collision | If `--tun-ip` / `--tun-ip6` omitted, walk salted derives until free |
| Manual override collision | Only `--tun-ip` / `--tun-ip6` fail hard with a short CLI error |
| `--tun-ip` / `--tun-ip6` | Override derived addresses |

---

## MTU and PMTUD

Final MTU = `min(--mtu, max_datagram_size())`. Default cap **1280**.

- **Linux:** the kernel disables IPv6 on an interface when link MTU is below 1280
  (RFC 8200 minimum). The Linux backend floors programmed interface MTU at
  **1280**; path ceilings below that are enforced via ICMP Frag Needed / PTB on
  the datagram send path (not by shrinking the interface below 1280).
- Oversize packets: inject ICMP Fragmentation Needed.
- MTU raise/lower uses hysteresis to avoid flapping.
- Ops clamp when path is lossy: `--mtu 1162`.
- `--cc bbr3` often helps on lossy or relay-heavy paths — compare before filing
  throughput bugs (see [`architecture/performance.md`](../architecture/performance.md)).

### Transport layer

- Outer transport is **QUIC** (iroh). Inner IP rides QUIC **datagrams**
  (unreliable, no stream flow-control window). Apps may still run **TCP or UDP
  inside** the tunnel; that is not “TUN implemented over TCP”.
- Roster uses a reliable control stream (`LPR3` frames).
- Stream-mode `LPF1` hello belongs to `link-p2p/tcp-forward/1` — not used in TUN ALPN.

---

## CLI

### Foreground (debug / systemd)

```bash
link-p2p tun serve  [--tun-ip <addr>] [--tun-ip6 <addr>] [--mtu <mtu>] [--allow <id>]…
link-p2p tun connect --to <EndpointId> [--tun-ip <addr>] [--tun-ip6 <addr>] …
```

Keep these forever as **foreground debug mode** (blocking, logs on stderr).
Same as `tun up --foreground --role hub|spoke` (or `tun join` / daemon phone mode).

**Privileges:** root / `CAP_NET_ADMIN` (Linux, macOS); Administrator + signed
`wintun.dll` beside the binary (Windows). Linux shortcut:
`sudo setcap cap_net_admin+ep $(which link-p2p)`.

**Reconnect:** `tun connect` re-dials with exponential backoff; TUN interface and
`/16` route survive across sessions.

**Observability:** `link-p2p ping` reports initial and settled RTT/path. While on
relay, periodic `network_change` retries hole-punch; low relay throughput triggers
a yellow warning. For relay-only baseline, use `--relay-only` on both sides.

### Daemon control plane

Scope: **TUN only**. Stream `serve` / `connect` / `call` / SOCKS5 stay
single-process blocking CLIs.

| Command | Role |
|---|---|
| `tun up … [--system]` | Ad-hoc background (Unix) or foreground; `--system` for supervisors |
| `tun join <hub>` | Sugar for spoke `tun up --to <hub>` |
| `tun call …` / `tun ring` | Phone-mode dial / accept / reject / list pending (ctl v2) |
| `tun down [--system]` | Graceful shutdown (idempotent) |
| `tun status` / `tun peers` | Queries (`--format text\|json`, `--system`; status includes `pending_calls`) |

`tun serve` / `tun connect` = `tun up --foreground` (ad-hoc paths only).
Control protocol version is **2** (`Call` / `Accept` / `Reject` + `pending_calls`).

#### Runtime modes (`RuntimeMode` in `src/tun_ctl.rs`)

Selected **only** via `--system` on CLI — not euid heuristics, not env vars.

| Resource | Ad-hoc | System (`--system`) |
|---|---|---|
| Control (Linux) | `$CONFIG/link-p2p/tun.sock` | `/run/link-p2p/tun.sock` |
| Control (macOS) | config dir | `/var/run/link-p2p/tun.sock` |
| Control (Windows) | hashed user pipe | `\\.\pipe\link-p2p-tun-system` (SDDL + protocol-layer admin for Shutdown) |
| Lock | `tun.lock` | same runtime dir |
| Pid file | `tun.pid` | **none** |
| Log | `tun.log` (not rotated) | **none** (journald / plist) |

After `tun up` (ad-hoc), the CLI prints the log path. For the system service:

```bash
systemctl status link-p2p-tun.service
journalctl -u link-p2p-tun.service -f
```

Startup failures also surface a short error on the CLI (plus a pointer to the log /
journal).

| Session | pid + Status | **memory only**, still in Status |
| Identity | default config dir | **`--identity` required** (Unix: `/etc/link-p2p/identity.key`; Windows: `%ProgramData%\link-p2p\identity.key`) |

Path helpers are pure (no IO). `tun up --system` requires `--foreground`.
Service example: `link-p2p tun up --foreground --role hub --system --identity /etc/link-p2p/identity.key`.

**Protocol:** `LPC1` + version + JSON (`tun_ctl.rs`); separate from roster `LPR3`.

**Ad-hoc lifecycle:** ready handshake exit codes 2/3/4; probe authoritative;
flock on `tun.lock`; stale socket unlink; `tun down` idempotent.

**Status:** ad-hoc CLI done; system paths (Step 0) done; Linux systemd install (Step 1) done;
macOS LaunchDaemon (Step 2) implemented — plist rendering covered by unit tests; real
`launchctl bootstrap`/`bootout` not yet verified on hardware.

```bash
# Linux
sudo cp target/release/link-p2p /usr/local/bin/
sudo link-p2p tun service install --role hub
link-p2p tun status --system
sudo link-p2p tun service uninstall

# macOS (LaunchDaemon as root; control socket under /var/run/link-p2p/)
sudo cp target/release/link-p2p /usr/local/bin/
sudo link-p2p tun service install --role hub
link-p2p tun status --system
sudo link-p2p tun service uninstall
```

**macOS log rotation:** system mode has no in-process log file; LaunchDaemon writes
stdout/stderr to `/var/log/link-p2p/tun.log` and `tun.err.log`. Add a newsyslog
drop-in (not installed automatically), e.g. `/etc/newsyslog.d/link-p2p.conf`:

```
/var/log/link-p2p/tun.log       640  7  *  @T00  J
/var/log/link-p2p/tun.err.log   640  7  *  @T00  J
```

Adjust retention (`7` = keep 7 rotated files) to taste. Linux uses journald via systemd.

#### Linux system socket permissions (open)

`bind_listener` currently `chmod`s the control socket to **0600** after bind
(`tun_daemon.rs`). A systemd service running as `link-p2p` therefore accepts
connections **only from that uid** (or root) — a normal login user running
`tun status --system` will fail probe/connect and surface **`DAEMON_NOT_RUNNING`**
even when the service is up (misleading, same class as path mismatch).

**To verify:** install the unit, then as a non-`link-p2p`, non-root local user,
run `link-p2p tun status --system`.

**Planned fix (align with Windows two-layer model below):** widen socket permissions
so any local user can connect for read-only ctl (`Status`/`Peers`); enforce
admin-only **`Shutdown`** (and any future privileged ops) in the daemon by
inspecting the peer cred on Unix (`SO_PEERCRED` / `getpeereid`) rather than
relying on file mode alone. macOS system mode needs the same audit (`/var/run/link-p2p/tun.sock`).

#### Step 3 — Windows SCM (**implemented**; verify on real hardware)

Operator doc: [windows-service-setup.md](../user-guide/windows-service-setup.md)
(Event Log source `link-p2p-tun`, 30s `SetServiceStatus` keep-alive, SDDL
pre-validation at install/start, ProgramData identity writability check).

Prerequisites: Windows named-pipe control in `tun_ctl`/`tun_daemon`/`win_pipe`
(same LPC1 protocol as Unix). TUN data plane via Wintun is already in tree.

**Service account: LocalSystem** — no dedicated low-privilege Windows account.
Linux `AmbientCapabilities=CAP_NET_ADMIN` has no Windows equivalent; Wintun adapter
creation and `netsh` route setup need administrator-class rights. Virtual
`NT SERVICE\…` accounts would not cover external `netsh` calls without LSA
policy work. Follow WireGuard/Tailscale convention (`account_name: None` → LocalSystem).

**Identity path:** `%ProgramData%\link-p2p\identity.key` — resolve `ProgramData`
env var, fallback `C:\ProgramData\link-p2p\identity.key` (same pattern as
`HOME`/`XDG` fallbacks elsewhere). Service install bootstraps from the installing
admin's `%LOCALAPPDATA%\link-p2p\identity.key` when missing.

**Administrator gate:** `require_admin()` (via `GetTokenInformation` /
`TokenElevation` — not deprecated `IsUserAnAdmin`) runs **first** in
`tun service install/uninstall` dispatch, before any filesystem or identity work
(mirror Linux `require_root()` ordering).

**Named pipe — two layers (not DACL-only):**

| Layer | What |
|---|---|
| DACL on `\\.\pipe\link-p2p-tun-system` | Who may **connect** |
| Daemon handler | Who may run **privileged** ctl ops |

SDDL (local pipe only; no Everyone/WD):

```text
D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)
```

- `(A;;GRGW;;;BU)` — `BUILTIN\Users`: read/write connect so any logged-in user
  can run `tun status --system` / `tun peers --system` without elevation.
- `(A;;GA;;;SY)` / `(A;;GA;;;BA)` — SYSTEM and Administrators: full control.
- Do **not** add `(A;;GA;;;WD)`.

`Shutdown` is **not** blocked by DACL alone. On `Shutdown`, the daemon
**impersonates the named-pipe client** (`ImpersonateNamedPipeClient`), checks
Administrators / LocalSystem membership on that token, then `RevertToSelf`.
Do **not** use `GetNamedPipeClientProcessId` + later `OpenProcess` (PID reuse
race). Reject with `CtlResponse::Err` and a dedicated permission exit code
(not `DAEMON_NOT_RUNNING`).

**Control plane (cross-platform, before widening socket/DACL access):**

- Accept loop spawns a **per-connection task**; each `read_request` is wrapped
  in a short read timeout (2–5s). A hung client must not block `Shutdown`.
- Shared shutdown flag / `TunHooks` cancel; stop accepting after Shutdown.
- `peer_is_privileged(&stream) -> bool`: Unix `peer_cred()` (`uid == 0 || uid == euid`);
  Windows impersonation as above. `Status`/`Peers` open to any connector;
  `Shutdown` requires privileged. Ad-hoc 0600 sockets may skip the check.
- Ready handshake (`127.0.0.1:0`): require a nonce (reuse `ENV_SESSION` or
  dedicated) so a local third party cannot inject `OK` / `ERROR`.

Tokio's safe `ServerOptions` cannot set custom `SECURITY_ATTRIBUTES`; use
`windows-sys` `CreateNamedPipeW` with the SDDL above, then
`NamedPipeServer::from_raw_handle` (unsafe) to hand off to tokio — the only
raw FFI surface for pipe creation. Use `PIPE_UNLIMITED_INSTANCES` (or a pool)
so accepting one client immediately arms the next instance — same head-of-line
pattern as the Unix accept loop.

**Keep `src/win_pipe.rs` (do not swap for `interprocess`):** system ctl needs
custom SDDL, `ImpersonateNamedPipeClient`, and `TokenElevation` checks in one
auditable module beside `tun_ctl` / SCM. `interprocess` does not give us that
as a stable unit today; revisit only if it grows first-class SDDL +
impersonation we can pin and fuzz. See the module docs on `win_pipe`.

**Separate SCM entry path (not `--foreground` reuse):**

systemd/LaunchDaemon treat the child as a normal foreground process; Windows SCM
requires `StartServiceCtrlDispatcherW` + a control handler for
`SERVICE_CONTROL_STOP`. Add an internal **`--windows-service`** flag (only in the
service `launch_arguments`, not for manual use). When set, `main` branches into
the SCM handshake (`windows-service` crate:
`define_windows_service!` + `service_dispatcher::start()`), then runs the same
TUN worker as `--foreground --system`. `SERVICE_CONTROL_STOP` (and ctl
`Shutdown` when admin) all trigger the existing `TunHooks` **cancel** channel —
one teardown path, no Windows-specific shutdown fork.

Service registration sketch (`windows-service::service_manager`):

```rust
ServiceInfo {
    name: "link-p2p-tun".into(),
    display_name: "link-p2p TUN mesh daemon".into(),
    service_type: ServiceType::OWN_PROCESS,
    start_type: ServiceStartType::AutoStart,
    error_control: ServiceErrorControl::Normal,
    executable_path: validated_binary_path,
    launch_arguments: vec![
        "tun", "up", "--foreground", "--system", "--windows-service",
        "--role", role, /* + --identity ProgramData path */,
    ],
    account_name: None,   // LocalSystem
    account_password: None,
    ..
}
```

Uninstall: `.stop()` → poll `.query_status()` until `SERVICE_STOPPED` (same shape
as `tun down` teardown wait) → `.delete()`.

Shutdown order: `Shutdown` → `hooks.cancel` → data plane exit → `endpoint.close()` → cleanup.

---

## Release acceptance checklist

Run before shipping a release that touches `src/tun/` or platform routing/MTU
helpers. Linux is the maintainer baseline; macOS and Windows are best-effort —
open an issue with OS, command line, and logs on failure.

| # | Check | How | Pass if |
|---|---|---|---|
| 1 | Serve starts | `sudo link-p2p tun serve` (elevated on Windows) | Prints VIP + `ENDPOINT_ID=…`; interface up |
| 2 | Connect + ICMP | Peer: `tun connect --to <id>`; both `ping <peer VIP>` v4 **and** v6 | RTT both ways |
| 3 | TCP over VIP | e.g. `nc -l` / `nc` or `ssh user@<peer VIP>` | Payload round-trips |
| 4 | Reconnect / route cleanup | Stop serve, restart, connect again | Old `/32` gone; new session works |
| 5 | Hub mesh reconnect | 3-node hub + 2 spokes; kill hub spoke session ~10s, redial | Traffic resumes; no stale routes |
| 6 | MTU raise | `RUST_LOG=link_p2p=info`; large `ping -s 1200` | No outer fragmentation; MTU raises when negotiated |
| 7 | MTU shrink | Lower path MTU if possible | Log shows lowered MTU and/or ICMP Frag Needed; TCP recovers |
| 8 | Ctrl+C teardown | Ctrl+C both sides | Interface removed; peer route deleted |
| 9 | VIP collision | Same `--tun-ip` on a real local iface, then start tun | Clear error; no second binding |
| 10 | Exit codes | Block UDP / refuse peer | Online wait → **4**; bind/connect hard fail → **3** |

### Platform notes

**Windows**

- `wintun.dll` architecture must match the exe (official signed `amd64\wintun.dll`).
- MTU: `netsh interface ipv4 set subinterface … mtu=` when path ceiling changes.
- Peer route: `netsh interface ipv4 add route <peer>/32 <WintunName>` — do not use
  `route add … <ownVIP>` (often blackholes traffic off Wintun).
- If `netsh` MTU fails, ICMP injection remains; re-test under strict ICMP drop policies.

**macOS**

- Interface name is kernel-assigned `utunN`.
- Reconnect should not leave `route -n get <peer VIP>` failing longer than one
  failed `route add` retry.

---

## Out of scope (roadmap)

Lazy dial-on-traffic, fine-grained ACL (per-port/CIDR), separate routing protocol,
public DHT (iroh covers discovery).
