# Platform guide

Platform-specific setup for running link-p2p. Install and quick start:
[README.md](../../README.md). Day-to-day recipes: [usage.md](usage.md).

---

## Linux

Stream modes need no privileges. TUN mode needs **root** or `CAP_NET_ADMIN`:

```bash
sudo link-p2p tun serve
# or grant capability once:
sudo setcap cap_net_admin+ep $(which link-p2p)
```

TUN uses `/dev/net/tun` and `ip` for routing. macOS/Windows TUN details differ
below; Linux is the maintainer baseline.

**Install layout:** put the binary and a sibling `locales/` under the same
directory (e.g. `/usr/local/bin/link-p2p` + `/usr/local/bin/locales/…`), or set
`LINK_P2P_LOCALEDIR`. See [README Install](../../README.md#install).

**Linux MTU note:** interface MTU is never programmed below **1280** so IPv6 stays
enabled on the TUN device; smaller path ceilings use ICMP PTB on the send path.
See [subsystems/tun.md](../subsystems/tun.md#mtu-and-pmtud).

---

## macOS

TUN uses `utun` (kernel-assigned name). Requires root or `CAP_NET_ADMIN`
equivalent. Best-effort without dedicated CI — report create/route/MTU issues
with logs.

---

## Windows

### Stream modes

No administrator required.

```powershell
link-p2p serve --forward 127.0.0.1:3389
link-p2p connect --to <EndpointId> --listen 127.0.0.1:13389
```

Identity defaults to `%LOCALAPPDATA%\link-p2p\identity.key`.

### Translations

Windows often has no `LANG` / `LANGUAGE`. link-p2p reads the OS UI language
list (e.g. `zh-CN`) when unset. Catalogs must sit **next to the exe**:

```
link-p2p.exe
locales\zh_CN\LC_MESSAGES\link-p2p.mo
locales\ja_JP\LC_MESSAGES\link-p2p.mo
locales\es_ES\LC_MESSAGES\link-p2p.mo
```

Override with `LINK_P2P_LOCALEDIR` or `LANGUAGE=zh_CN`.

### Shell completions

```powershell
link-p2p completions powershell | Out-File -Encoding utf8 $PROFILE\link-p2p.ps1
```

### TUN / Wintun

Requirements:

1. **Elevated** terminal (Administrator).
2. Official signed **`wintun.dll`** in the same folder as `link-p2p.exe`
   (download from https://www.wintun.net/ — use `amd64\wintun.dll` on x64).
3. Allow firewall prompt when the adapter comes up.

```powershell
.\link-p2p.exe tun serve
.\link-p2p.exe tun connect --to <EndpointId>
# or: .\link-p2p.exe tun up --foreground --role hub
# Background `tun up` (no --foreground) is not yet supported on Windows.
```

**System service (LocalSystem):** see
[windows-service-setup.md](windows-service-setup.md)
(`tun service install`, `%ProgramData%\link-p2p\identity.key`, Event Log
source `link-p2p-tun`).

**“The file is not signed”** — wrong or unsigned DLL, or an older DLL on `PATH`.
Replace with official `amd64\wintun.dll`. Admin rights do not bypass Authenticode
(signer must be **WireGuard LLC**).

See [TUN subsystem doc](../subsystems/tun.md) for routing/MTU and release checklist.

---

## Unix-only features

Compiled only on Unix (`cfg(unix)`). Windows builds keep stream/proxy/ping, JSON,
env vars, exit codes, and PowerShell completions.

| Feature | Behavior |
|---|---|
| `connect --stdio` | Bidirectional stdio ↔ QUIC stream (`ssh -o ProxyCommand=…`, `rsync -e`). Banners on **stderr**. |
| `--to -` | Read peer `EndpointId` from stdin (one line). |
| `link-p2p man` | Lightweight troff page from the same help tree as `--help`. |

Give each long-running role its own `--identity` file. Two processes sharing one
key fight over relay/discovery.

### Completions and man

```bash
link-p2p completions fish|bash|zsh|powershell|elvish
link-p2p man | gzip -c > /usr/local/share/man/man1/link-p2p.1.gz
```

---

## Cross-platform reference

### Scripting

| Feature | Linux / macOS | Windows |
|---|---|---|
| `ping --format json` | yes | yes |
| `LINK_P2P_*` env vars | yes | yes |
| `-q` / `-v` | yes | yes |
| Exit codes 0–6 | yes | yes (`$LASTEXITCODE`) |
| `connect --stdio` | yes | **no** |
| `--to -` | yes | **no** |
| `link-p2p man` | yes | **no** — use `--help` |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`tun down` when already stopped is also 0) |
| 1 | Other / unexpected error |
| 2 | Usage / bad arguments (includes `tun up` while already running) |
| 3 | Connect failed (`tun up` when daemon reports init failure) |
| 4 | Timeout (`tun up` ready wait; online wait elsewhere) |
| 5 | Denied (peer not on `--allow`) |
| 6 | TUN daemon not running (`tun status` / `tun peers` only — not `tun down`) |

### Environment (CLI flags win)

| Variable | Purpose |
|---|---|
| `LINK_P2P_TO` | Peer EndpointId |
| `LINK_P2P_RELAY` | Relay URL(s) |
| `LINK_P2P_ALLOW` | Allowlist for serve |
| `LINK_P2P_PASSPHRASE` | Identity passphrase (prefer over flag) |
| `LINK_P2P_CC` | Congestion control (`cubic` / `bbr3`) |
| `LINK_P2P_SEND_WINDOW` | QUIC send window (bytes) |
| `LINK_P2P_STREAM_RECV_WINDOW` | Per-stream recv window (bytes) |

### Quiet / verbose vs `RUST_LOG`

| Flag | Role |
|---|---|
| `-q` | Quieter user-facing output |
| `-v` / `-vv` | More user-facing detail |
| `RUST_LOG` | Structured tracing (independent of `-q`/`-v`) |

Default without `RUST_LOG`: `link_p2p=info,iroh=warn`.
