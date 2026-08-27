# Windows notes

Stream modes (`serve`, `connect`, `ping`, SOCKS5 proxy) work on Windows without
administrator privileges. TUN mode is **Linux-only** (`link-p2p tun` exits with
a clear error on other OSes).

## Quick start

```powershell
# Expose a local service (e.g. RDP on 3389):
link-p2p serve --forward 127.0.0.1:3389

# On another machine — copy the printed EndpointId:
link-p2p connect --to <EndpointId> --listen 127.0.0.1:13389
```

Identity defaults to `%LOCALAPPDATA%\link-p2p\identity.key` (via the same XDG-style
path logic as other platforms).

## Shell completions

```powershell
link-p2p completions powershell | Out-File -Encoding utf8 $PROFILE\link-p2p.ps1
```

Restart the shell or dot-source the file.

## Scripting

| Feature | Windows |
|---|---|
| `ping --format json` | yes — machine-readable RTT/path on stdout |
| `LINK_P2P_*` env vars | yes — same as `--flag` overrides |
| `-q` / `-v` | yes |
| Exit codes 0–5 | yes — use `$LASTEXITCODE` in PowerShell |
| `connect --stdio` | **Unix build only** (ssh ProxyCommand / pipe mode) |
| `--to -` (stdin EndpointId) | **Unix build only** |
| `link-p2p man` | **Unix build only** (troff; use `--help` on Windows) |

## TUN / VPN

Use WSL2 or a Linux peer for `link-p2p tun`. Whole-machine IP bridging needs
TUN + `ip route`, which this crate implements on Linux only.
