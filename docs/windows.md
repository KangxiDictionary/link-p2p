# Windows notes

Stream modes (`serve`, `connect`, `ping`, SOCKS5 proxy) work on Windows without
administrator privileges. TUN mode works on Windows via **Wintun**, but needs an
elevated process and a **signed** `wintun.dll` beside the binary (see below).
Stream and TUN are independent; use stream when you only need one TCP port.

## Quick start

```powershell
# Expose a local service (e.g. RDP on 3389):
link-p2p serve --forward 127.0.0.1:3389

# On another machine — copy the printed EndpointId:
link-p2p connect --to <EndpointId> --listen 127.0.0.1:13389
```

Identity defaults to `%LOCALAPPDATA%\link-p2p\identity.key` (via the same XDG-style
path logic as other platforms).

## Translations

Windows usually has no `LANG` / `LANGUAGE` environment variables. link-p2p reads
the OS UI language list (e.g. `zh-CN`) when those are unset.

You still need the compiled catalogs **next to the exe**:

```
link-p2p.exe
locales\zh_CN\LC_MESSAGES\link-p2p.mo
locales\ja_JP\LC_MESSAGES\link-p2p.mo
locales\es_ES\LC_MESSAGES\link-p2p.mo
```

After a Linux cross-build they live under
`target/x86_64-pc-windows-gnu/release/locales/` — copy that folder with the exe.
Building on Windows without `msgfmt` (gettext) skips `.mo` generation and stays
English; override with `LINK_P2P_LOCALEDIR` or set `LANGUAGE=zh_CN` explicitly.

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

## TUN / VPN (Wintun)

Whole-machine IP bridging (`link-p2p tun serve` / `tun connect`) uses
[Wintun](https://www.wintun.net/). Requirements:

1. Run an **elevated** PowerShell / terminal (Administrator).
2. Put the **official signed** `wintun.dll` for your CPU architecture in the
   **same directory** as `link-p2p.exe`:
   - Download the zip from https://www.wintun.net/
   - Use `amd64\wintun.dll` on 64-bit Intel/AMD Windows (not arm64, not a
     self-built/unsigned copy).
3. Allow the firewall if Windows prompts when the adapter comes up.

```powershell
# elevated — exe and wintun.dll in the same folder
.\link-p2p.exe tun serve
# peer:
.\link-p2p.exe tun connect --to <EndpointId>
```

### “The file is not signed”

`wintun-bindings` verifies Authenticode and expects signer **WireGuard LLC**.
That error almost always means:

- a wrong/unsigned DLL was placed beside the exe, or
- an older unsigned `wintun.dll` earlier on `PATH` was loaded (link-p2p now
  forces the path next to the exe to avoid PATH shadowing).

Fix: replace with the official `amd64\wintun.dll` from wintun.net. Admin rights
alone do not bypass the signature check.

Interface MTU: link-p2p also runs `netsh interface ipv4 set subinterface … mtu=`
when the path ceiling changes, so local TCP can learn a lower MTU without
depending only on injected ICMP Fragmentation Needed (which some firewalls
drop). If `netsh` fails, the datagram loop still clamps sends and injects ICMP
— re-test under a strict ICMP policy if you care about that edge case.

Peer VIP route: after handshake, link-p2p installs
`netsh interface ipv4 add route <peer>/32 <WintunName>` (on-link via the
adapter). Do **not** expect `route add <peer> mask 255.255.255.255 <ownVIP>`
to work — that often lands off the Wintun interface and blackholes ICMP/TCP
even though the session log says “connected”.

Release checklist: [`docs/tun-acceptance.md`](tun-acceptance.md).

## Cross-compiling from Linux (preferred)

```bash
rustup target add x86_64-pc-windows-gnu   # once
# Arch/CachyOS: sudo pacman -S mingw-w64-gcc

cargo build --release --target x86_64-pc-windows-gnu
```

Artifacts:

```
target/x86_64-pc-windows-gnu/release/link-p2p.exe
target/x86_64-pc-windows-gnu/release/locales/   # copy next to the exe
```

This repo’s `.cargo/config.toml` sets the MinGW linker for that target.
