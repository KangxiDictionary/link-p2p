# Windows Service setup (TUN system mode)

Install `link-p2p` as a LocalSystem SCM service so the TUN mesh stays up
across logouts. Ad-hoc `tun up` (user session) is separate — see
[platforms.md](platforms.md) and [../subsystems/tun.md](../subsystems/tun.md).

## Prerequisites

1. **Administrator** PowerShell or cmd (elevated).
2. Official signed **`wintun.dll`** in the **same folder** as `link-p2p.exe`
   (from [wintun.net](https://www.wintun.net/) — use the `amd64` build on
   64-bit Windows). Do not run the service from `Temp` or `Downloads` —
   the binary refuses to load `wintun.dll` from those directories.
3. Preferred install layout:

   ```
   C:\Program Files\link-p2p\link-p2p.exe
   C:\Program Files\link-p2p\wintun.dll
   C:\Program Files\link-p2p\locales\…   (optional translations)
   ```

4. Visual C++ Redistributable only if you ship an MSVC-linked build that
   needs it (depends on how you cross-compile).

## Install / uninstall

```powershell
cd "C:\Program Files\link-p2p"

# Hub (default identity under %ProgramData%\link-p2p\identity.key)
.\link-p2p.exe tun service install --role hub

# Spoke
.\link-p2p.exe tun service install --role spoke --to <HubEndpointId>

.\link-p2p.exe tun service uninstall
```

`install` validates the system named-pipe SDDL, ensures
`%ProgramData%\link-p2p` is writable, registers **`link-p2p-tun`**, and
starts it. It also adds a **program-scoped** Windows Firewall inbound allow
rule named `link-p2p-tun` for this executable (not a global firewall disable).
Identity is kept on uninstall; the firewall rule is removed.

### SSH / RDP disconnect

After `tun service install`, the mesh runs under **LocalSystem** via SCM.
Closing the SSH/RDP session must not stop the service. Verify:

```powershell
Get-Service link-p2p-tun
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='link-p2p-tun']]]" -MaxEvents 10
# From another session / user:
.\link-p2p.exe tun status --system
```

Do **not** rely on a long-lived interactive console for production — use the
service install path.

Control plane (any local user can Status/Peers; Shutdown requires elevated
token via named-pipe impersonation):

```powershell
.\link-p2p.exe tun status --system
.\link-p2p.exe tun peers --system
.\link-p2p.exe tun down --system   # needs Administrator
```

## Environment

| Variable | Purpose |
|---|---|
| `LINK_P2P_PASSPHRASE` | Unlock / create passphrase-encrypted identity (min 8, max 1024 chars). Prefer this over CLI flags in the service account environment. |
| `LINK_P2P_LOCALEDIR` | Override catalog search path |

## Troubleshoot

| Symptom | What to check |
|---|---|
| **Service manager rejected the command** / OpenSCManager failed | Run elevated; `Get-Service link-p2p-tun` |
| **wintun.dll not found** | Place official DLL beside the exe; reinstall from a trusted path |
| **refusing to load wintun.dll from a temporary…** | Move install out of Temp/Downloads into Program Files |
| **Access Denied** / Shutdown fails | Elevate for `tun down --system` and service install |
| Service stuck Starting / silent crash | Event Viewer → Windows Logs → Application → source **`link-p2p-tun`** (startup and worker errors are logged there, not only to stderr) |
| Control: daemon not running | `.\link-p2p.exe tun status --system`; `Get-Service link-p2p-tun` |

Keep-alive: while Running, the service refreshes `SetServiceStatus` about
every 30 seconds so SCM notices a dead worker instead of waiting forever.

## Manual foreground (debug)

Without SCM (still elevated):

```powershell
.\link-p2p.exe tun up --foreground --system --role hub
```

Do **not** pass `--windows-service` yourself unless you are the SCM — that
flag only belongs on the registered service command line.
