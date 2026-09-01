use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tun2::AbstractDevice;
use tracing::warn;

use crate::i18n::{tr, tr_fmt};
use crate::tun::{OwnVips, VIP_PREFIX};

use super::{vip6_already_taken_msg, vip_already_taken_msg, TunPlatform};

pub(crate) struct Windows;

fn run_cmd(bin: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| tr_fmt!("running `{0} {1}`", bin, args.join(" ")))?;
    if !out.status.success() {
        let err = if out.stderr.is_empty() {
            String::from_utf8_lossy(&out.stdout)
        } else {
            String::from_utf8_lossy(&out.stderr)
        };
        bail!(tr_fmt!(
            "command `{0} {1}` failed: {2}",
            bin,
            args.join(" "),
            err.trim()
        ));
    }
    Ok(())
}

impl TunPlatform for Windows {
    fn ensure_vip_free(vip: Ipv4Addr) -> Result<()> {
        let vip_s = vip.to_string();
        // Prefer one-IP-per-line from Get-NetIPAddress (no gateway/DNS false hits).
        // Only trust a successful run that listed at least one address: SilentlyContinue
        // can yield exit 0 with empty stdout when the cmdlet fails, which would
        // otherwise look like "no conflict".
        if let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }",
            ])
            .output()
        {
            if out.status.success() {
                // Own the lossy conversion so line slices can live past the statement.
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                let ips: Vec<&str> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                if !ips.is_empty() {
                    if ips.iter().any(|ip| *ip == vip_s) {
                        bail!(vip_already_taken_msg(vip));
                    }
                    return Ok(());
                }
            }
        }
        // Fallback: only parse "IP Address" value fields from netsh (not gateways).
        let out = Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .output()
            .context(tr!("checking local interfaces for the virtual IP"))?;
        let taken = String::from_utf8_lossy(&out.stdout).lines().any(|line| {
            let lower = line.to_ascii_lowercase();
            // English netsh: "IP Address:                 192.168.1.1"
            if !lower.contains("ip address") {
                return false;
            }
            line.rsplit(':')
                .next()
                .is_some_and(|v| v.trim() == vip_s)
        });
        if taken {
            bail!(vip_already_taken_msg(vip));
        }
        Ok(())
    }

    fn ensure_vip6_free(vip: Ipv6Addr) -> Result<()> {
        let vip_s = vip.to_string();
        if let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }",
            ])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                let ips: Vec<&str> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                if !ips.is_empty() {
                    if ips.iter().any(|ip| *ip == vip_s) {
                        bail!(vip6_already_taken_msg(vip));
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Create the TUN interface, assign IPv4+IPv6 VIPs, set MTU and bring it up.
    ///
    /// Contract across platforms: L3 device, address = `v4`/32 + `v6`/128, up, MTU set.
    /// Peer host routes are installed later via [`add_peer_route`] (not at create
    /// time — the peer VIP is learned in the handshake).
    fn create_device(vips: OwnVips, mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
        // Always load the DLL next to this exe — relative "wintun.dll" would
        // search PATH and can pick up an unsigned copy (→ "The file is not signed").
        let dll = wintun_dll_beside_exe()?;
        let mut config = tun2::configure();
        config
            .tun_name("link-p2p")
            .address(vips.v4)
            .netmask(Ipv4Addr::new(255, 255, 255, 255))
            .mtu(mtu)
            .up()
            .layer(tun2::Layer::L3)
            .platform_config(|p| {
                p.wintun_file(&dll);
            });
        let device = tun2::create_as_async(&config).with_context(|| {
            tr_fmt!(
                "creating TUN device failed (needs Administrator).\n\
                 Use the official signed wintun.dll from https://www.wintun.net/ \
                 (amd64 for 64-bit), placed next to this executable:\n\
                   {0}\n\
                 \"The file is not signed\" means Windows rejected the DLL signature — \
                 replace a wrong/unsigned/PATH-shadowed copy with the official one.",
                dll.display()
            )
        })?;
        let name = device
            .tun_name()
            .context(tr!("reading TUN interface name"))?;
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "address",
                &name,
                &vips.v6.to_string(),
                "store=active",
            ])
            .output();
        Ok((device, name))
    }

    /// Point the peer's virtual IP at the tunnel.
    fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        // Prefer netsh on-link route via the Wintun interface name. Using the local
        // VIP as a `route add` gateway often installs a route that never selects
        // the Wintun adapter — ICMP then blackholes even though the session is up.
        let peer = format!("{peer_vip}/32");
        let add_netsh = || {
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    peer.as_str(),
                    tun_name,
                    "store=active",
                ],
            )
        };
        if add_netsh().is_err() {
            let _ = run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    peer.as_str(),
                    tun_name,
                ],
            );
            add_netsh()?;
        }
        let peer6 = format!("{peer_vip6}/128");
        let add6 = || {
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    peer6.as_str(),
                    tun_name,
                    "store=active",
                ],
            )
        };
        if add6().is_err() {
            let _ = run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "delete",
                    "route",
                    peer6.as_str(),
                    tun_name,
                ],
            );
            let _ = add6();
        }
        Ok(())
    }

    /// Remove the peer's routes when a session ends, so a later peer with a
    /// different virtual IP doesn't leave stale routes on the TUN interface.
    /// Best-effort: a route that is already gone (or was never installed) must
    /// not fail the teardown.
    fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("{peer_vip}/32"),
                tun_name,
            ],
        );
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "route",
                &format!("{peer_vip6}/128"),
                tun_name,
            ],
        );
        Ok(())
    }

    /// Spoke-side: send the whole VIP /16 into the TUN so traffic for *any*
    /// mesh peer (not only the hub) is captured and sent to the hub for
    /// forwarding.
    fn add_mesh_route(tun_name: &str) -> Result<()> {
        let add = || {
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    VIP_PREFIX,
                    tun_name,
                    "store=active",
                ],
            )
        };
        if add().is_ok() {
            return Ok(());
        }
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "delete",
                "route",
                VIP_PREFIX,
                tun_name,
            ],
        );
        add()
    }

    fn del_mesh_route(tun_name: &str) -> Result<()> {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "delete",
                "route",
                VIP_PREFIX,
                tun_name,
            ],
        )
    }

    /// Lower/raise the interface MTU to the connection's datagram ceiling.
    fn set_mtu(tun_name: &str, mtu: u16) -> Result<()> {
        // Wintun's ring accepts huge packets; ask the IPv4 stack to advertise a
        // lower interface MTU so local TCP can learn without relying solely on
        // ICMP Frag Needed (Windows firewalls sometimes drop injected ICMP).
        // Best-effort: failure must not tear the tunnel down.
        let mtu_arg = format!("mtu={mtu}");
        if let Err(e) = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                tun_name,
                &mtu_arg,
                "store=active",
            ],
        ) {
            warn!(
                error = %e,
                "{}",
                tr!("could not set Windows interface MTU via netsh; relying on ICMP PMTUD injection")
            );
        }
        Ok(())
    }
}

/// Resolve `wintun.dll` beside `link-p2p.exe` (not via PATH).
///
/// Hardening: canonicalize the executable directory and refuse Temporary /
/// Downloads-style locations where a planted DLL is a realistic attack. The
/// intended install layout is `Program Files\link-p2p\link-p2p.exe` + sibling
/// `wintun.dll` (service install already rejects user-writable binary paths).
pub(crate) fn wintun_dll_selftest_path() -> Result<std::path::PathBuf> {
    wintun_dll_beside_exe()
}

/// Resolve `wintun.dll` beside `link-p2p.exe` (not via PATH).
///
/// Hardening: canonicalize the executable directory and refuse Temporary /
/// Downloads-style locations where a planted DLL is a realistic attack. The
/// intended install layout is `Program Files\link-p2p\link-p2p.exe` + sibling
/// `wintun.dll` (service install already rejects user-writable binary paths).
fn wintun_dll_beside_exe() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context(tr!("resolving path to this executable"))?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let dir = exe
        .parent()
        .context(tr!("resolving directory of this executable"))?
        .to_path_buf();

    if is_untrusted_wintun_dir(&dir) {
        bail!(tr_fmt!(
            "refusing to load wintun.dll from a temporary or download directory ({0}); \
             install link-p2p to a trusted path (e.g. Program Files) with the official signed DLL beside the executable",
            dir.display().to_string()
        ));
    }

    let dll = dir.join("wintun.dll");
    if !dll.is_file() {
        bail!(tr_fmt!(
            "wintun.dll not found next to this executable:\n\
               {0}\n\
             Download the official signed build from https://www.wintun.net/ \
             (use the amd64 folder on 64-bit Windows) and copy wintun.dll here.",
            dll.display()
        ));
    }
    // Prefer the canonical path so LoadLibrary sees a resolved location.
    Ok(std::fs::canonicalize(&dll).unwrap_or(dll))
}

/// Paths where a co-located DLL is untrusted (writable by the user who also
/// runs elevated TUN). Program Files / Windows are *trusted* for our layout.
fn is_untrusted_wintun_dir(dir: &std::path::Path) -> bool {
    let lower = dir.to_string_lossy().to_ascii_lowercase();
    let markers = [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "/temp/",
        "/tmp/",
        "/downloads/",
    ];
    if markers.iter().any(|m| lower.contains(m)) {
        return true;
    }
    for key in ["TEMP", "TMP"] {
        if let Ok(t) = std::env::var(key) {
            let t = std::path::PathBuf::from(t);
            if let Ok(canon) = std::fs::canonicalize(&t) {
                if dir.starts_with(&canon) {
                    return true;
                }
            } else if dir.starts_with(&t) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod wintun_path_tests {
    use super::is_untrusted_wintun_dir;
    use std::path::Path;

    #[test]
    fn program_files_is_trusted() {
        assert!(!is_untrusted_wintun_dir(Path::new(
            r"C:\Program Files\link-p2p"
        )));
    }

    #[test]
    fn temp_is_untrusted() {
        assert!(is_untrusted_wintun_dir(Path::new(
            r"C:\Users\alice\AppData\Local\Temp\link-p2p"
        )));
        assert!(is_untrusted_wintun_dir(Path::new(
            r"C:\Users\alice\Downloads\link-p2p"
        )));
    }
}
