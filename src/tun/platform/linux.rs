use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tun2::AbstractDevice;

use crate::i18n::{tr, tr_fmt};
use crate::tun::{OwnVips, VIP6_PREFIX, VIP_PREFIX};

use super::{vip6_already_taken_msg, vip_already_taken_msg, TunPlatform};

pub(crate) struct Linux;

/// Run `ip` with the given args, erroring with its stderr on failure.
fn run_ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| tr_fmt!("running `ip {0}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(tr_fmt!(
            "command `ip {0}` failed: {1}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

impl TunPlatform for Linux {
    /// Refuse to start if the derived/override VIP is already assigned to a local
    /// interface. The range choice (VIP_BASE) only dodges the conflicts we know
    /// about, so this check is the universal fallback against *any* third-party
    /// address collision — it stays even though collisions are rare.
    fn ensure_vip_free(vip: Ipv4Addr) -> Result<()> {
        let out = Command::new("ip")
            .args(["-o", "-4", "addr", "show"])
            .output()
            .context(tr!("checking local interfaces for the virtual IP"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // `-o` prints one line per address; matching on the padded token keeps
        // 172.24.0.2 from false-positiving on 172.24.0.20.
        let needle = format!(" inet {vip}/");
        if text.contains(&needle) {
            bail!(vip_already_taken_msg(vip));
        }
        Ok(())
    }

    fn ensure_vip6_free(vip: Ipv6Addr) -> Result<()> {
        let out = Command::new("ip")
            .args(["-o", "-6", "addr", "show"])
            .output()
            .context(tr!("checking local interfaces for the virtual IPv6"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = format!(" inet6 {vip}/");
        if text.contains(&needle) {
            bail!(vip6_already_taken_msg(vip));
        }
        Ok(())
    }

    /// Create the TUN interface, assign IPv4+IPv6 VIPs, set MTU and bring it up.
    ///
    /// Contract across platforms: L3 device, address = `v4`/32 + `v6`/128, up, MTU set.
    /// Peer host routes are installed later via [`add_peer_route`] (not at create
    /// time — the peer VIP is learned in the handshake).
    fn create_device(vips: OwnVips, mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
        let mut config = tun2::configure();
        config
            .tun_name("link-p2p%d") // kernel picks link-p2p0, link-p2p1, ...
            .layer(tun2::Layer::L3)
            .platform_config(|p| {
                p.ensure_root_privileges(false);
            });
        let device = tun2::create_as_async(&config)
            .with_context(|| tr!("creating TUN device (needs root / CAP_NET_ADMIN)"))?;
        let name = device
            .tun_name()
            .context(tr!("reading TUN interface name"))?;
        run_ip(&[
            "addr",
            "add",
            &format!("{}/32", vips.v4),
            "dev",
            &name,
        ])?;
        run_ip(&[
            "-6",
            "addr",
            "add",
            &format!("{}/128", vips.v6),
            "dev",
            &name,
        ])?;
        run_ip(&["link", "set", "dev", &name, "mtu", &mtu.to_string()])?;
        run_ip(&["link", "set", "dev", &name, "up"])?;
        Ok((device, name))
    }

    /// Point the peer's virtual IP at the tunnel.
    fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        // `replace` (not `add`) so a reconnecting peer updates the route instead
        // of erroring on "exists".
        run_ip(&[
            "route",
            "replace",
            &format!("{peer_vip}/32"),
            "dev",
            tun_name,
        ])?;
        run_ip(&[
            "-6",
            "route",
            "replace",
            &format!("{peer_vip6}/128"),
            "dev",
            tun_name,
        ])
    }

    /// Remove the peer's routes when a session ends, so a later peer with a
    /// different virtual IP doesn't leave stale routes on the TUN interface.
    /// Best-effort: a route that is already gone (or was never installed) must
    /// not fail the teardown.
    fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        let _ = run_ip(&["route", "del", &format!("{peer_vip}/32"), "dev", tun_name]);
        let _ = run_ip(&[
            "-6",
            "route",
            "del",
            &format!("{peer_vip6}/128"),
            "dev",
            tun_name,
        ]);
        Ok(())
    }

    /// Spoke-side: send the whole VIP /16 into the TUN so traffic for *any*
    /// mesh peer (not only the hub) is captured and sent to the hub for
    /// forwarding.
    fn add_mesh_route(tun_name: &str) -> Result<()> {
        run_ip(&["route", "replace", VIP_PREFIX, "dev", tun_name])?;
        run_ip(&["-6", "route", "replace", VIP6_PREFIX, "dev", tun_name])
    }

    fn del_mesh_route(tun_name: &str) -> Result<()> {
        run_ip(&["route", "del", VIP_PREFIX, "dev", tun_name])
    }

    /// Lower/raise the interface MTU to the connection's datagram ceiling.
    fn set_mtu(tun_name: &str, mtu: u16) -> Result<()> {
        run_ip(&["link", "set", "dev", tun_name, "mtu", &mtu.to_string()])
    }
}
