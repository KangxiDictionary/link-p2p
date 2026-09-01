use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tun2::AbstractDevice;

use crate::i18n::{tr, tr_fmt};
use crate::tun::{OwnVips, VIP6_PREFIX, VIP_PREFIX};

use super::{vip6_already_taken_msg, vip_already_taken_msg, TunPlatform};

pub(crate) struct MacOs;

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

impl TunPlatform for MacOs {
    fn ensure_vip_free(vip: Ipv4Addr) -> Result<()> {
        let out = Command::new("ifconfig")
            .arg("-a")
            .output()
            .context(tr!("checking local interfaces for the virtual IP"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // ifconfig: "inet 172.24.0.1 netmask ..."
        let needle = format!("inet {vip} ");
        if text.contains(&needle) {
            bail!(vip_already_taken_msg(vip));
        }
        Ok(())
    }

    fn ensure_vip6_free(vip: Ipv6Addr) -> Result<()> {
        let out = Command::new("ifconfig")
            .arg("-a")
            .output()
            .context(tr!("checking local interfaces for the virtual IPv6"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = format!("inet6 {vip} ");
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
        // Leave tun_name unset so the kernel allocates the next free utunN.
        // destination=vip + /32 is the BSD point-to-point alias; peer host
        // routes are installed later via `route -n add -host`.
        let mut config = tun2::configure();
        config
            .address(vips.v4)
            .destination(vips.v4)
            .netmask(Ipv4Addr::new(255, 255, 255, 255))
            .mtu(mtu)
            .up()
            .layer(tun2::Layer::L3);
        let device = tun2::create_as_async(&config).with_context(|| {
            tr!("creating TUN device (needs root; macOS uses utun)")
        })?;
        let name = device
            .tun_name()
            .context(tr!("reading TUN interface name"))?;
        run_cmd(
            "ifconfig",
            &[&name, "inet6", &vips.v6.to_string(), "prefixlen", "128"],
        )?;
        Ok((device, name))
    }

    /// Point the peer's virtual IP at the tunnel.
    fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        let _ = run_cmd(
            "route",
            &["-n", "delete", "-host", &peer_vip.to_string()],
        );
        run_cmd(
            "route",
            &[
                "-n",
                "add",
                "-host",
                &peer_vip.to_string(),
                "-interface",
                tun_name,
            ],
        )?;
        let _ = run_cmd(
            "route",
            &["-n", "delete", "-inet6", &peer_vip6.to_string()],
        );
        run_cmd(
            "route",
            &[
                "-n",
                "add",
                "-inet6",
                &peer_vip6.to_string(),
                "-interface",
                tun_name,
            ],
        )
    }

    /// Remove the peer's routes when a session ends, so a later peer with a
    /// different virtual IP doesn't leave stale routes on the TUN interface.
    /// Best-effort: a route that is already gone (or was never installed) must
    /// not fail the teardown.
    fn del_peer_route(_tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()> {
        let _ = run_cmd("route", &["-n", "delete", "-host", &peer_vip.to_string()]);
        let _ = run_cmd(
            "route",
            &["-n", "delete", "-inet6", &peer_vip6.to_string()],
        );
        Ok(())
    }

    /// Spoke-side: send the whole VIP /16 into the TUN so traffic for *any*
    /// mesh peer (not only the hub) is captured and sent to the hub for
    /// forwarding.
    fn add_mesh_route(tun_name: &str) -> Result<()> {
        let _ = run_cmd("route", &["-n", "delete", "-net", VIP_PREFIX]);
        run_cmd(
            "route",
            &["-n", "add", "-net", VIP_PREFIX, "-interface", tun_name],
        )?;
        let _ = run_cmd("route", &["-n", "delete", "-inet6", VIP6_PREFIX]);
        run_cmd(
            "route",
            &[
                "-n",
                "add",
                "-inet6",
                VIP6_PREFIX,
                "-interface",
                tun_name,
            ],
        )
    }

    fn del_mesh_route(_tun_name: &str) -> Result<()> {
        run_cmd("route", &["-n", "delete", "-net", VIP_PREFIX])
    }

    /// Lower/raise the interface MTU to the connection's datagram ceiling.
    fn set_mtu(tun_name: &str, mtu: u16) -> Result<()> {
        run_cmd("ifconfig", &[tun_name, "mtu", &mtu.to_string()])
    }
}
