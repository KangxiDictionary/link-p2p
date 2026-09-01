use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

use crate::i18n::tr;
use crate::tun::OwnVips;

use super::TunPlatform;

pub(crate) struct Unsupported;

impl TunPlatform for Unsupported {
    fn ensure_vip_free(_vip: Ipv4Addr) -> Result<()> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }

    fn ensure_vip6_free(_vip: Ipv6Addr) -> Result<()> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }

    fn create_device(_vips: OwnVips, _mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }

    fn add_peer_route(
        _tun_name: &str,
        _peer_vip: Ipv4Addr,
        _peer_vip6: Ipv6Addr,
    ) -> Result<()> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }

    fn del_peer_route(_tun_name: &str, _peer_vip: Ipv4Addr, _peer_vip6: Ipv6Addr) -> Result<()> {
        Ok(())
    }

    fn add_mesh_route(_tun_name: &str) -> Result<()> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }

    fn del_mesh_route(_tun_name: &str) -> Result<()> {
        Ok(())
    }

    fn set_mtu(_tun_name: &str, _mtu: u16) -> Result<()> {
        bail!(tr!(
            "TUN mode supports Linux, macOS, and Windows only on this build"
        ))
    }
}
