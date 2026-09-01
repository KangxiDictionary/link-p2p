use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;

use crate::i18n::tr_fmt;
use crate::tun::OwnVips;

pub(crate) trait TunPlatform {
    fn ensure_vip_free(vip: Ipv4Addr) -> Result<()>;
    fn ensure_vip6_free(vip: Ipv6Addr) -> Result<()>;
    fn create_device(vips: OwnVips, mtu: u16) -> Result<(tun2::AsyncDevice, String)>;
    fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()>;
    fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr, peer_vip6: Ipv6Addr) -> Result<()>;
    fn add_mesh_route(tun_name: &str) -> Result<()>;
    fn del_mesh_route(tun_name: &str) -> Result<()>;
    fn set_mtu(tun_name: &str, mtu: u16) -> Result<()>;
}

pub(crate) fn vip_already_taken_msg(vip: Ipv4Addr) -> String {
    tr_fmt!(
        "virtual IP {0} is already assigned to a local interface",
        vip
    )
}

pub(crate) fn vip6_already_taken_msg(vip: Ipv6Addr) -> String {
    tr_fmt!(
        "virtual IPv6 {0} is already assigned to a local interface",
        vip
    )
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) type Os = linux::Linux;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) type Os = macos::MacOs;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) type Os = windows::Windows;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) type Os = unsupported::Unsupported;

#[cfg(windows)]
pub(crate) use windows::wintun_dll_selftest_path;
