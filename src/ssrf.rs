//! SSRF guard for `serve --proxy`: peers must not make this node dial into
//! private / loopback / link-local ranges unless `--allow-private` is set.
//!
//! Classification always goes through [`IpAddr::to_canonical`] first so
//! IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is judged by the IPv4 rules. Extra
//! embedded-IPv4 forms (deprecated IPv4-compatible `::a.b.c.d`, NAT64
//! well-known, 6to4, Teredo) are unwrapped or blocked so a dual-stack peer
//! cannot smuggle a private v4 past the v6 branch.
//!
//! Dialing goes through [`CheckedTarget`]: resolve once → [`check_proxy_target`]
//! → [`dial_checked`]. That type-level path prevents DNS-rebinding TOCTOU
//! from a second `resolve` between check and connect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;

use crate::i18n::tr_fmt;

/// A [`SocketAddr`] that has already passed [`check_proxy_target`].
///
/// Opaque on purpose: callers dial via [`dial_checked`] (or [`Self::addr`] for
/// logging) and cannot "forget" the check by connecting a raw `SocketAddr`
/// from a fresh DNS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckedTarget(SocketAddr);

impl CheckedTarget {
    pub(crate) fn addr(self) -> SocketAddr {
        self.0
    }
}

/// Reject `target` when it resolves into a blocked range and private dials
/// are not allowed. Runs on the *resolved* address so domains cannot smuggle
/// a private IP past a hostname check.
///
/// On success returns a [`CheckedTarget`] — the only token accepted by
/// [`dial_checked`].
pub(crate) fn check_proxy_target(target: SocketAddr, allow_private: bool) -> Result<CheckedTarget> {
    if !allow_private && is_blocked_target(target) {
        bail!(tr_fmt!(
            "target {0} is in a private/loopback/link-local range; blocked in proxy mode (use --allow-private to permit)",
            target
        ));
    }
    Ok(CheckedTarget(target))
}

/// Connect using an address that already passed the SSRF guard.
pub(crate) async fn dial_checked(target: CheckedTarget) -> Result<TcpStream> {
    let addr = target.addr();
    TcpStream::connect(addr)
        .await
        .with_context(|| tr_fmt!("connecting to {0}", addr))
}

/// Loopback, RFC 1918 private, RFC 6598 CGNAT (`100.64.0.0/10`), link-local,
/// unspecified, multicast, broadcast (v4); loopback, unspecified, multicast,
/// ULA, link-local, and embedded-v4 tunnel forms (v6).
pub(crate) fn is_blocked_target(addr: SocketAddr) -> bool {
    is_blocked_ip(addr.ip())
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    // `::ffff:a.b.c.d` → V4(a.b.c.d). Native v6 left as-is.
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_ipv4(v6) {
                return is_blocked_v4(v4);
            }
            if is_teredo(v6) {
                // Client IPv4 is XOR-obfuscated in the last 32 bits; safer to
                // refuse the whole tunnel prefix than to mis-decode it.
                return true;
            }
            is_blocked_v6_native(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    // RFC 6598 CGNAT / shared address space (100.64.0.0/10). Not in
    // `Ipv4Addr::is_private()` but used by carriers and some cloud/VPN
    // fabrics (Tailscale also treats this range specially).
    let bits = u32::from(ip);
    let is_cgnat = (bits & 0xffc0_0000) == 0x6440_0000;
    // RFC 3068 6to4 relay anycast 192.88.99.0/24 (protocol largely dead, but
    // still a special-use block we refuse in proxy mode for symmetry with
    // other tunnel embeddings).
    let is_6to4_relay_anycast = (bits & 0xffff_ff00) == 0xc058_6300;
    // v4 needs an explicit broadcast check: 255.255.255.255 is not in
    // 224.0.0.0/4. v6 has no directed broadcast — multicast alone covers
    // the analogous "not a unicast peer" cases.
    ip.is_loopback()
        || ip.is_private()
        || is_cgnat
        || is_6to4_relay_anycast
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
}

fn is_blocked_v6_native(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
}

/// IPv4 embedded in a v6 address outside the `::ffff:0:0/96` mapped range
/// (already handled by [`IpAddr::to_canonical`]).
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    // Deprecated IPv4-compatible ::a.b.c.d (RFC 4291 §2.5.5.1). `to_canonical`
    // does not unwrap these. Skip :: and ::1 (unspecified / loopback).
    if s[0] == 0
        && s[1] == 0
        && s[2] == 0
        && s[3] == 0
        && s[4] == 0
        && s[5] == 0
        && !ip.is_unspecified()
        && !ip.is_loopback()
    {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }
    // 6to4 2002::/16 (RFC 3056): next 32 bits are the embedded IPv4.
    if s[0] == 0x2002 {
        return Some(ipv4_from_u16_pair(s[1], s[2]));
    }
    None
}

fn is_teredo(ip: Ipv6Addr) -> bool {
    // RFC 4380: Teredo prefix is 2001:0000::/32 (not 2001::/16).
    let s = ip.segments();
    s[0] == 0x2001 && s[1] == 0x0000
}

fn ipv4_from_u16_pair(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_target_ssrf_guard() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4("10.1.2.3".parse().unwrap()),
            IpAddr::V4("172.16.0.1".parse().unwrap()),
            IpAddr::V4("172.31.255.255".parse().unwrap()),
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            IpAddr::V4("100.64.0.1".parse().unwrap()),
            IpAddr::V4("100.127.255.255".parse().unwrap()),
            IpAddr::V4("169.254.169.254".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4("224.0.0.1".parse().unwrap()),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fd12:3456::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
        ] {
            assert!(
                is_blocked_target(SocketAddr::new(ip, 80)),
                "{ip} should be blocked"
            );
        }
        for ip in [
            IpAddr::V4("8.8.8.8".parse().unwrap()),
            IpAddr::V4("203.0.113.7".parse().unwrap()),
            IpAddr::V4("100.63.255.255".parse().unwrap()), // just below CGNAT
            IpAddr::V4("100.128.0.1".parse().unwrap()),    // just above CGNAT
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            assert!(
                !is_blocked_target(SocketAddr::new(ip, 80)),
                "{ip} should pass"
            );
        }
        assert!(check_proxy_target("127.0.0.1:80".parse().unwrap(), false).is_err());
        assert!(check_proxy_target("10.0.0.1:80".parse().unwrap(), false).is_err());
        assert!(check_proxy_target("8.8.8.8:80".parse().unwrap(), false).is_ok());
        assert_eq!(
            check_proxy_target("8.8.8.8:80".parse().unwrap(), false)
                .unwrap()
                .addr(),
            "8.8.8.8:80".parse().unwrap()
        );
        assert!(check_proxy_target("127.0.0.1:80".parse().unwrap(), true).is_ok());

        // Port 0 is not an SSRF concern (connect will fail later); we only
        // classify the IP. Public IP + port 0 must pass the guard.
        assert!(!is_blocked_target("8.8.8.8:0".parse().unwrap()));
        assert!(check_proxy_target("8.8.8.8:0".parse().unwrap(), false).is_ok());

        // 6to4 relay anycast (RFC 3068).
        assert!(is_blocked_ip(IpAddr::V4(
            "192.88.99.1".parse().unwrap()
        )));
        assert!(is_blocked_ip(IpAddr::V4(
            "192.88.99.255".parse().unwrap()
        )));
    }

    #[test]
    fn ipv4_mapped_and_embedded_blocked() {
        // Classic SSRF bypass: IPv4-mapped loopback / RFC1918.
        let mapped_loop = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let mapped_priv = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        let mapped_ll = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
        let mapped_pub = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());
        assert!(is_blocked_ip(mapped_loop));
        assert!(is_blocked_ip(mapped_priv));
        assert!(is_blocked_ip(mapped_ll));
        assert!(!is_blocked_ip(mapped_pub));

        // NAT64 well-known: 64:ff9b::10.0.0.1
        let nat64_priv: Ipv6Addr = "64:ff9b::a00:1".parse().unwrap();
        let nat64_pub: Ipv6Addr = "64:ff9b::808:808".parse().unwrap();
        assert!(is_blocked_ip(IpAddr::V6(nat64_priv)));
        assert!(!is_blocked_ip(IpAddr::V6(nat64_pub)));

        // 6to4 with embedded 10.0.0.1 → 2002:0a00:0001::
        let sixto4_priv: Ipv6Addr = "2002:0a00:0001::1".parse().unwrap();
        assert!(is_blocked_ip(IpAddr::V6(sixto4_priv)));

        // Teredo prefix — blocked wholesale.
        let teredo: Ipv6Addr = "2001:0:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap();
        assert!(is_blocked_ip(IpAddr::V6(teredo)));

        // Deprecated IPv4-compatible ::a.b.c.d (not the mapped ::ffff: form).
        let compat_priv = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_compatible();
        let compat_pub = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_compatible();
        assert_eq!(compat_priv, "::a00:1".parse::<Ipv6Addr>().unwrap());
        assert!(is_blocked_ip(IpAddr::V6(compat_priv)));
        assert!(!is_blocked_ip(IpAddr::V6(compat_pub)));
        // :: and ::1 must stay on the native v6 path (still blocked, but not
        // via "embedded 0.0.0.0 / 0.0.0.1").
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
