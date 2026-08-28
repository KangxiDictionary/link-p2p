//! SSRF guard for `serve --proxy`: peers must not make this node dial into
//! private / loopback / link-local ranges unless `--allow-private` is set.

use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Result};

use crate::i18n::tr_fmt;

/// Reject `target` when it resolves into a blocked range and private dials
/// are not allowed. Runs on the *resolved* address so domains cannot smuggle
/// a private IP past a hostname check.
pub(crate) fn check_proxy_target(target: SocketAddr, allow_private: bool) -> Result<()> {
    if !allow_private && is_blocked_target(target) {
        bail!(tr_fmt!(
            "target {0} is in a private/loopback/link-local range; blocked in proxy mode (use --allow-private to permit)",
            target
        ));
    }
    Ok(())
}

/// Loopback, RFC 1918 private, link-local, unspecified, multicast, broadcast
/// (v4); loopback, unspecified, multicast, ULA, link-local (v6).
pub(crate) fn is_blocked_target(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn proxy_target_ssrf_guard() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4("10.1.2.3".parse().unwrap()),
            IpAddr::V4("172.16.0.1".parse().unwrap()),
            IpAddr::V4("172.31.255.255".parse().unwrap()),
            IpAddr::V4("192.168.1.1".parse().unwrap()),
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
        assert!(check_proxy_target("127.0.0.1:80".parse().unwrap(), true).is_ok());
    }
}
