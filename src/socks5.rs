//! Two things live here:
//!   1. A compact wire header (`Target` + read/write) sent as the first
//!      bytes of every QUIC stream in proxy mode, so `serve` knows where to
//!      dial. Reuses SOCKS5's own address-type encoding since it's already
//!      a well-defined compact format — no need to invent a new one.
//!   2. A minimal RFC 1928 SOCKS5 *server* handshake (no-auth, CONNECT only)
//!      that `connect --socks5-listen` speaks to local clients (browsers,
//!      tun2socks, curl --socks5, etc).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::i18n::{tr, tr_fmt};

#[derive(Debug, Clone)]
pub enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl Target {
    /// Resolve to a dialable SocketAddr. Domain names are resolved on the
    /// `serve` side (not by the SOCKS5 client) — this is what makes the
    /// proxy usable for hosts the connecting machine can't resolve itself
    /// (e.g. a remote-network-only DNS name), same as a real VPN.
    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            Target::Addr(a) => Ok(*a),
            Target::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
                .await
                .with_context(|| tr_fmt!("resolving {0}", host))?
                .next()
                .with_context(|| tr_fmt!("no addresses for {0}", host)),
        }
    }
}

// --- wire header on the QUIC stream --------------------------------------

pub async fn write_target<W: AsyncWrite + Unpin>(w: &mut W, t: &Target) -> Result<()> {
    match t {
        Target::Addr(SocketAddr::V4(a)) => {
            w.write_u8(1).await?;
            w.write_all(&a.ip().octets()).await?;
            w.write_u16(a.port()).await?;
        }
        Target::Addr(SocketAddr::V6(a)) => {
            w.write_u8(4).await?;
            w.write_all(&a.ip().octets()).await?;
            w.write_u16(a.port()).await?;
        }
        Target::Domain(host, port) => {
            if host.len() > 255 {
                bail!(tr_fmt!("domain name too long: {0} bytes", host.len()));
            }
            w.write_u8(3).await?;
            w.write_u8(host.len() as u8).await?;
            w.write_all(host.as_bytes()).await?;
            w.write_u16(*port).await?;
        }
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_target<R: AsyncRead + Unpin>(r: &mut R) -> Result<Target> {
    Ok(
        match r.read_u8().await.context(tr!("reading target header"))? {
            1 => {
                let mut ip = [0u8; 4];
                r.read_exact(&mut ip).await?;
                Target::Addr(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(ip)),
                    r.read_u16().await?,
                ))
            }
            4 => {
                let mut ip = [0u8; 16];
                r.read_exact(&mut ip).await?;
                Target::Addr(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(ip)),
                    r.read_u16().await?,
                ))
            }
            3 => {
                let len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                r.read_exact(&mut buf).await?;
                let host =
                    String::from_utf8(buf).context(tr!("non-utf8 domain in target header"))?;
                Target::Domain(host, r.read_u16().await?)
            }
            other => bail!(tr_fmt!("unknown address type {0} in target header", other)),
        },
    )
}

// --- local-facing SOCKS5 server (talks to browsers/apps) -----------------

/// Minimal RFC 1928 handshake: no-auth only, CONNECT only. On success the
/// SOCKS5 reply has already been sent and `tcp` is ready to pipe raw bytes.
///
/// SECURITY NOTE: no-auth means anything that can reach `--socks5-listen`
/// can proxy through it. Fine bound to 127.0.0.1; do not bind this to
/// 0.0.0.0 without adding username/password auth (SOCKS5 method 0x02) first.
pub async fn accept_handshake(tcp: &mut TcpStream) -> Result<Target> {
    let mut hdr = [0u8; 2];
    tcp.read_exact(&mut hdr)
        .await
        .context(tr!("reading SOCKS5 greeting"))?;
    if hdr[0] != 0x05 {
        bail!(tr_fmt!(
            "unsupported SOCKS version {0} (only SOCKS5 is supported)",
            hdr[0]
        ));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    tcp.read_exact(&mut methods).await?;
    tcp.write_all(&[0x05, 0x00])
        .await
        .context(tr!("sending SOCKS5 method selection"))?;

    let mut req = [0u8; 4];
    tcp.read_exact(&mut req)
        .await
        .context(tr!("reading SOCKS5 request"))?;
    if req[0] != 0x05 {
        bail!(tr_fmt!("bad SOCKS5 request version {0}", req[0]));
    }
    if req[1] != 0x01 {
        // BND reply code 0x07 = command not supported
        tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        bail!(tr_fmt!(
            "only CONNECT is supported (got command {0})",
            req[1]
        ));
    }

    let target = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await?;
            Target::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                tcp.read_u16().await?,
            ))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await?;
            Target::Addr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                tcp.read_u16().await?,
            ))
        }
        0x03 => {
            let len = tcp.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            tcp.read_exact(&mut buf).await?;
            let host = String::from_utf8(buf).context(tr!("non-utf8 domain in SOCKS5 request"))?;
            Target::Domain(host, tcp.read_u16().await?)
        }
        other => {
            tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .ok();
            bail!(tr_fmt!("unsupported address type {0}", other));
        }
    };

    // BND.ADDR/BND.PORT don't mean much for a relayed connection — echo
    // 0.0.0.0:0, which every real SOCKS5 client treats as "don't care".
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .context(tr!("sending SOCKS5 success reply"))?;
    Ok(target)
}
