//! Two things live here:
//!   1. A compact wire header (`Target` + read/write) sent as the first
//!      bytes of every QUIC stream in proxy mode, so `serve` knows where to
//!      dial. Reuses SOCKS5's own address-type encoding since it's already
//!      a well-defined compact format — no need to invent a new one.
//!   2. A minimal RFC 1928 SOCKS5 *server* handshake (no-auth, CONNECT only)
//!      that `connect --socks5-listen` speaks to local clients (browsers,
//!      tun2socks, curl --socks5, etc).
//!
//! Peer-input paths (`read_target`, `accept_handshake`) return [`Result`] —
//! malformed SOCKS/proxy headers must not panic the accept loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::i18n::{tr, tr_fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl Target {
    /// Resolve to a dialable SocketAddr. Domain names are resolved on the
    /// `serve` side (not by the SOCKS5 client) — this is what makes the
    /// proxy usable for hosts the connecting machine can't resolve itself
    /// (e.g. a remote-network-only DNS name), same as a real VPN.
    ///
    /// Uses the first address `lookup_host` returns (no multi-A retry). DNS
    /// is capped at [`DNS_RESOLVE_TIMEOUT`] so a hung resolver cannot stall
    /// the whole proxy accept loop.
    ///
    /// # DNS rebinding (callers must not resolve twice)
    ///
    /// SSRF safety for `serve --proxy` is enforced by types: resolve once,
    /// then [`crate::ssrf::check_proxy_target`] yields a [`crate::ssrf::CheckedTarget`]
    /// that [`crate::ssrf::dial_checked`] alone will connect. Prefer that path
    /// over calling `resolve` again between check and connect.
    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            Target::Addr(a) => Ok(*a),
            Target::Domain(host, port) => {
                let host = host.clone();
                let port = *port;
                let lookup = tokio::net::lookup_host((host.as_str(), port));
                let mut addrs = tokio::time::timeout(DNS_RESOLVE_TIMEOUT, lookup)
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(tr_fmt!(
                            "timed out resolving {0} after {1} seconds",
                            host,
                            DNS_RESOLVE_TIMEOUT.as_secs()
                        ))
                    })?
                    .with_context(|| tr_fmt!("resolving {0}", host))?;
                addrs
                    .next()
                    .with_context(|| tr_fmt!("no addresses for {0}", host))
            }
        }
    }
}

/// Cap for SOCKS5 domain → address resolution (see [`Target::resolve`]).
const DNS_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// --- wire header on the QUIC stream --------------------------------------

fn encode_target(buf: &mut Vec<u8>, t: &Target) -> Result<()> {
    match t {
        Target::Addr(SocketAddr::V4(a)) => {
            buf.push(1);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Addr(SocketAddr::V6(a)) => {
            buf.push(4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            if host.len() > 255 {
                bail!(tr_fmt!("domain name too long: {0} bytes", host.len()));
            }
            buf.push(3);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// Write the proxy-mode stream header.
///
/// Encodes into a stack/heap buffer and issues a single `write_all`. There is
/// deliberately **no** `.flush()` afterward: callers pass an unbuffered iroh
/// QUIC `SendStream`, where each write is already scheduled for the wire.
/// If a future caller wraps `W` in `BufWriter` (or similar), they must either
/// restore an explicit `flush()` here or flush themselves — otherwise the
/// header can sit in the buffer until it fills or the stream closes, which
/// looks like a hung handshake under light traffic.
pub async fn write_target<W: AsyncWrite + Unpin>(w: &mut W, t: &Target) -> Result<()> {
    let mut buf = Vec::with_capacity(270);
    encode_target(&mut buf, t)?;
    w.write_all(&buf).await?;
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
                if len > 255 {
                    bail!(tr!("domain length out of range in target header"));
                }
                let mut domain = [0u8; 255];
                r.read_exact(&mut domain[..len]).await?;
                let host = std::str::from_utf8(&domain[..len])
                    .context(tr!("non-utf8 domain in target header"))?
                    .to_owned();
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
///
/// No [`crate::ssrf`] check here on purpose: this is the *local* SOCKS5
/// entry (browser / tun2socks talking to `connect --socks5-listen`). The
/// SSRF guard applies on the `serve --proxy` side when the remote asks us
/// to dial (see `runtime::forward_one`). Filtering private ranges at this
/// local handshake would break the common "SOCKS into my LAN via P2P" case.
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
    // NMETHODS is a single u8 — allocation is bounded to ≤255 bytes. Do not
    // copy this pattern for length fields from larger integer types without a cap.
    // NMETHODS=0 → empty `methods` → no-auth not offered → 0xFF + bail (correct).
    let mut methods = vec![0u8; hdr[1] as usize];
    tcp.read_exact(&mut methods).await?;
    // RFC 1928 §3: the server must pick a method from the client's offered
    // list. We only speak no-auth (0x00); if the client didn't offer it,
    // reply 0xFF ("no acceptable method") and close instead of proceeding
    // with a method the client never agreed to. The bail after the reply is
    // for our caller (log / drop the TCP), not an extra wire message.
    if !methods.contains(&0x00) {
        tcp.write_all(&[0x05, 0xFF])
            .await
            .context(tr!("sending SOCKS5 method selection"))?;
        bail!(tr!("no acceptable SOCKS5 authentication method"));
    }
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
            if len > 255 {
                bail!(tr!("domain length out of range in SOCKS5 request"));
            }
            let mut domain = [0u8; 255];
            tcp.read_exact(&mut domain[..len]).await?;
            let host = std::str::from_utf8(&domain[..len])
                .context(tr!("non-utf8 domain in SOCKS5 request"))?
                .to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Pin English catalogs so assertions on error text stay stable under zh_CN.
    fn english_catalog() -> std::sync::MutexGuard<'static, ()> {
        crate::i18n::pin_english_catalog()
    }

    // --- wire header round-trips (no network) -----------------------------

    #[tokio::test]
    async fn target_round_trip_v4() {
        let t = Target::Addr("203.0.113.7:8080".parse().unwrap());
        let mut buf = Vec::new();
        write_target(&mut buf, &t).await.unwrap();
        assert_eq!(buf, [1, 203, 0, 113, 7, 0x1F, 0x90]);
        let mut slice: &[u8] = &buf;
        assert_eq!(read_target(&mut slice).await.unwrap(), t);
        assert!(slice.is_empty(), "no trailing bytes");
    }

    #[tokio::test]
    async fn target_round_trip_v6() {
        let t = Target::Addr("[2001:db8::1]:443".parse().unwrap());
        let mut buf = Vec::new();
        write_target(&mut buf, &t).await.unwrap();
        assert_eq!(buf[0], 4);
        assert_eq!(buf.len(), 1 + 16 + 2);
        let mut slice: &[u8] = &buf;
        assert_eq!(read_target(&mut slice).await.unwrap(), t);
        assert!(slice.is_empty());
    }

    #[tokio::test]
    async fn target_round_trip_domain() {
        let host = "internal-x.example";
        let t = Target::Domain(host.to_string(), 80);
        let mut buf = Vec::new();
        write_target(&mut buf, &t).await.unwrap();
        assert_eq!(buf[0], 3);
        assert_eq!(buf[1], host.len() as u8);
        let mut slice: &[u8] = &buf;
        assert_eq!(read_target(&mut slice).await.unwrap(), t);
        assert!(slice.is_empty());
    }

    #[tokio::test]
    async fn domain_longer_than_255_bytes_is_rejected() {
        let _guard = english_catalog();
        let t = Target::Domain("x".repeat(300), 80);
        let mut buf = Vec::new();
        let err = write_target(&mut buf, &t).await.unwrap_err();
        // Locale-independent: the error quotes the offending length.
        assert!(err.to_string().contains("300"));
    }

    #[tokio::test]
    async fn unknown_address_type_is_rejected() {
        let _guard = english_catalog();
        let mut buf: &[u8] = &[9, 1, 2, 3, 4, 0, 80];
        let err = read_target(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains('9'));
    }

    #[tokio::test]
    async fn truncated_header_is_an_error() {
        let mut buf: &[u8] = &[1, 0, 0]; // ATYP=1 but only 3 bytes of the 4-byte IP
        assert!(read_target(&mut buf).await.is_err());
    }

    // --- RFC 1928 handshake over real localhost TCP -----------------------

    /// Bind a listener, run `accept_handshake` on it in a task, return the
    /// client socket and the server's outcome.
    async fn handshake_pair() -> (TcpStream, tokio::task::JoinHandle<Result<Target>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            accept_handshake(&mut sock).await
        });
        let client = TcpStream::connect(addr).await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn handshake_ok_with_no_auth_and_v4_connect() {
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);

        c.write_all(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x1F, 0x90])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[0..2], &[0x05, 0x00]);
        assert_eq!(rep[3], 0x01); // ATYP echoed, BND.ADDR = 0.0.0.0

        let t = server.await.unwrap().unwrap();
        assert_eq!(t, Target::Addr("203.0.113.7:8080".parse().unwrap()));
    }

    #[tokio::test]
    async fn handshake_ok_with_domain_connect() {
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);

        let host = b"internal-x";
        c.write_all(&[0x05, 0x01, 0x00, 0x03, host.len() as u8])
            .await
            .unwrap();
        c.write_all(host).await.unwrap();
        c.write_all(&[0x00, 0x50]).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[0..2], &[0x05, 0x00]);

        let t = server.await.unwrap().unwrap();
        assert_eq!(t, Target::Domain("internal-x".to_string(), 80));
    }

    #[tokio::test]
    async fn no_auth_method_must_be_offered() {
        // Client only offers username/password (0x02): the server must reply
        // 0xFF (no acceptable method) and fail the handshake.
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0xFF]);
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn non_socks5_version_is_rejected() {
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn non_connect_command_gets_command_not_supported() {
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);

        // BIND (0x02), not CONNECT.
        c.write_all(&[0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[0..2], &[0x05, 0x07]); // 0x07 = command not supported
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unsupported_address_type_gets_reply_code_0x08() {
        let (mut c, server) = handshake_pair().await;
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();

        // ATYP 0x02 is not defined in SOCKS5.
        c.write_all(&[0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[0..2], &[0x05, 0x08]); // 0x08 = address type not supported
        assert!(server.await.unwrap().is_err());
    }
}
