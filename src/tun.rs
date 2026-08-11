//! TUN mode: whole-machine IP reachability over QUIC datagrams.
//!
//! `serve`/`connect` forward one TCP port. This module instead bridges two
//! entire machines at the IP layer: one TUN interface, one /32 route to the
//! peer, and every packet (TCP/UDP/ICMP) crossing the tunnel as an
//! *unreliable* QUIC datagram — reliability is the inner protocol's job.
//!
//! Implements v1 of docs/tun-design.md: point-to-point, Linux only,
//! no mesh/ACL/discovery, `serve`/`connect` untouched. Requires root /
//! CAP_NET_ADMIN (unlike the stream modes).

use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::process::Command;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use tracing::{info, warn};
#[cfg(target_os = "linux")]
use tun2::AbstractDevice;

use crate::i18n::{tr, tr_fmt};
use crate::style::Styler;

/// ALPN for TUN mode. Distinct from the stream-forwarding ALPN so a `tun`
/// peer and a `serve --forward` peer can't handshake into the wrong protocol.
pub const TUN_ALPN: &[u8] = b"link-p2p/tun/0";

/// 100.64.0.0/10 — RFC 6598 carrier-grade NAT space. CGNAT space keeps the
/// virtual addresses out of the way of typical LANs (and of Tailscale, which
/// uses the same space — hence the startup collision check below).
const VIP_BASE: u32 = 0x6440_0000; // 100.64.0.0
const VIP_HOST_BITS: u32 = 0x003F_FFFF; // low 22 bits of the hash

/// Derive this node's virtual IP from its EndpointId.
///
/// `0x6440_0000 | (BLAKE3(endpoint_id) & 0x003F_FFFF)` — deterministic, so
/// both sides can compute both addresses from the EndpointIds they already
/// hold, with no coordination server (design decision 1). 22 host bits ≈ 4M
/// addresses; point-to-point collision probability is negligible, and the
/// local-interface check catches the cases that do collide.
pub fn derive_vip(endpoint_id: EndpointId) -> Ipv4Addr {
    let hash = blake3::hash(endpoint_id.as_bytes());
    let raw = u32::from_be_bytes([
        hash.as_bytes()[0],
        hash.as_bytes()[1],
        hash.as_bytes()[2],
        0,
    ]);
    Ipv4Addr::from(VIP_BASE | (raw & VIP_HOST_BITS))
}

/// `--mtu` is an upper bound, never a licence to raise the ceiling: anything
/// above 1280 would risk outer-path fragmentation (design decision 2 — 1500
/// is the classic "connects fine, then crawls" failure mode).
pub fn validate_mtu(mtu: u16) -> Result<()> {
    if mtu > 1280 {
        bail!(tr_fmt!(
            "--mtu must be at most 1280 (got {0}); higher values would fragment the outer QUIC datagrams",
            mtu
        ));
    }
    Ok(())
}

/// The final TUN MTU: the user's `--mtu` bound, clamped down to what the
/// negotiated QUIC datagram path can actually carry.
///
/// Fails closed: if datagrams weren't negotiated on this connection, TUN
/// mode cannot work at all — refusing beats silently falling back to a
/// stream-based transport, which would reintroduce head-of-line blocking.
fn choose_mtu(user_mtu: u16, conn: &Connection) -> Result<u16> {
    let max_dgram = conn.max_datagram_size().context(tr!(
        "the peer or path does not support QUIC datagrams; TUN mode cannot work over this connection.\n\
         Refusing to start rather than silently falling back to a stream transport."
    ))?;
    let mtu = std::cmp::min(user_mtu, max_dgram as u16);
    info!("choose_mtu({user_mtu}, {max_dgram}) = {mtu}");
    Ok(mtu)
}

// ---------------------------------------------------------------------------
// Local interface setup (Linux). tun2 only opens /dev/net/tun; everything
// else goes through the `ip` command so failures produce readable errors.
// Dropping the AsyncDevice deletes the interface (and its addresses/routes),
// so there's no explicit cleanup path.
// ---------------------------------------------------------------------------

/// Run `ip` with the given args, erroring with its stderr on failure.
#[cfg(target_os = "linux")]
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

/// Refuse to start if the derived/override VIP is already assigned to a local
/// interface (e.g. Tailscale's own 100.x address). Deterministic derivation
/// makes collisions rare but real — see design decision 1.
#[cfg(target_os = "linux")]
fn ensure_vip_free(vip: Ipv4Addr) -> Result<()> {
    let out = Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .context(tr!("checking local interfaces for the virtual IP"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // `-o` prints one line per address; matching on the padded token keeps
    // 100.64.1.2 from false-positiving on 100.64.1.20.
    let needle = format!(" inet {vip}/");
    if text.contains(&needle) {
        bail!(tr_fmt!(
            "virtual IP {0} is already assigned to a local interface.\n\
             Pick a different one with --tun-ip.",
            vip
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_vip_free(_vip: Ipv4Addr) -> Result<()> {
    bail!(tr!("TUN mode currently supports Linux only"))
}

/// Create the TUN interface, assign `vip`, set MTU and bring it up.
///
/// tun2 only does TUNSETIFF with IFF_TUN|IFF_NO_PI (raw IP packets); with
/// `ensure_root_privileges` off it skips its own ioctl configure, so address/
/// MTU/up go through `ip` — one code path, readable errors. Returns the
/// device (keep it alive: dropping it deletes the interface) and its
/// kernel-assigned name (needed for the later `ip route` calls).
#[cfg(target_os = "linux")]
fn create_tun_device(vip: Ipv4Addr, mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
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
    run_ip(&["addr", "add", &format!("{vip}/32"), "dev", &name])?;
    run_ip(&["link", "set", "dev", &name, "mtu", &mtu.to_string()])?;
    run_ip(&["link", "set", "dev", &name, "up"])?;
    Ok((device, name))
}

#[cfg(not(target_os = "linux"))]
fn create_tun_device(_vip: Ipv4Addr, _mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
    bail!(tr!("TUN mode currently supports Linux only"))
}

/// Point the peer's virtual IP at the tunnel. `replace` (not `add`) so a
/// reconnecting peer updates the route instead of erroring on "exists".
#[cfg(target_os = "linux")]
fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr) -> Result<()> {
    run_ip(&[
        "route",
        "replace",
        &format!("{peer_vip}/32"),
        "dev",
        tun_name,
    ])
}

#[cfg(not(target_os = "linux"))]
fn add_peer_route(_tun_name: &str, _peer_vip: Ipv4Addr) -> Result<()> {
    bail!(tr!("TUN mode currently supports Linux only"))
}

/// Lower the interface MTU to the connection's datagram ceiling. `serve`
/// creates the device before the connection exists, so it clamps down here
/// once the peer's negotiated max is known.
#[cfg(target_os = "linux")]
fn set_tun_mtu(tun_name: &str, mtu: u16) -> Result<()> {
    run_ip(&["link", "set", "dev", tun_name, "mtu", &mtu.to_string()])
}

#[cfg(not(target_os = "linux"))]
fn set_tun_mtu(_tun_name: &str, _mtu: u16) -> Result<()> {
    bail!(tr!("TUN mode currently supports Linux only"))
}

// ---------------------------------------------------------------------------
// The datagram pump.
// ---------------------------------------------------------------------------

/// How a TUN session ended, so the caller can distinguish "user pressed
/// Ctrl+C" (tear everything down) from "peer went away" (serve may keep
/// accepting a new peer).
enum SessionEnd {
    CtrlC,
    PeerGone,
}

/// Pump IP packets between the TUN interface and the peer's QUIC connection.
///
/// One inner IP packet = one QUIC datagram, deliberately *unreliable*:
/// loss/reordering are left to the inner protocol (TCP retransmits, UDP
/// doesn't care), matching what a real network link does. A reliable stream
/// transport would stack a second retransmission layer under the first and
/// reintroduce head-of-line blocking — one dropped packet stalling every
/// later one.
///
/// `send_datagram_wait` (not `send_datagram`) so congestion backpressures
/// into the TUN read loop instead of silently dropping inner packets: with
/// drops, inner TCP would just retransmit into the same full buffer forever.
async fn run_datagram_loop(
    tun: &tun2::AsyncDevice,
    conn: &Connection,
    mtu: u16,
    peer: EndpointId,
    styler: Styler,
) -> Result<SessionEnd> {
    let mut buf = vec![0u8; mtu as usize + 64];
    loop {
        tokio::select! {
            r = tun.recv(&mut buf) => {
                let n = r.context(tr!("reading packet from TUN device"))?;
                let pkt = Bytes::copy_from_slice(&buf[..n]);
                if let Err(e) = conn.send_datagram_wait(pkt).await {
                    warn!(%peer, error = %e, "{}", tr!("sending datagram to peer failed"));
                    return Ok(SessionEnd::PeerGone);
                }
            }
            r = conn.read_datagram() => {
                match r {
                    Ok(data) => {
                        tun.send(&data[..])
                            .await
                            .context(tr!("writing packet to TUN device"))?;
                    }
                    Err(e) => {
                        info!(%peer, error = %e, "{}", tr!("peer disconnected"));
                        return Ok(SessionEnd::PeerGone);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("{}", styler.warn(&tr!("shutting down...")));
                return Ok(SessionEnd::CtrlC);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

/// Exposed side (`tun serve`): accept one peer at a time and bridge this
/// machine to it. The collision check and device creation happen before we
/// accept anything, so a startup problem is reported immediately rather than
/// after a peer has already dialed.
pub async fn run_tun_serve(
    secret_key: SecretKey,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: Option<&str>,
    styler: Styler,
) -> Result<()> {
    let endpoint = crate::build_endpoint(secret_key, relay)?
        .alpns(vec![TUN_ALPN.to_vec()])
        .bind()
        .await
        .context(tr!("binding endpoint"))?;

    let own_id = endpoint.id();
    let own_vip = tun_ip.unwrap_or_else(|| derive_vip(own_id));
    // Collision check first (needs no network): a taken address should be
    // reported before we spend up to 30s waiting to come online.
    ensure_vip_free(own_vip)?;
    crate::wait_online(&endpoint).await?;
    let (tun, tun_name) = create_tun_device(own_vip, mtu)?;

    println!("{}", styler.banner("link-p2p tun serve"));
    println!(
        "  {}",
        styler.dim(&tr!("your virtual IP (the peer reaches you here):"))
    );
    println!("    {}", styler.highlight(&own_vip.to_string()));
    println!(
        "  {}",
        styler.dim(&tr!(
            "your EndpointId (give this to peers running `tun connect --to`):"
        ))
    );
    println!("    {}", styler.highlight(&own_id.to_string()));
    println!();
    println!("{}", styler.dim(&tr!("Press Ctrl+C to stop.")));

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    bail!(tr!("endpoint closed"));
                };
                // Errors here are usually garbage packets hitting the UDP
                // socket, not app problems — log and keep listening.
                let accepting = match incoming.accept() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "{}", tr!("rejecting malformed incoming connection"));
                        continue;
                    }
                };
                let conn = accepting
                    .await
                    .context(tr!("completing connection handshake"))?;
                let peer = conn.remote_id();
                let peer_vip = derive_vip(peer);
                info!(%peer, "{}", tr!("TUN session established"));

                let result = async {
                    add_peer_route(&tun_name, peer_vip)?;
                    let mtu = choose_mtu(mtu, &conn)?;
                    set_tun_mtu(&tun_name, mtu)?;
                    // Observability for the MTU-symmetry question: max_datagram_size
                    // is a per-end value (local path MTU estimate + peer-advertised
                    // limit), so the two sides' numbers may legitimately differ —
                    // e.g. different egress interface MTUs. That alone is harmless:
                    // both sides' tun MTU is capped at the same 1280. The dangerous
                    // signal is either side BELOW 1280 — that side's tun MTU is
                    // smaller than the peer's, and the peer's oversize sends get
                    // silently dropped at this side's tun write (this side's own
                    // sends are fine, they're clamped to its own smaller max).
                    info!(%peer, "{}", tr_fmt!(
                        "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
                        conn.max_datagram_size().unwrap_or_default(),
                        mtu
                    ));
                    run_datagram_loop(&tun, &conn, mtu, peer, styler).await
                }
                .await;

                match result {
                    Ok(SessionEnd::CtrlC) => break,
                    Ok(SessionEnd::PeerGone) => { /* keep accepting */ }
                    Err(e) => warn!(%peer, error = %e, "{}", tr!("TUN session error")),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("{}", styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }
    Ok(())
}

/// Connecting side (`tun connect`): dial the peer, then bridge this machine
/// to it at the IP layer.
pub async fn run_tun_connect(
    secret_key: SecretKey,
    to: &str,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: Option<&str>,
    styler: Styler,
) -> Result<()> {
    let endpoint = crate::build_endpoint(secret_key, relay)?
        .bind()
        .await
        .context(tr!("binding endpoint"))?;

    let peer_id: EndpointId = to
        .parse()
        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId", to))?;
    let own_id = endpoint.id();
    let own_vip = tun_ip.unwrap_or_else(|| derive_vip(own_id));
    let peer_vip = derive_vip(peer_id);
    // Collision check first (needs no network): fail fast on a taken address.
    ensure_vip_free(own_vip)?;
    crate::wait_online(&endpoint).await?;

    let dial_addr = match relay {
        // With a custom relay we know exactly where the peer is: dial it
        // through this relay, no DNS/pkarr lookup needed.
        Some(relay_url) => {
            let relay_url = relay_url
                .parse()
                .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
            EndpointAddr::new(peer_id).with_relay_url(relay_url)
        }
        // Default path: rely on n0's address discovery (DNS/pkarr) to find
        // where the peer is.
        None => EndpointAddr::from(peer_id),
    };

    println!("{}", styler.info(&tr_fmt!("dialing {0}...", peer_id)));
    let conn = endpoint
        .connect(dial_addr, TUN_ALPN)
        .await
        .context(tr!("connecting to remote endpoint"))?;

    // Fail closed on datagram support before creating any interface.
    let mtu = choose_mtu(mtu, &conn)?;
    let (tun, tun_name) = create_tun_device(own_vip, mtu)?;
    add_peer_route(&tun_name, peer_vip)?;
    // Same observability line as `tun serve`: compare this across both machines
    // to check the MTU-symmetry assumption (see the comment in run_tun_serve).
    info!(%peer_id, "{}", tr_fmt!(
        "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
        conn.max_datagram_size().unwrap_or_default(),
        mtu
    ));

    println!(
        "{}",
        styler.ok(&tr_fmt!("connected. your virtual IP: {0}", own_vip))
    );
    println!(
        "{}",
        styler.dim(&tr_fmt!(
            "peer {0} is reachable at {1}",
            peer_id.fmt_short(),
            peer_vip
        ))
    );
    println!("{}", styler.dim(&tr!("Press Ctrl+C to stop.")));

    match run_datagram_loop(&tun, &conn, mtu, peer_id, styler).await? {
        SessionEnd::CtrlC => {}
        SessionEnd::PeerGone => {
            println!("{}", styler.warn(&tr!("peer disconnected, exiting...")));
        }
    }
    Ok(())
}
