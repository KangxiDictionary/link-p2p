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
use tokio::time::{self, Duration};
use tracing::{info, warn};
#[cfg(target_os = "linux")]
use tun2::AbstractDevice;

use crate::i18n::{tr, tr_fmt};
use crate::style::Styler;

/// ALPN for TUN mode. Versioned: "1" added the one-shot VIP exchange stream;
/// a "0" peer would install a route to the wrong address, so a version
/// mismatch must fail the handshake rather than misroute. Distinct from the
/// stream-forwarding ALPN so a `tun` peer and a `serve --forward` peer can't
/// handshake into the wrong protocol either.
pub const TUN_ALPN: &[u8] = b"link-p2p/tun/1";

/// 172.24.0.0/16 — a slice of RFC 1918's 172.16.0.0/12 that common tools
/// (Docker's default bridge 172.17/16, typical home-router DHCP pools) don't
/// grab by default. Deliberately NOT RFC 6598's 100.64.0.0/10: measured on
/// real hardware (2026-08), Tailscale's netfilter rules DROP every packet
/// with a 100.64/10 source that doesn't arrive on tailscale0
/// (`-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP`), which
/// blackholes a tunnel in that range in both directions. This choice only
/// dodges the conflicts we know about — the startup collision check
/// (ensure_vip_free) stays as the universal fallback.
const VIP_BASE: u32 = 0xAC18_0000; // 172.24.0.0
/// Low 16 bits of the hash — one /16's worth of host bits.
const VIP_HOST_BITS: u32 = 0x0000_FFFF;

/// Derive this node's *default* virtual IP from its EndpointId, used when
/// `--tun-ip` isn't given.
///
/// `0xAC18_0000 | (BLAKE3(endpoint_id) & 0x0000_FFFF)` — deterministic, so
/// both sides can compute the default without coordination (design decision
/// 1). 16 host bits ≈ 64K addresses; point-to-point collision probability is
/// negligible, and the local-interface check catches the cases that do
/// collide. The *peer's* address is no longer derived: each side announces
/// the address it actually bound during the handshake (see
/// exchange_peer_vip), so `--tun-ip` overrides stay consistent.
pub fn derive_vip(endpoint_id: EndpointId) -> Ipv4Addr {
    let hash = blake3::hash(endpoint_id.as_bytes());
    let raw = u32::from_be_bytes([0, 0, hash.as_bytes()[0], hash.as_bytes()[1]]);
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
///
/// NOTE: the first call happens right after the handshake, when the QUIC
/// PMTUD probe is still at its RFC 9000 starting value (1200) — on a path
/// that supports more, `max_datagram_size()` climbs to the real value a few
/// ms later. A one-shot clamp at this point is therefore conservative
/// (e.g. 1162 instead of the design's 1280). The datagram loop re-checks
/// periodically and raises the TUN MTU once PMTUD has converged (see
/// run_datagram_loop).
fn choose_mtu(user_mtu: u16, conn: &Connection) -> Result<u16> {
    let max_dgram = conn.max_datagram_size().context(tr!(
        "the peer or path does not support QUIC datagrams; TUN mode cannot work over this connection.\n\
         Refusing to start rather than silently falling back to a stream transport."
    ))?;
    // max_datagram_size is a usize; clamp before narrowing so a value above
    // u16::MAX can't truncate into a misleadingly small MTU.
    let max_dgram = u16::try_from(max_dgram).unwrap_or(u16::MAX);
    let mtu = std::cmp::min(user_mtu, max_dgram);
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
/// interface. The range choice (VIP_BASE) only dodges the conflicts we know
/// about, so this check is the universal fallback against *any* third-party
/// address collision — it stays even though collisions are rare.
#[cfg(target_os = "linux")]
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

/// Remove the peer's route when a session ends, so a later peer with a
/// different virtual IP doesn't leave stale routes on the TUN interface.
/// Best-effort: a route that is already gone (or was never installed) must
/// not fail the teardown.
#[cfg(target_os = "linux")]
fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr) -> Result<()> {
    run_ip(&["route", "del", &format!("{peer_vip}/32"), "dev", tun_name])
}

#[cfg(not(target_os = "linux"))]
fn del_peer_route(_tun_name: &str, _peer_vip: Ipv4Addr) -> Result<()> {
    Ok(())
}

/// Lower the interface MTU to the connection's datagram ceiling. `serve`
/// creates the device before the connection exists, so it clamps down here
/// once the peer's negotiated max is known.
#[cfg(target_os = "linux")]
fn set_tun_mtu(tun_name: &str, mtu: u16) -> Result<()> {
    run_ip(&["link", "set", "dev", tun_name, "mtu", &mtu.to_string()])
}

/// Update the TUN interface MTU if the connection's datagram ceiling has
/// risen since the last check. The initial clamp runs right after the
/// handshake, when QUIC PMTUD is still at its 1200-byte starting value; as
/// the path probe converges, `max_datagram_size()` climbs (e.g. 1162 →
/// 1414), and the interface MTU should follow it up to the user's --mtu
/// bound. Never lowers the MTU: a drop would mean the path shrank, which
/// the sender must not exploit after we've already told the peer our limit.
#[cfg(target_os = "linux")]
fn refresh_tun_mtu(tun_name: &str, user_mtu: u16, conn: &Connection, mtu: &mut u16) -> Result<()> {
    let Some(max_dgram) = conn.max_datagram_size() else {
        return Ok(()); // datagrams gone (shouldn't happen); keep current MTU
    };
    let candidate = std::cmp::min(user_mtu, max_dgram as u16);
    if candidate > *mtu {
        *mtu = candidate;
        set_tun_mtu(tun_name, candidate)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn refresh_tun_mtu(
    _tun_name: &str,
    _user_mtu: u16,
    _conn: &Connection,
    _mtu: &mut u16,
) -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_tun_mtu(_tun_name: &str, _mtu: u16) -> Result<()> {
    bail!(tr!("TUN mode currently supports Linux only"))
}

// ---------------------------------------------------------------------------
// VIP exchange: each side tells the peer which address is really on its TUN
// interface, so routes point at the peer's actual VIP (derived or --tun-ip).
// ---------------------------------------------------------------------------

/// How long the one-shot VIP exchange may take before the session fails. A
/// peer that completes the QUIC handshake but never answers is either an old
/// build or misbehaving — failing beats hanging forever.
const VIP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Announce our actual virtual IP to the peer and learn theirs, over a
/// one-shot bidi stream opened right after the QUIC handshake.
///
/// Without this, each side derived the peer's VIP from its EndpointId and
/// routed to that guess — which silently breaks the moment one side uses
/// `--tun-ip` (the derived address is then not what's on the peer's
/// interface). Exchanging the address makes both sides agree by construction.
///
/// Wire format: 4 bytes, the IPv4 octets. The dialer (`tun connect`) speaks
/// first, the acceptor (`tun serve`) replies with its own.
async fn exchange_peer_vip(conn: &Connection, own_vip: Ipv4Addr, dialer: bool) -> Result<Ipv4Addr> {
    let exchange = async {
        let (mut send, mut recv) = if dialer {
            conn.open_bi().await?
        } else {
            conn.accept_bi().await?
        };
        let mut buf = [0u8; 4];
        if dialer {
            send.write_all(&own_vip.octets()).await?;
            recv.read_exact(&mut buf).await?;
        } else {
            recv.read_exact(&mut buf).await?;
            send.write_all(&own_vip.octets()).await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(Ipv4Addr::from(buf))
    };
    let peer_vip = time::timeout(VIP_EXCHANGE_TIMEOUT, exchange)
        .await
        .context(tr!("peer did not complete the TUN address exchange"))??;
    if peer_vip.is_unspecified() || peer_vip.is_broadcast() || peer_vip.is_multicast() {
        bail!(tr_fmt!(
            "peer announced an unusable virtual IP {0}",
            peer_vip
        ));
    }
    Ok(peer_vip)
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
///
/// Also periodically refreshes the interface MTU upward (see choose_mtu for
/// why the initial clamp is conservative).
async fn run_datagram_loop(
    tun: &tun2::AsyncDevice,
    tun_name: &str,
    conn: &Connection,
    user_mtu: u16,
    mtu: &mut u16,
    peer: EndpointId,
    styler: Styler,
) -> Result<SessionEnd> {
    let mut buf = vec![0u8; *mtu as usize + 64];
    let mut refresh = time::interval(Duration::from_secs(2));
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
            _ = refresh.tick() => {
                let old = *mtu;
                refresh_tun_mtu(tun_name, user_mtu, conn, mtu)?;
                if *mtu != old {
                    info!(%peer, "{}", tr_fmt!(
                        "TUN interface MTU raised {0} → {1} (datagram path MTU converged)",
                        old, *mtu
                    ));
                    buf.resize(*mtu as usize + 64, 0);
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
                info!(%peer, "{}", tr!("TUN session established"));

                // The peer's real VIP — its derived default or its --tun-ip
                // override — announced during the handshake. Kept outside the
                // session block so it survives for route cleanup below.
                let peer_vip = match exchange_peer_vip(&conn, own_vip, false).await {
                    Ok(vip) => vip,
                    Err(e) => {
                        warn!(%peer, error = %e, "{}", tr!("TUN session error"));
                        continue;
                    }
                };

                let result = async {
                    add_peer_route(&tun_name, peer_vip)?;
                    let mut mtu = choose_mtu(mtu, &conn)?;
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
                    run_datagram_loop(&tun, &tun_name, &conn, mtu, &mut mtu, peer, styler).await
                }
                .await;

                // Session over (peer gone, error, or Ctrl+C): drop the peer's
                // route so a later peer with a different VIP doesn't leave a
                // stale route on the TUN interface. Best-effort, but never
                // silent — a failure here is how zombie routes get diagnosed.
                if let Err(e) = del_peer_route(&tun_name, peer_vip) {
                    warn!(%peer, error = %e, "{}", tr!("could not remove peer route"));
                }

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
    // Close gracefully: send close frames to any connected peer instead of
    // dropping the socket, so the peer's session (and route cleanup) ends
    // immediately.
    endpoint.close().await;
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
    // The peer's actual VIP (derived default or `--tun-ip` override) comes
    // from the handshake — never re-derived from its EndpointId.
    let peer_vip = exchange_peer_vip(&conn, own_vip, true).await?;

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

    let mut mtu = mtu;
    let result = run_datagram_loop(&tun, &tun_name, &conn, mtu, &mut mtu, peer_id, styler).await;
    // Close gracefully instead of dropping the socket: the peer's datagram
    // loop then fails immediately (route cleanup on the serve side is
    // instant) and iroh doesn't log its ungraceful-drop error.
    endpoint.close().await;
    match result? {
        SessionEnd::CtrlC => {}
        SessionEnd::PeerGone => {
            println!("{}", styler.warn(&tr!("peer disconnected, exiting...")));
        }
    }
    Ok(())
}
