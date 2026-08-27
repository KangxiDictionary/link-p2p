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

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;
#[cfg(target_os = "linux")]
use std::process::Command;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::protocol::ProtocolHandler;
use iroh::{EndpointId, SecretKey};
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
    info!(
        "{}",
        tr_fmt!("choose_mtu({0}, {1}) = {2}", user_mtu, max_dgram, mtu)
    );
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

/// Raise the TUN interface MTU when the connection's datagram ceiling has
/// risen since the last check. The initial clamp runs right after the
/// handshake, when QUIC PMTUD is still at its 1200-byte starting value; as
/// the path probe converges, `max_datagram_size()` climbs (e.g. 1162 →
/// 1414), and the interface MTU should follow it up to the user's --mtu
/// bound.
///
/// Deliberately only raises (and only after `raise_after`): lowering is
/// driven by an actual oversize packet on the send path (see
/// `shrink_tun_mtu`). The hold-off after a shrink stops the
/// raise→oversize→drop→shrink loop when `max_datagram_size()` wiggles
/// between two paths (e.g. Tailscale vs relay) whose ceilings differ.
/// `max_datagram_size()` is the max payload `send_datagram` will accept
/// (QUIC framing already subtracted), so the interface MTU can be set to
/// it directly.
#[cfg(target_os = "linux")]
fn refresh_tun_mtu(
    tun_name: &str,
    user_mtu: u16,
    conn: &Connection,
    mtu: &mut u16,
    raise_after: Instant,
) -> Result<()> {
    if Instant::now() < raise_after {
        return Ok(());
    }
    let Some(max_dgram) = conn.max_datagram_size() else {
        return Ok(()); // datagrams gone (shouldn't happen); keep current MTU
    };
    let candidate = std::cmp::min(user_mtu, u16::try_from(max_dgram).unwrap_or(u16::MAX));
    if candidate > *mtu {
        *mtu = candidate;
        set_tun_mtu(tun_name, candidate)?;
    }
    Ok(())
}

/// Lower the TUN interface MTU because the path's datagram ceiling shrank
/// below it. Real-hardware logs showed a migrated-to path whose PMTUD
/// converged at 1230 while the interface sat at 1280, making every big
/// packet a "datagram too large" refusal at the QUIC layer. Event-driven:
/// only called when an actual oversize packet shows up on the send path, so
/// it cannot oscillate on its own — the timer raises it back once the path
/// really supports more. Takes the already-fetched ceiling (the caller
/// queried `max_datagram_size()` for its own check) instead of querying it
/// again. Returns whether the MTU was lowered.
#[cfg(target_os = "linux")]
fn shrink_tun_mtu(tun_name: &str, ceiling: usize, mtu: &mut u16) -> Result<bool> {
    let ceiling = u16::try_from(ceiling).unwrap_or(u16::MAX);
    if ceiling < *mtu {
        *mtu = ceiling;
        set_tun_mtu(tun_name, ceiling)?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn shrink_tun_mtu(_tun_name: &str, _ceiling: usize, _mtu: &mut u16) -> Result<bool> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn refresh_tun_mtu(
    _tun_name: &str,
    _user_mtu: u16,
    _conn: &Connection,
    _mtu: &mut u16,
    _raise_after: Instant,
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

/// How long to refuse raising the TUN MTU after a path-ceiling shrink.
/// Stops the raise→oversize-drop→shrink oscillation when
/// `max_datagram_size()` flickers between two path ceilings.
const MTU_RAISE_HOLDOFF: Duration = Duration::from_secs(15);

/// Cap ICMP Frag Needed injections so a UDP flood of oversize packets
/// cannot turn into an ICMP storm back into the local stack.
const ICMP_PTB_RATE_PER_SEC: u32 = 20;

/// Internet checksum (RFC 1071) over `data`, with an odd trailing byte
/// treated as a high-order octet paired with a zero low octet.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u16::from_be_bytes([b, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 ICMP Destination Unreachable / Fragmentation Needed
/// (Type 3 Code 4) packet announcing `next_hop_mtu`, addressed to the
/// original packet's source, sourced from our TUN VIP (we are the next hop).
///
/// Returns `None` when the original is not a unicast IPv4 packet we should
/// answer (too short, ICMP already, multicast/broadcast) — RFC 1122 says
/// never ICMP-error an ICMP error.
///
/// Wire shape (RFC 792 + RFC 1191 Next-Hop MTU in the formerly-unused field):
/// ```text
/// IP(src=gateway, dst=orig.src, proto=ICMP)
///   ICMP type=3 code=4 | checksum | unused=0 | next_hop_mtu
///   orig IP header + first 8 bytes of orig payload
/// ```
fn build_icmp_frag_needed(orig: &[u8], next_hop_mtu: u16, gateway: Ipv4Addr) -> Option<Vec<u8>> {
    if orig.len() < 20 {
        return None;
    }
    let ihl = (orig[0] & 0x0f) as usize * 4;
    if ihl < 20 || orig.len() < ihl {
        return None;
    }
    // IPv4 version check
    if orig[0] >> 4 != 4 {
        return None;
    }
    let proto = orig[9];
    if proto == 1 {
        // ICMP — do not reply to ICMP (error storms).
        return None;
    }
    let orig_src = Ipv4Addr::new(orig[12], orig[13], orig[14], orig[15]);
    if orig_src.is_unspecified()
        || orig_src.is_broadcast()
        || orig_src.is_multicast()
        || orig_src.is_loopback()
    {
        return None;
    }

    // Classic RFC 792 quote: IP header + 64 bits of original datagram.
    let quote_len = std::cmp::min(orig.len(), ihl + 8);
    let quote = &orig[..quote_len];

    // ICMP header (8) + quote
    let mut icmp = Vec::with_capacity(8 + quote_len);
    icmp.push(3); // Destination Unreachable
    icmp.push(4); // Fragmentation Needed
    icmp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp.extend_from_slice(&0u16.to_be_bytes()); // unused
    icmp.extend_from_slice(&next_hop_mtu.to_be_bytes());
    icmp.extend_from_slice(quote);
    let csum = inet_checksum(&icmp);
    icmp[2] = (csum >> 8) as u8;
    icmp[3] = (csum & 0xff) as u8;

    let total_len = 20 + icmp.len();
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45); // v4, IHL=5
    pkt.push(0); // TOS
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    pkt.push(64); // TTL
    pkt.push(1); // protocol ICMP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum placeholder
    pkt.extend_from_slice(&gateway.octets());
    pkt.extend_from_slice(&orig_src.octets());
    let ip_csum = inet_checksum(&pkt[..20]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = (ip_csum & 0xff) as u8;
    pkt.extend_from_slice(&icmp);
    Some(pkt)
}

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
/// Datagram errors (send or read) are NOT treated as a peer disconnect
/// here — iroh/noq's connection migration (MagicSocket) causes transient
/// failures while switching paths, and the upper layer must not tear down
/// the session during a path switch. The `conn.closed()` branch at the top
/// of the select detects genuine disconnection as an event, so the error
/// branches just log a warning and keep going.
///
/// The interface MTU is adjusted in both directions: the timer raises it as
/// the path's PMTUD converges upward (held off for [`MTU_RAISE_HOLDOFF`] after
/// a shrink), and the send path lowers it (via `shrink_tun_mtu`) when an
/// actual oversize packet shows up after a switch to a worse path. Oversized
/// drops also inject an ICMP Fragmentation Needed (Type 3 Code 4) back into
/// the TUN so the local TCP stack learns the new Next-Hop MTU immediately
/// instead of waiting for black-hole detection.
async fn run_datagram_loop(
    tun: &tun2::AsyncDevice,
    tun_name: &str,
    conn: &Connection,
    user_mtu: u16,
    mtu: &mut u16,
    own_vip: Ipv4Addr,
    peer: EndpointId,
    styler: Styler,
) -> Result<SessionEnd> {
    let mut buf = vec![0u8; *mtu as usize + 64];
    let mut refresh = time::interval(Duration::from_secs(2));
    // Path-quality observability: every 15 refresh ticks (= 30s), log the
    // connection's cumulative datagram/loss counters so a running tunnel is
    // diagnosable without waiting for a failure (debug level only).
    let mut stats_log_ticks = 0u8;
    let mut dropped_oversized: u64 = 0;
    let mut icmp_injected: u64 = 0;
    let mut raise_after = Instant::now();
    let mut icmp_window_start = Instant::now();
    let mut icmp_window_count: u32 = 0;
    loop {
        tokio::select! {
            biased; // closed() first — a disconnection is detected before
                    // we waste time on stale packets.

            _ = conn.closed() => {
                info!(%peer, "{}", tr!("peer disconnected"));
                return Ok(SessionEnd::PeerGone);
            }
            r = tun.recv(&mut buf) => {
                let n = r.context(tr!("reading packet from TUN device"))?;
                // The interface MTU can lag behind the path's current
                // datagram ceiling after a path switch (PMTUD re-converges
                // smaller, e.g. 1280 interface vs 1230 ceiling). Check before
                // sending so an oversize packet *lowers* the MTU instead of
                // being refused by the QUIC layer as "datagram too large" on
                // every send. The packet itself is dropped — and we synthesize
                // ICMP Frag Needed into the TUN so local TCP PMTUD reacts
                // immediately rather than via black-hole timeouts.
                let ceiling = conn.max_datagram_size().unwrap_or(usize::MAX);
                if n > ceiling {
                    let next_hop = u16::try_from(ceiling).unwrap_or(u16::MAX);
                    dropped_oversized += 1;
                    if shrink_tun_mtu(tun_name, ceiling, mtu)? {
                        raise_after = Instant::now() + MTU_RAISE_HOLDOFF;
                        warn!(%peer, "{}", tr_fmt!(
                            "path datagram ceiling dropped to {0}; lowered TUN interface MTU and dropped one packet",
                            *mtu
                        ));
                    }
                    // Rate-limited ICMP PTB back into the local stack.
                    if icmp_window_start.elapsed() >= Duration::from_secs(1) {
                        icmp_window_start = Instant::now();
                        icmp_window_count = 0;
                    }
                    if icmp_window_count < ICMP_PTB_RATE_PER_SEC {
                        if let Some(icmp) = build_icmp_frag_needed(&buf[..n], next_hop, own_vip) {
                            if let Err(e) = tun.send(&icmp).await {
                                warn!(%peer, error = %e, "{}", tr!("failed to inject ICMP Fragmentation Needed into TUN"));
                            } else {
                                icmp_injected += 1;
                                icmp_window_count += 1;
                            }
                        }
                    }
                    continue;
                }
                let pkt = Bytes::copy_from_slice(&buf[..n]);
                if let Err(e) = conn.send_datagram_wait(pkt).await {
                    // The connection is still alive (closed() above would
                    // have fired if not) — iroh is migrating to a new path.
                    // Drop this packet (TUN mode is best-effort) and keep
                    // the session alive.
                    warn!(%peer, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
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
                        warn!(%peer, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
                    }
                }
            }
            _ = refresh.tick() => {
                let old = *mtu;
                refresh_tun_mtu(tun_name, user_mtu, conn, mtu, raise_after)?;
                if *mtu != old {
                    info!(%peer, "{}", tr_fmt!(
                        "TUN interface MTU raised {0} → {1} (datagram path MTU converged)",
                        old, *mtu
                    ));
                    buf.resize(*mtu as usize + 64, 0);
                }
                // Flush drop / ICMP counters once per tick instead of one
                // log line per oversize packet.
                if dropped_oversized > 0 || icmp_injected > 0 {
                    warn!(%peer, "{}", tr_fmt!(
                        "dropped {0} oversized packets in the last 2s (interface MTU is {1}; injected {2} ICMP Fragmentation Needed)",
                        dropped_oversized, *mtu, icmp_injected
                    ));
                    dropped_oversized = 0;
                    icmp_injected = 0;
                }
                if stats_log_ticks == 0 {
                    let s = conn.stats();
                    tracing::debug!(%peer,
                        udp_tx = s.udp_tx.datagrams,
                        udp_rx = s.udp_rx.datagrams,
                        lost_packets = s.lost_packets,
                        lost_bytes = s.lost_bytes,
                        "path stats (growing udp_tx/rx means the direct path is in use)"
                    );
                    stats_log_ticks = 15;
                } else {
                    stats_log_ticks -= 1;
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

/// Answer `link-p2p ping` probes (PING_ALPN connections) on a dedicated task
/// so the tunnel's accept loop keeps serving peers while a probe is open.
fn handle_ping_probe(conn: Connection) {
    tokio::spawn(async move {
        if let Err(e) = crate::PingHandler.accept(conn).await {
            warn!(error = %e, "{}", tr!("ping probe error"));
        }
    });
}

/// Exposed side (`tun serve`): accept one peer at a time and bridge this
/// machine to it. The collision check and device creation happen before we
/// accept anything, so a startup problem is reported immediately rather than
/// after a peer has already dialed.
pub async fn run_tun_serve(
    secret_key: SecretKey,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: Option<&str>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    styler: Styler,
) -> Result<()> {
    let endpoint = crate::build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune)?
        // PING_ALPN must be registered here or the probe never gets past the
        // TLS ALPN negotiation: iroh only accepts connections whose ALPN is
        // in this list, so the conn.alpn() dispatch below would be dead code.
        .alpns(vec![TUN_ALPN.to_vec(), crate::PING_ALPN.to_vec()])
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
    let ep_hex = own_id.to_string();
    println!("    {}", styler.highlight(&ep_hex));
    println!("ENDPOINT_ID={ep_hex}");
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

                // `link-p2p ping` probes arrive on their own ALPN; answer
                // them on a dedicated task so the tunnel keeps accepting
                // peers. (PING_ALPN is registered on the endpoint above.)
                if conn.alpn() == crate::PING_ALPN {
                    handle_ping_probe(conn);
                    continue;
                }

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
                    let user_mtu = mtu;
                    let mut mtu = choose_mtu(user_mtu, &conn)?;
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
                    run_datagram_loop(
                        &tun, &tun_name, &conn, user_mtu, &mut mtu, own_vip, peer, styler,
                    )
                    .await
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
#[allow(clippy::too_many_arguments)] // CLI entry point; explicit config beats a grab-bag struct
pub async fn run_tun_connect(
    secret_key: SecretKey,
    to: &str,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: Option<&str>,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    styler: Styler,
) -> Result<()> {
    let endpoint = crate::build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune)?
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

    let dial_addr = crate::build_dial_addr(peer_id, relay, &to_addr)?;
    if !to_addr.is_empty() {
        println!(
            "  {}",
            styler.dim(&tr_fmt!(
                "dialing the peer's direct address hint(s): {0}",
                to_addr
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        );
    }

    // The TUN device lives for the whole process: sessions come and go, the
    // interface (and its /32 address) survives across reconnects. MTU is
    // clamped per session (choose_mtu) and the interface follows via
    // set_tun_mtu, so start with the user's --mtu bound.
    let (tun, tun_name) = create_tun_device(own_vip, mtu)?;

    // Reconnect loop: unlike stream-mode `connect`, which re-dials per QUIC
    // connection in the background, a TUN session *is* the whole data path —
    // when the peer goes away the datagram loop ends, so re-establish the
    // session (dial + VIP exchange + route) with the same exponential backoff
    // stream mode uses (Backoff, shared with spawn_reconnect_watcher). Ctrl+C
    // is handled both inside the datagram loop and during the backoff wait.
    let mut connected_once = false;
    let mut backoff = crate::Backoff::new(crate::RECONNECT_BASE, crate::RECONNECT_MAX);
    let mut delay: Option<Duration> = None;
    loop {
        // Backoff between sessions (None = first attempt, dial immediately).
        if let Some(d) = delay {
            tokio::select! {
                _ = time::sleep(d) => {}
                _ = tokio::signal::ctrl_c() => {
                    println!("{}", styler.warn(&tr!("shutting down...")));
                    endpoint.close().await;
                    return Ok(());
                }
            }
        }

        println!("{}", styler.info(&tr_fmt!("dialing {0}...", peer_id)));
        let session = async {
            let conn = endpoint
                .connect(dial_addr.clone(), TUN_ALPN)
                .await
                .context(tr!("connecting to remote endpoint"))?;
            // The peer's actual VIP (derived default or `--tun-ip` override)
            // comes from the handshake — never re-derived from its EndpointId.
            let peer_vip = exchange_peer_vip(&conn, own_vip, true).await?;

            // Fail closed on datagram support before bridging anything.
            let user_mtu = mtu;
            let mut mtu = choose_mtu(user_mtu, &conn)?;
            set_tun_mtu(&tun_name, mtu)?;
            add_peer_route(&tun_name, peer_vip)?;
            // Same observability line as `tun serve`: compare this across both
            // machines to check the MTU-symmetry assumption.
            info!(%peer_id, "{}", tr_fmt!(
                "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
                conn.max_datagram_size().unwrap_or_default(),
                mtu
            ));

            if !connected_once {
                connected_once = true;
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
            }

            let end = run_datagram_loop(
                &tun, &tun_name, &conn, user_mtu, &mut mtu, own_vip, peer_id, styler,
            )
            .await?;
            Ok::<_, anyhow::Error>((end, Some(peer_vip)))
        }
        .await;

        let (end, peer_vip) = match session {
            Ok(x) => x,
            Err(e) => {
                warn!(%peer_id, error = %e, "{}", tr!("TUN session error"));
                (SessionEnd::PeerGone, None)
            }
        };
        // Session over (peer gone, error, or Ctrl+C): drop the peer's route so
        // a later session with a different VIP doesn't leave a stale route on
        // the TUN interface. Best-effort, but never silent.
        if let Some(vip) = peer_vip {
            if let Err(e) = del_peer_route(&tun_name, vip) {
                warn!(%peer_id, error = %e, "{}", tr!("could not remove peer route"));
            }
        }

        match end {
            SessionEnd::CtrlC => break,
            SessionEnd::PeerGone => {
                let next = backoff.next();
                delay = Some(next);
                info!(%peer_id, "{}", tr_fmt!("reconnecting in {0}", format!("{next:?}")));
            }
        }
    }
    // Close gracefully instead of dropping the socket: the peer's datagram
    // loop then fails immediately (route cleanup on the serve side is
    // instant) and iroh doesn't log its ungraceful-drop error.
    endpoint.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal IPv4 TCP SYN-ish packet: 20-byte header + 8 bytes "payload".
    fn sample_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, total_len: u16) -> Vec<u8> {
        let mut p = vec![0u8; total_len as usize];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total_len.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let csum = inet_checksum(&p[..20]);
        p[10] = (csum >> 8) as u8;
        p[11] = (csum & 0xff) as u8;
        // Fake TCP ports + seq so the 8-byte quote is non-zero.
        p[20..28].copy_from_slice(&[0x04, 0xd2, 0x00, 0x50, 1, 2, 3, 4]);
        p
    }

    #[test]
    fn inet_checksum_known_vector() {
        // Empty → 0xffff (all ones after one's complement of zero sum).
        assert_eq!(inet_checksum(&[]), 0xffff);
        // Two zero bytes → same.
        assert_eq!(inet_checksum(&[0, 0]), 0xffff);
    }

    #[test]
    fn icmp_frag_needed_wire_shape() {
        let src = Ipv4Addr::new(172, 24, 0, 1);
        let dst = Ipv4Addr::new(172, 24, 0, 2);
        let gw = Ipv4Addr::new(172, 24, 0, 1);
        let orig = sample_ipv4_tcp(src, dst, 1280);
        let pkt = build_icmp_frag_needed(&orig, 1162, gw).expect("build");

        assert_eq!(pkt[0] >> 4, 4);
        assert_eq!(pkt[0] & 0x0f, 5);
        assert_eq!(pkt[9], 1); // ICMP
        assert_eq!(&pkt[12..16], &gw.octets());
        assert_eq!(&pkt[16..20], &src.octets());

        let icmp = &pkt[20..];
        assert_eq!(icmp[0], 3); // Dest Unreachable
        assert_eq!(icmp[1], 4); // Frag Needed
        assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), 0); // unused
        assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1162); // Next-Hop MTU
        // Quoted original: IP header (20) + 8 bytes
        assert_eq!(&icmp[8..28], &orig[..20]);
        assert_eq!(&icmp[28..36], &orig[20..28]);

        // Checksums must verify to 0 when recomputed including the field
        // (RFC 1071: sum including the stored checksum folds to 0xffff, then
        // one's complement yields 0).
        assert_eq!(inet_checksum(&pkt[..20]), 0);
        assert_eq!(inet_checksum(icmp), 0);
    }

    #[test]
    fn icmp_frag_needed_skips_icmp_and_bad_src() {
        let gw = Ipv4Addr::new(172, 24, 0, 1);
        let mut icmp_orig = sample_ipv4_tcp(
            Ipv4Addr::new(172, 24, 0, 1),
            Ipv4Addr::new(172, 24, 0, 2),
            40,
        );
        icmp_orig[9] = 1; // rewrite as ICMP
        assert!(build_icmp_frag_needed(&icmp_orig, 1162, gw).is_none());

        let mcast = sample_ipv4_tcp(Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::new(172, 24, 0, 2), 40);
        assert!(build_icmp_frag_needed(&mcast, 1162, gw).is_none());

        assert!(build_icmp_frag_needed(&[], 1162, gw).is_none());
        assert!(build_icmp_frag_needed(&[0x45; 10], 1162, gw).is_none());
    }
}
