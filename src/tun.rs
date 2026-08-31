//! TUN mode: whole-machine IP reachability over QUIC datagrams.
//!
//! Stream `serve`/`connect` forward one TCP port. This module bridges machines
//! at the IP layer over *unreliable* QUIC datagrams (inner TCP/UDP/ICMP keep
//! their own reliability).
//!
//! Topology is **hub-and-spoke with optional spoke↔spoke direct paths**:
//! `tun serve` is the hub (roster + fallback forward); `tun connect` dials the
//! hub, receives the VIP↔EndpointId roster over a reliable control stream, and
//! tries a direct `TUN_ALPN` link to each peer (iroh discovery/hole-punch).
//! Packets prefer a direct connection when present, otherwise go via the hub.
//!
//! Desktop backends: Linux / macOS / Windows. Privileged unlike stream modes.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Command;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use tokio::sync::{mpsc, oneshot, Notify, RwLock};
use tokio::time::{self, Duration};
use tracing::{info, warn};
use tun2::AbstractDevice;

use std::sync::Mutex as StdMutex;

use crate::i18n::{tr, tr_fmt};
use crate::style::Styler;
use crate::tun_ctl::{CtlPeer, CtlResponse};
use crate::tun_roster::{
    encode_joined, encode_left, encode_snapshot, read_msg, should_dial, write_msg, RosterEntry,
    RosterMsg,
};

/// ALPN for TUN mode. "2" adds the reliable roster control stream after VIP
/// exchange so spokes can learn the full mesh and attempt direct links.
pub const TUN_ALPN: &[u8] = b"link-p2p/tun/2";

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
/// Whole mesh prefix spokes install on the TUN (hub keeps per-peer /32s).
const VIP_PREFIX: &str = "172.24.0.0/16";

/// Live snapshot for the daemon control plane (`Status` / `Peers`).
#[derive(Debug)]
pub struct TunLiveState {
    pub role: String,
    pub session: String,
    started: Instant,
    vip: RwLock<Option<Ipv4Addr>>,
    path_kind: RwLock<String>,
    peers: RwLock<Vec<CtlPeer>>,
}

impl TunLiveState {
    pub fn new(role: impl Into<String>, session: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            role: role.into(),
            session: session.into(),
            started: Instant::now(),
            vip: RwLock::new(None),
            path_kind: RwLock::new("unknown".into()),
            peers: RwLock::new(Vec::new()),
        })
    }

    pub async fn set_vip(&self, vip: Ipv4Addr) {
        *self.vip.write().await = Some(vip);
    }

    pub async fn set_path_kind(&self, kind: &str) {
        *self.path_kind.write().await = kind.to_string();
    }

    pub async fn set_peers(&self, peers: Vec<CtlPeer>) {
        *self.peers.write().await = peers;
    }

    pub async fn status_response(&self) -> CtlResponse {
        CtlResponse::Status {
            role: self.role.clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            vip: self.vip.read().await.unwrap_or(Ipv4Addr::UNSPECIFIED),
            path_kind: self.path_kind.read().await.clone(),
            session: self.session.clone(),
        }
    }

    pub async fn peers_response(&self) -> CtlResponse {
        CtlResponse::Peers {
            peers: self.peers.read().await.clone(),
        }
    }
}

/// Hooks so a TUN data-plane future can be driven by the daemon worker:
/// cancel on `Shutdown`, publish live Status/Peers, and fire ready after TUN
/// create (parent must not return success before the interface exists).
pub struct TunHooks {
    pub cancel: Arc<Notify>,
    pub state: Arc<TunLiveState>,
    ready: StdMutex<Option<oneshot::Sender<Result<()>>>>,
}

impl TunHooks {
    pub fn new(state: Arc<TunLiveState>) -> (Self, oneshot::Receiver<Result<()>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                cancel: Arc::new(Notify::new()),
                state,
                ready: StdMutex::new(Some(tx)),
            },
            rx,
        )
    }

    pub fn signal_ready(&self, result: Result<()>) {
        if let Ok(mut g) = self.ready.lock() {
            if let Some(tx) = g.take() {
                let _ = tx.send(result);
            }
        }
    }

    pub fn request_shutdown(&self) {
        self.cancel.notify_waiters();
    }
}

fn vip_in_mesh(ip: Ipv4Addr) -> bool {
    u32::from(ip) & !VIP_HOST_BITS == VIP_BASE
}

/// IPv4 destination from a raw L3 packet (no Ethernet header on our TUN).
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

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
// Local interface setup (Linux / macOS / Windows).
//
// Packet I/O goes through tun2::AsyncDevice on every desktop OS. Address,
// MTU and peer routes are OS-specific: Linux uses `ip`; macOS uses
// `ifconfig`/`route` (and tun2's create-time alias); Windows uses Wintun
// config + `route`. Dropping the AsyncDevice tears the interface down.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn vip_already_taken_msg(vip: Ipv4Addr) -> String {
    tr_fmt!(
        "virtual IP {0} is already assigned to a local interface.\n\
         Pick a different one with --tun-ip.",
        vip
    )
}

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

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
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
        bail!(vip_already_taken_msg(vip));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
fn ensure_vip_free(vip: Ipv4Addr) -> Result<()> {
    let vip_s = vip.to_string();
    // Prefer one-IP-per-line from Get-NetIPAddress (no gateway/DNS false hits).
    // Only trust a successful run that listed at least one address: SilentlyContinue
    // can yield exit 0 with empty stdout when the cmdlet fails, which would
    // otherwise look like "no conflict".
    if let Ok(out) = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }",
        ])
        .output()
    {
        if out.status.success() {
            // Own the lossy conversion so line slices can live past the statement.
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let ips: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if !ips.is_empty() {
                if ips.iter().any(|ip| *ip == vip_s) {
                    bail!(vip_already_taken_msg(vip));
                }
                return Ok(());
            }
        }
    }
    // Fallback: only parse "IP Address" value fields from netsh (not gateways).
    let out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "addresses"])
        .output()
        .context(tr!("checking local interfaces for the virtual IP"))?;
    let taken = String::from_utf8_lossy(&out.stdout).lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        // English netsh: "IP Address:                 192.168.1.1"
        if !lower.contains("ip address") {
            return false;
        }
        line.rsplit(':')
            .next()
            .is_some_and(|v| v.trim() == vip_s)
    });
    if taken {
        bail!(vip_already_taken_msg(vip));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn ensure_vip_free(_vip: Ipv4Addr) -> Result<()> {
    bail!(tr!(
        "TUN mode supports Linux, macOS, and Windows only on this build"
    ))
}

/// Create the TUN interface, assign `vip`, set MTU and bring it up.
///
/// Contract across platforms: L3 device, address = `vip`/32, up, MTU set.
/// Peer host routes are installed later via [`add_peer_route`] (not at create
/// time — the peer VIP is learned in the handshake).
///
/// Linux keeps address/MTU/`up` on `ip` so failures stay readable and match
/// the long-tested path (`ensure_root_privileges(false)`). macOS needs
/// tun2's point-to-point alias (`destination` = self) at create time.
/// Windows configures address/netmask/MTU via Wintun; `destination` is
/// omitted (Wintun treats it as a default gateway, which we do not want for
/// a /32 VIP — peer routes use `route add` instead).
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

#[cfg(target_os = "macos")]
fn create_tun_device(vip: Ipv4Addr, mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
    // Leave tun_name unset so the kernel allocates the next free utunN.
    // destination=vip + /32 is the BSD point-to-point alias; peer host
    // routes are installed later via `route -n add -host`.
    let mut config = tun2::configure();
    config
        .address(vip)
        .destination(vip)
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
    Ok((device, name))
}

#[cfg(windows)]
fn create_tun_device(vip: Ipv4Addr, mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
    // Always load the DLL next to this exe — relative "wintun.dll" would
    // search PATH and can pick up an unsigned copy (→ "The file is not signed").
    let dll = wintun_dll_beside_exe()?;
    let mut config = tun2::configure();
    config
        .tun_name("link-p2p")
        .address(vip)
        .netmask(Ipv4Addr::new(255, 255, 255, 255))
        .mtu(mtu)
        .up()
        .layer(tun2::Layer::L3)
        .platform_config(|p| {
            p.wintun_file(&dll);
        });
    let device = tun2::create_as_async(&config).with_context(|| {
        tr_fmt!(
            "creating TUN device failed (needs Administrator).\n\
             Use the official signed wintun.dll from https://www.wintun.net/ \
             (amd64 for 64-bit), placed next to this executable:\n\
               {0}\n\
             \"The file is not signed\" means Windows rejected the DLL signature — \
             replace a wrong/unsigned/PATH-shadowed copy with the official one.",
            dll.display()
        )
    })?;
    let name = device
        .tun_name()
        .context(tr!("reading TUN interface name"))?;
    Ok((device, name))
}

/// Resolve `wintun.dll` beside `link-p2p.exe` (not via PATH).
#[cfg(windows)]
fn wintun_dll_beside_exe() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context(tr!("resolving path to this executable"))?;
    let dir = exe
        .parent()
        .context(tr!("resolving directory of this executable"))?;
    let dll = dir.join("wintun.dll");
    if !dll.is_file() {
        bail!(tr_fmt!(
            "wintun.dll not found next to this executable:\n\
               {0}\n\
             Download the official signed build from https://www.wintun.net/ \
             (use the amd64 folder on 64-bit Windows) and copy wintun.dll here.",
            dll.display()
        ));
    }
    Ok(dll)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn create_tun_device(_vip: Ipv4Addr, _mtu: u16) -> Result<(tun2::AsyncDevice, String)> {
    bail!(tr!(
        "TUN mode supports Linux, macOS, and Windows only on this build"
    ))
}

/// Point the peer's virtual IP at the tunnel.
#[cfg(target_os = "linux")]
fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, _own_vip: Ipv4Addr) -> Result<()> {
    // `replace` (not `add`) so a reconnecting peer updates the route instead
    // of erroring on "exists".
    run_ip(&[
        "route",
        "replace",
        &format!("{peer_vip}/32"),
        "dev",
        tun_name,
    ])
}

#[cfg(target_os = "macos")]
fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, _own_vip: Ipv4Addr) -> Result<()> {
    // Prefer add-only so a clean first install has no delete→add gap. If the
    // host route already exists (reconnect), delete then re-add.
    let peer = peer_vip.to_string();
    let add_args = [
        "-n",
        "add",
        "-host",
        peer.as_str(),
        "-interface",
        tun_name,
    ];
    if run_cmd("route", &add_args).is_ok() {
        return Ok(());
    }
    let _ = run_cmd("route", &["-n", "delete", "-host", peer.as_str()]);
    run_cmd("route", &add_args)
}

#[cfg(windows)]
fn add_peer_route(tun_name: &str, peer_vip: Ipv4Addr, _own_vip: Ipv4Addr) -> Result<()> {
    // Prefer netsh on-link route via the Wintun interface name. Using the local
    // VIP as a `route add` gateway often installs a route that never selects
    // the Wintun adapter — ICMP then blackholes even though the session is up.
    let peer = format!("{peer_vip}/32");
    let add_netsh = || {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                peer.as_str(),
                tun_name,
                "store=active",
            ],
        )
    };
    if add_netsh().is_ok() {
        return Ok(());
    }
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "delete",
            "route",
            peer.as_str(),
            tun_name,
        ],
    );
    add_netsh()
}

#[cfg(windows)]
fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr) -> Result<()> {
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "delete",
            "route",
            &format!("{peer_vip}/32"),
            tun_name,
        ],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn add_peer_route(
    _tun_name: &str,
    _peer_vip: Ipv4Addr,
    _own_vip: Ipv4Addr,
) -> Result<()> {
    bail!(tr!(
        "TUN mode supports Linux, macOS, and Windows only on this build"
    ))
}

/// Remove the peer's route when a session ends, so a later peer with a
/// different virtual IP doesn't leave stale routes on the TUN interface.
/// Best-effort: a route that is already gone (or was never installed) must
/// not fail the teardown.
#[cfg(target_os = "linux")]
fn del_peer_route(tun_name: &str, peer_vip: Ipv4Addr) -> Result<()> {
    run_ip(&["route", "del", &format!("{peer_vip}/32"), "dev", tun_name])
}

#[cfg(target_os = "macos")]
fn del_peer_route(_tun_name: &str, peer_vip: Ipv4Addr) -> Result<()> {
    run_cmd("route", &["-n", "delete", "-host", &peer_vip.to_string()])
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn del_peer_route(_tun_name: &str, _peer_vip: Ipv4Addr) -> Result<()> {
    Ok(())
}

/// Spoke-side: send the whole VIP /16 into the TUN so traffic for *any*
/// mesh peer (not only the hub) is captured and sent to the hub for
/// forwarding.
#[cfg(target_os = "linux")]
fn add_mesh_route(tun_name: &str) -> Result<()> {
    run_ip(&["route", "replace", VIP_PREFIX, "dev", tun_name])
}

#[cfg(target_os = "macos")]
fn add_mesh_route(tun_name: &str) -> Result<()> {
    let _ = run_cmd("route", &["-n", "delete", "-net", VIP_PREFIX]);
    run_cmd(
        "route",
        &["-n", "add", "-net", VIP_PREFIX, "-interface", tun_name],
    )
}

#[cfg(windows)]
fn add_mesh_route(tun_name: &str) -> Result<()> {
    let add = || {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                VIP_PREFIX,
                tun_name,
                "store=active",
            ],
        )
    };
    if add().is_ok() {
        return Ok(());
    }
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "delete",
            "route",
            VIP_PREFIX,
            tun_name,
        ],
    );
    add()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn add_mesh_route(_tun_name: &str) -> Result<()> {
    bail!(tr!(
        "TUN mode supports Linux, macOS, and Windows only on this build"
    ))
}

#[cfg(target_os = "linux")]
fn del_mesh_route(tun_name: &str) -> Result<()> {
    run_ip(&["route", "del", VIP_PREFIX, "dev", tun_name])
}

#[cfg(target_os = "macos")]
fn del_mesh_route(_tun_name: &str) -> Result<()> {
    run_cmd("route", &["-n", "delete", "-net", VIP_PREFIX])
}

#[cfg(windows)]
fn del_mesh_route(tun_name: &str) -> Result<()> {
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "delete",
            "route",
            VIP_PREFIX,
            tun_name,
        ],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn del_mesh_route(_tun_name: &str) -> Result<()> {
    Ok(())
}

/// Lower/raise the interface MTU to the connection's datagram ceiling.
#[cfg(target_os = "linux")]
fn set_tun_mtu(tun_name: &str, mtu: u16) -> Result<()> {
    run_ip(&["link", "set", "dev", tun_name, "mtu", &mtu.to_string()])
}

#[cfg(target_os = "macos")]
fn set_tun_mtu(tun_name: &str, mtu: u16) -> Result<()> {
    run_cmd("ifconfig", &[tun_name, "mtu", &mtu.to_string()])
}

#[cfg(windows)]
fn set_tun_mtu(tun_name: &str, mtu: u16) -> Result<()> {
    // Wintun's ring accepts huge packets; ask the IPv4 stack to advertise a
    // lower interface MTU so local TCP can learn without relying solely on
    // ICMP Frag Needed (Windows firewalls sometimes drop injected ICMP).
    // Best-effort: failure must not tear the tunnel down.
    let mtu_arg = format!("mtu={mtu}");
    if let Err(e) = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            tun_name,
            &mtu_arg,
            "store=active",
        ],
    ) {
        warn!(
            error = %e,
            "{}",
            tr!("could not set Windows interface MTU via netsh; relying on ICMP PMTUD injection")
        );
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn set_tun_mtu(_tun_name: &str, _mtu: u16) -> Result<()> {
    bail!(tr!(
        "TUN mode supports Linux, macOS, and Windows only on this build"
    ))
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
fn shrink_tun_mtu(tun_name: &str, ceiling: usize, mtu: &mut u16) -> Result<bool> {
    let ceiling = u16::try_from(ceiling).unwrap_or(u16::MAX);
    if ceiling < *mtu {
        *mtu = ceiling;
        set_tun_mtu(tun_name, ceiling)?;
        return Ok(true);
    }
    Ok(false)
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

/// Shared "do not raise interface MTU before this Instant" gate (one per TUN).
type MtuRaiseGate = Arc<std::sync::Mutex<Instant>>;

fn new_mtu_raise_gate() -> MtuRaiseGate {
    Arc::new(std::sync::Mutex::new(Instant::now()))
}

fn note_mtu_shrink(gate: &MtuRaiseGate) {
    if let Ok(mut g) = gate.lock() {
        *g = Instant::now() + MTU_RAISE_HOLDOFF;
    }
}

fn raise_after_now(gate: &MtuRaiseGate) -> Instant {
    gate.lock().map(|g| *g).unwrap_or_else(|_| Instant::now())
}

/// Internet checksum (RFC 1071) over `data`, with an odd trailing byte
/// treated as a high-order octet paired with a zero low octet.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&b) = remainder.first() {
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
    let peer_vip = match time::timeout(VIP_EXCHANGE_TIMEOUT, exchange).await {
        Ok(Ok(vip)) => vip,
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            return Err(crate::exit::coded(
                crate::exit::TIMEOUT,
                anyhow::anyhow!(tr!("peer did not complete the TUN address exchange")),
            ));
        }
    };
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

// Per-peer outbound datagrams: [`spawn_peer_sender`] (channel +
// `send_datagram_wait`). TUN device I/O: [`spawn_tun_io`]. The old monolithic
// `run_datagram_loop` was removed so hub fan-out cannot HoL on one peer's CC.

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

/// One spoke currently attached to the hub.
#[derive(Clone)]
struct HubPeer {
    id: EndpointId,
    conn: Connection,
    /// Non-blocking enqueue for datagrams destined to this spoke. A dedicated
    /// send task drains the channel so one congested peer cannot stall
    /// `read_datagram` / TUN demux for others (`send_datagram_wait` HoL).
    outbound: mpsc::Sender<Bytes>,
}

type HubPeers = Arc<RwLock<HashMap<Ipv4Addr, HubPeer>>>;
/// Control-stream writers for roster push (one per spoke).
type RosterFans = Arc<RwLock<HashMap<EndpointId, mpsc::Sender<Bytes>>>>;

fn path_label(conn: &Connection) -> &'static str {
    crate::path_kind::path_label(conn)
}

fn check_allow(allow: Option<&HashSet<EndpointId>>, peer: EndpointId) -> Result<()> {
    // Plain anyhow (not exit::coded): callers warn + close the connection and
    // keep serving — the process exit code is never taken from this Err.
    if let Some(set) = allow {
        if !set.contains(&peer) {
            return Err(anyhow::anyhow!(tr!(
                "rejecting connection: peer is not in the --allow list"
            )));
        }
    }
    Ok(())
}

/// Owned by a single task — never lock across `recv`/`send` awaits from
/// other tasks (that starved spoke→hub delivery: the reader held the mutex
/// while blocked in `recv`, so writers could not inject packets into TUN).
#[derive(Clone)]
struct TunIo {
    /// Packets to write into the TUN (spoke→hub local delivery, ICMP PTB).
    to_tun: mpsc::Sender<Bytes>,
}

impl TunIo {
    async fn send(&self, pkt: Bytes) {
        let _ = self.to_tun.send(pkt).await;
    }
}

fn spawn_tun_io(
    tun: tun2::AsyncDevice,
    user_mtu: u16,
) -> (TunIo, mpsc::Receiver<Bytes>) {
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Bytes>(256);
    let (from_tun_tx, from_tun_rx) = mpsc::channel::<Bytes>(256);
    tokio::spawn(async move {
        let tun = tun;
        let mut buf = vec![0u8; user_mtu as usize + 64];
        loop {
            tokio::select! {
                biased;
                Some(pkt) = to_tun_rx.recv() => {
                    if let Err(e) = tun.send(&pkt).await {
                        warn!(error = %e, "{}", tr!("writing packet to TUN device"));
                        break;
                    }
                }
                r = tun.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            if from_tun_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "{}", tr!("reading packet from TUN device"));
                            break;
                        }
                    }
                }
            }
        }
    });
    (TunIo { to_tun: to_tun_tx }, from_tun_rx)
}

/// Drain one peer's outbound datagram queue onto its QUIC connection.
///
/// Owns ICMP Frag Needed injection (rate-limited) and interface MTU shrink on
/// oversize; raise hold-off is recorded on [`MtuRaiseGate`] so the session's
/// periodic [`refresh_tun_mtu`] respects it.
fn spawn_peer_sender(
    tun: TunIo,
    tun_name: String,
    own_vip: Ipv4Addr,
    peer: EndpointId,
    conn: Connection,
    mut rx: mpsc::Receiver<Bytes>,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    tokio::spawn(async move {
        let mut iface_mtu = user_mtu;
        let mut icmp_window_start = Instant::now();
        let mut icmp_window_count: u32 = 0;
        while let Some(pkt) = rx.recv().await {
            let n = pkt.len();
            let ceiling = conn.max_datagram_size().unwrap_or(usize::MAX);
            if n > ceiling {
                let next_hop = u16::try_from(ceiling).unwrap_or(u16::MAX);
                if matches!(
                    shrink_tun_mtu(&tun_name, ceiling, &mut iface_mtu),
                    Ok(true)
                ) {
                    note_mtu_shrink(&raise_gate);
                    warn!(%peer, "{}", tr_fmt!(
                        "path datagram ceiling dropped to {0}; lowered TUN interface MTU and dropped one packet",
                        iface_mtu
                    ));
                }
                if icmp_window_start.elapsed() >= Duration::from_secs(1) {
                    icmp_window_start = Instant::now();
                    icmp_window_count = 0;
                }
                if icmp_window_count < ICMP_PTB_RATE_PER_SEC {
                    if let Some(icmp) = build_icmp_frag_needed(&pkt, next_hop, own_vip) {
                        tun.send(Bytes::from(icmp)).await;
                        icmp_window_count += 1;
                    }
                }
                continue;
            }
            if let Err(e) = conn.send_datagram_wait(pkt).await {
                warn!(%peer, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
            }
        }
    });
}

fn enqueue_peer(peer: &HubPeer, pkt: Bytes) {
    // Drop on full — same semantics as a lossy link / full datagram window.
    let _ = peer.outbound.try_send(pkt);
}

async fn broadcast_roster(fans: &RosterFans, msg: Bytes) {
    let senders: Vec<_> = fans.read().await.values().cloned().collect();
    for tx in senders {
        let _ = tx.send(msg.clone()).await;
    }
}

async fn hub_roster_snapshot(
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    peers: &HubPeers,
) -> Vec<RosterEntry> {
    let mut entries = vec![RosterEntry {
        vip: own_vip,
        id: own_id,
    }];
    for (vip, p) in peers.read().await.iter() {
        entries.push(RosterEntry {
            vip: *vip,
            id: p.id,
        });
    }
    entries
}

/// Hub: packets from the local TUN → spoke (by destination VIP).
async fn hub_tun_to_peers(
    mut from_tun: mpsc::Receiver<Bytes>,
    own_vip: Ipv4Addr,
    peers: HubPeers,
) {
    while let Some(pkt) = from_tun.recv().await {
        let Some(dst) = ipv4_dst(&pkt) else {
            continue;
        };
        if dst == own_vip || !vip_in_mesh(dst) {
            continue;
        }
        let peer = {
            let map = peers.read().await;
            map.get(&dst).cloned()
        };
        let Some(peer) = peer else {
            tracing::debug!(%dst, "no hub peer for destination VIP; dropping");
            continue;
        };
        enqueue_peer(&peer, pkt);
    }
}

/// Hub: packets from one spoke → local TUN and/or another spoke's outbound queue.
async fn hub_peer_to_mesh(
    tun: TunIo,
    own_vip: Ipv4Addr,
    peers: HubPeers,
    peer_vip: Ipv4Addr,
    peer: HubPeer,
) {
    loop {
        tokio::select! {
            _ = peer.conn.closed() => {
                info!(peer = %peer.id, %peer_vip, "{}", tr!("peer disconnected"));
                break;
            }
            r = peer.conn.read_datagram() => {
                match r {
                    Ok(data) => {
                        let Some(src) = ipv4_src(&data) else { continue };
                        if src != peer_vip {
                            tracing::debug!(%peer_vip, %src, "dropping spoofed source VIP");
                            continue;
                        }
                        let Some(dst) = ipv4_dst(&data) else { continue };
                        if dst == own_vip {
                            tun.send(data).await;
                            continue;
                        }
                        if !vip_in_mesh(dst) || dst == peer_vip {
                            continue;
                        }
                        let other = {
                            let map = peers.read().await;
                            map.get(&dst).cloned()
                        };
                        let Some(other) = other else {
                            tracing::debug!(%dst, "no hub peer for forwarded VIP; dropping");
                            continue;
                        };
                        enqueue_peer(&other, data);
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
                    }
                }
            }
        }
    }
}

/// Exposed side (`tun serve`): hub for many concurrent spokes. Keeps accepting
/// while sessions run; pushes a VIP↔EndpointId roster; demuxes local TUN
/// traffic and forwards spoke→spoke (fallback when spokes have no direct path).
pub async fn run_tun_serve(
    secret_key: SecretKey,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    allow: Option<HashSet<EndpointId>>,
    ui: crate::Ui,
    styler: Styler,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let endpoint = match crate::build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0_relays,
    ) {
        Ok(b) => b
            .alpns(vec![TUN_ALPN.to_vec(), crate::PING_ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| {
                crate::exit::coded(
                    crate::exit::CONNECT,
                    anyhow::Error::new(e).context(tr!("binding endpoint")),
                )
            }),
        Err(e) => Err(e),
    };
    let endpoint = match endpoint {
        Ok(e) => e,
        Err(e) => {
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            }
            return Err(e);
        }
    };

    let own_id = endpoint.id();
    let own_vip = tun_ip.unwrap_or_else(|| derive_vip(own_id));
    let signal_err = |e: &anyhow::Error| {
        if let Some(h) = &hooks {
            h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
        }
    };
    if let Err(e) = ensure_vip_free(own_vip) {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    if let Err(e) = crate::wait_online(&endpoint).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    if let Err(e) = crate::install_extra_relays(&endpoint, relay, no_n0_relays).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    let (tun, tun_name) = match create_tun_device(own_vip, mtu) {
        Ok(x) => x,
        Err(e) => {
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            }
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Some(h) = &hooks {
        h.state.set_vip(own_vip).await;
        h.signal_ready(Ok(()));
    }
    let (tun_io, from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let peers: HubPeers = Arc::new(RwLock::new(HashMap::new()));
    let fans: RosterFans = Arc::new(RwLock::new(HashMap::new()));

    tokio::spawn(hub_tun_to_peers(from_tun, own_vip, Arc::clone(&peers)));

    if hooks.is_none() {
        ui.line(styler.banner("link-p2p tun serve"));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!("your virtual IP (the peer reaches you here):"))
        ));
        ui.line(format!("    {}", styler.highlight(&own_vip.to_string())));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!(
                "your EndpointId (give this to peers running `tun connect --to`):"
            ))
        ));
        let ep_hex = own_id.to_string();
        ui.line(format!("    {}", styler.highlight(&ep_hex)));
        // Machine-readable for scripts / e2e — always stdout, even under `-q`.
        println!("ENDPOINT_ID={ep_hex}");
        ui.line(format!(
            "  {}",
            styler.dim(&tr!(
                "hub mode: roster + fallback forward; spokes may peer directly"
            ))
        ));
        if allow.is_some() {
            ui.line(format!(
                "  {}",
                styler.dim(&tr!("only accepting connections from the --allow list"))
            ));
        }
        ui.line("");
        ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));
    } else {
        // Daemon: still emit machine-readable id on stdout of the worker (→ tun.log).
        let ep_hex = own_id.to_string();
        println!("ENDPOINT_ID={ep_hex}");
    }

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    bail!(tr!("endpoint closed"));
                };
                let accepting = match incoming.accept() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "{}", tr!("rejecting malformed incoming connection"));
                        continue;
                    }
                };
                let conn = match accepting.await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "{}", tr!("completing connection handshake"));
                        continue;
                    }
                };

                if conn.alpn() == crate::PING_ALPN {
                    handle_ping_probe(conn);
                    continue;
                }

                let peer_id = conn.remote_id();
                if let Err(e) = check_allow(allow.as_ref(), peer_id) {
                    warn!(peer = %peer_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    conn.close(0u32.into(), b"denied");
                    continue;
                }

                let tun_io = tun_io.clone();
                let peers = Arc::clone(&peers);
                let fans = Arc::clone(&fans);
                let tun_name = tun_name.clone();
                let raise_gate = Arc::clone(&raise_gate);
                let user_mtu = mtu;
                let hooks_s = hooks.clone();
                crate::spawn_path_monitor(
                    conn.clone(),
                    peer_id,
                    endpoint.clone(),
                    relay_only,
                    styler,
                    ui.quiet,
                );
                let quiet = ui.quiet;
                tokio::spawn(async move {
                    if let Err(e) = hub_run_spoke(
                        tun_io,
                        tun_name,
                        own_id,
                        own_vip,
                        peers,
                        fans,
                        peer_id,
                        conn,
                        user_mtu,
                        raise_gate,
                        quiet,
                        hooks_s,
                    )
                    .await
                    {
                        warn!(peer = %peer_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    }
                });
            }
            _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                ui.line(styler.warn(&tr!("shutting down...")));
                break;
            }
            _ = async {
                match &hooks {
                    Some(h) => h.cancel.notified().await,
                    None => std::future::pending().await,
                }
            } => {
                info!("{}", tr!("TUN daemon Shutdown requested"));
                break;
            }
        }
    }
    endpoint.close().await;
    Ok(())
}

async fn hub_run_spoke(
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    peers: HubPeers,
    fans: RosterFans,
    peer_id: EndpointId,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
    quiet: bool,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let peer_vip = exchange_peer_vip(&conn, own_vip, false).await?;
    if peer_vip == own_vip || !vip_in_mesh(peer_vip) {
        bail!(tr_fmt!(
            "peer announced an unusable virtual IP {0}",
            peer_vip
        ));
    }

    // Control stream: spoke opens after VIP exchange; we accept and push roster.
    let (mut ctrl_send, _ctrl_recv) = time::timeout(VIP_EXCHANGE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| {
            crate::exit::coded(
                crate::exit::TIMEOUT,
                anyhow::anyhow!(tr!("peer did not open the TUN roster control stream")),
            )
        })?
        .context(tr!("accepting TUN roster control stream"))?;

    let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
    let (fan_tx, mut fan_rx) = mpsc::channel::<Bytes>(32);
    let out_tx_mesh = out_tx.clone();
    spawn_peer_sender(
        tun.clone(),
        tun_name.clone(),
        own_vip,
        peer_id,
        conn.clone(),
        out_rx,
        user_mtu,
        raise_gate,
    );

    {
        let mut map = peers.write().await;
        if map.contains_key(&peer_vip) {
            bail!(tr_fmt!(
                "virtual IP {0} is already claimed by another peer",
                peer_vip
            ));
        }
        map.insert(
            peer_vip,
            HubPeer {
                id: peer_id,
                conn: conn.clone(),
                outbound: out_tx,
            },
        );
    }
    fans.write().await.insert(peer_id, fan_tx);

    if let Err(e) = add_peer_route(&tun_name, peer_vip, own_vip) {
        peers.write().await.remove(&peer_vip);
        fans.write().await.remove(&peer_id);
        return Err(e);
    }

    let session_mtu = choose_mtu(user_mtu, &conn).unwrap_or(user_mtu);
    info!(%peer_id, %peer_vip, path = path_label(&conn), "{}", tr!("TUN session established"));
    info!(%peer_id, "{}", tr_fmt!(
        "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
        conn.max_datagram_size().unwrap_or_default(),
        session_mtu
    ));
    if !quiet {
        println!(
            "{}",
            tr_fmt!(
                "peer {0} joined at {1}",
                peer_id.fmt_short(),
                peer_vip
            )
        );
    }

    // Snapshot to the new spoke, then Joined to everyone else.
    let snap = hub_roster_snapshot(own_id, own_vip, &peers).await;
    let _ = write_msg(&mut ctrl_send, &encode_snapshot(&snap)).await;
    let joined = Bytes::from(encode_joined(&RosterEntry {
        vip: peer_vip,
        id: peer_id,
    }));
    broadcast_roster(&fans, joined).await;

    if let Some(h) = &hooks {
        h.state.set_path_kind(path_label(&conn)).await;
        refresh_hub_peers_state(&h.state, &peers).await;
    }

    // Fan-out task: roster updates for this spoke.
    let ctrl_send_task = {
        let mut ctrl_send = ctrl_send;
        tokio::spawn(async move {
            while let Some(msg) = fan_rx.recv().await {
                if write_msg(&mut ctrl_send, &msg).await.is_err() {
                    break;
                }
            }
        })
    };

    let hub_peer = HubPeer {
        id: peer_id,
        conn: conn.clone(),
        outbound: out_tx_mesh,
    };
    hub_peer_to_mesh(tun, own_vip, Arc::clone(&peers), peer_vip, hub_peer).await;

    ctrl_send_task.abort();
    peers.write().await.remove(&peer_vip);
    fans.write().await.remove(&peer_id);
    let left = Bytes::from(encode_left(&RosterEntry {
        vip: peer_vip,
        id: peer_id,
    }));
    broadcast_roster(&fans, left).await;
    if let Some(h) = &hooks {
        refresh_hub_peers_state(&h.state, &peers).await;
    }
    if let Err(e) = del_peer_route(&tun_name, peer_vip) {
        warn!(%peer_id, error = %e, "{}", tr!("could not remove peer route"));
    }
    info!(%peer_id, %peer_vip, "{}", tr!("peer left the mesh"));
    Ok(())
}

async fn refresh_hub_peers_state(state: &TunLiveState, peers: &HubPeers) {
    let map = peers.read().await;
    let list: Vec<CtlPeer> = map
        .iter()
        .map(|(vip, p)| CtlPeer {
            vip: *vip,
            id: p.id.to_string(),
        })
        .collect();
    state.set_peers(list).await;
}

/// Spoke-side mesh table: hub fallback + optional direct peer connections.
struct SpokeMesh {
    #[allow(dead_code)]
    own_id: EndpointId,
    #[allow(dead_code)]
    own_vip: Ipv4Addr,
    hub_vip: Option<Ipv4Addr>,
    hub_out: Option<mpsc::Sender<Bytes>>,
    /// Direct links keyed by VIP.
    direct: HashMap<Ipv4Addr, mpsc::Sender<Bytes>>,
    /// Known EndpointId → VIP (from roster); used to decide dial vs wait.
    roster: HashMap<EndpointId, Ipv4Addr>,
}

impl SpokeMesh {
    fn new(own_id: EndpointId, own_vip: Ipv4Addr) -> Self {
        Self {
            own_id,
            own_vip,
            hub_vip: None,
            hub_out: None,
            direct: HashMap::new(),
            roster: HashMap::new(),
        }
    }

    fn clear_hub(&mut self) {
        self.hub_vip = None;
        self.hub_out = None;
    }

    fn lookup_out(&self, dst: Ipv4Addr) -> Option<mpsc::Sender<Bytes>> {
        if let Some(tx) = self.direct.get(&dst) {
            return Some(tx.clone());
        }
        if self.hub_vip == Some(dst) || vip_in_mesh(dst) {
            return self.hub_out.clone();
        }
        None
    }
}

type SharedSpokeMesh = Arc<RwLock<SpokeMesh>>;

fn spawn_conn_sender(
    tun: TunIo,
    tun_name: String,
    own_vip: Ipv4Addr,
    peer: EndpointId,
    conn: Connection,
    rx: mpsc::Receiver<Bytes>,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    spawn_peer_sender(tun, tun_name, own_vip, peer, conn, rx, user_mtu, raise_gate);
}

async fn spoke_install_direct(
    mesh: &SharedSpokeMesh,
    tun: TunIo,
    tun_name: &str,
    own_vip: Ipv4Addr,
    peer_id: EndpointId,
    peer_vip: Ipv4Addr,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    if peer_vip == own_vip {
        return;
    }
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    spawn_conn_sender(
        tun.clone(),
        tun_name.to_string(),
        own_vip,
        peer_id,
        conn.clone(),
        rx,
        user_mtu,
        raise_gate,
    );
    {
        let mut g = mesh.write().await;
        g.roster.insert(peer_id, peer_vip);
        g.direct.insert(peer_vip, tx);
    }
    info!(%peer_id, %peer_vip, path = path_label(&conn), "{}", tr!("direct mesh link ready"));
    // Read datagrams from this direct link into TUN.
    let mesh_drop = Arc::clone(mesh);
    let peer_vip_c = peer_vip;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = conn.closed() => break,
                r = conn.read_datagram() => {
                    match r {
                        Ok(data) => {
                            let Some(src) = ipv4_src(&data) else { continue };
                            if src != peer_vip_c {
                                continue;
                            }
                            tun.send(data).await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let mut g = mesh_drop.write().await;
        g.direct.remove(&peer_vip_c);
        info!(%peer_id, %peer_vip_c, "{}", tr!("direct mesh link closed"));
    });
}

async fn spoke_try_dial_peer(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    entry: RosterEntry,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
) {
    if entry.id == own_id || entry.vip == own_vip {
        return;
    }
    if let Err(e) = check_allow(allow.as_ref(), entry.id) {
        warn!(peer = %entry.id, error = format!("{e:#}"), "{}", tr!("skipping mesh peer (not allowed)"));
        return;
    }
    if !should_dial(own_id, entry.id) {
        return;
    }
    {
        let g = mesh.read().await;
        if g.direct.contains_key(&entry.vip) {
            return;
        }
    }
    let dial = EndpointAddr::from(entry.id);
    match endpoint.connect(dial, TUN_ALPN).await {
        Ok(conn) => {
            match exchange_peer_vip(&conn, own_vip, true).await {
                Ok(vip) if vip == entry.vip => {
                    // Spokes do not open a roster control stream on direct links.
                    spoke_install_direct(
                        &mesh,
                        tun,
                        &tun_name,
                        own_vip,
                        entry.id,
                        vip,
                        conn,
                        user_mtu,
                        raise_gate,
                    )
                    .await;
                }
                Ok(vip) => {
                    warn!(
                        peer = %entry.id,
                        expected = %entry.vip,
                        got = %vip,
                        "{}",
                        tr!("direct mesh VIP mismatch; closing")
                    );
                }
                Err(e) => {
                    warn!(peer = %entry.id, error = format!("{e:#}"), "{}", tr!("direct mesh VIP exchange failed"));
                }
            }
        }
        Err(e) => {
            info!(peer = %entry.id, error = %e, "{}", tr!("direct mesh dial failed; using hub fallback"));
        }
    }
}

async fn spoke_apply_roster_msg(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    msg: RosterMsg,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
    quiet: bool,
) {
    match msg {
        RosterMsg::Snapshot(entries) => {
            for e in entries {
                if e.id == own_id {
                    continue;
                }
                mesh.write().await.roster.insert(e.id, e.vip);
                let ep = endpoint.clone();
                let mesh = Arc::clone(&mesh);
                let tun = tun.clone();
                let tun_name = tun_name.clone();
                let allow = allow.clone();
                let raise_gate = Arc::clone(&raise_gate);
                tokio::spawn(async move {
                    spoke_try_dial_peer(
                        ep,
                        mesh,
                        tun,
                        tun_name,
                        own_id,
                        own_vip,
                        e,
                        user_mtu,
                        allow,
                        raise_gate,
                    )
                    .await;
                });
            }
        }
        RosterMsg::Joined(e) => {
            if e.id == own_id {
                return;
            }
            mesh.write().await.roster.insert(e.id, e.vip);
            if !quiet {
                println!(
                    "{}",
                    tr_fmt!("mesh peer {0} at {1}", e.id.fmt_short(), e.vip)
                );
            }
            tokio::spawn(spoke_try_dial_peer(
                endpoint,
                mesh,
                tun,
                tun_name,
                own_id,
                own_vip,
                e,
                user_mtu,
                allow,
                raise_gate,
            ));
        }
        RosterMsg::Left(e) => {
            let mut g = mesh.write().await;
            g.roster.remove(&e.id);
            g.direct.remove(&e.vip);
            info!(peer = %e.id, vip = %e.vip, "{}", tr!("mesh peer left"));
        }
    }
}

/// Connecting side (`tun connect`): join a hub mesh, learn the roster, try
/// direct spoke links, fall back to hub forward.
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_connect(
    secret_key: SecretKey,
    to: &str,
    tun_ip: Option<Ipv4Addr>,
    mtu: u16,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    allow: Option<HashSet<EndpointId>>,
    ui: crate::Ui,
    styler: Styler,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    crate::reject_relay_only_with_to_addr(relay_only, &to_addr)?;
    let endpoint = crate::build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0_relays,
    )?
        .alpns(vec![TUN_ALPN.to_vec(), crate::PING_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| {
            crate::exit::coded(
                crate::exit::CONNECT,
                anyhow::Error::new(e).context(tr!("binding endpoint")),
            )
        })?;

    let hub_id: EndpointId = match to.parse() {
        Ok(id) => id,
        Err(e) => {
            let err = anyhow::Error::new(e)
                .context(tr_fmt!("'{0}' is not a valid EndpointId", to));
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{err:#}")));
            }
            endpoint.close().await;
            return Err(err);
        }
    };
    let own_id = endpoint.id();
    let own_vip = tun_ip.unwrap_or_else(|| derive_vip(own_id));
    let signal_err = |e: &anyhow::Error| {
        if let Some(h) = &hooks {
            h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
        }
    };
    if let Err(e) = ensure_vip_free(own_vip) {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    if let Err(e) = crate::wait_online(&endpoint).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    if let Err(e) = crate::install_extra_relays(&endpoint, relay, no_n0_relays).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }

    let dial_addr = match crate::build_dial_addr(hub_id, relay, &to_addr) {
        Ok(a) => a,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if !to_addr.is_empty() && hooks.is_none() {
        ui.line(format!(
            "  {}",
            styler.dim(&tr_fmt!(
                "dialing the peer's direct address hint(s): {0}",
                to_addr
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        ));
    }

    let (tun, tun_name) = match create_tun_device(own_vip, mtu) {
        Ok(x) => x,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Some(h) = &hooks {
        h.state.set_vip(own_vip).await;
        // Spoke ready after TUN exists; hub dial may still be in progress.
        h.signal_ready(Ok(()));
    }
    let (tun_io, mut from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let mesh: SharedSpokeMesh = Arc::new(RwLock::new(SpokeMesh::new(own_id, own_vip)));

    // Long-lived TUN → mesh demux (hub and direct outs live in SpokeMesh).
    {
        let mesh_d = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some(pkt) = from_tun.recv().await {
                let Some(dst) = ipv4_dst(&pkt) else { continue };
                if dst == own_vip {
                    continue;
                }
                let out = mesh_d.read().await.lookup_out(dst);
                if let Some(tx) = out {
                    let _ = tx.try_send(pkt);
                }
            }
        });
    }

    // Accept inbound direct mesh dials (and ping) for the process lifetime.
    {
        let endpoint_acc = endpoint.clone();
        let mesh_acc = Arc::clone(&mesh);
        let tun_acc = tun_io.clone();
        let tun_name_acc = tun_name.clone();
        let allow_acc = allow.clone();
        let raise_gate_acc = Arc::clone(&raise_gate);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_acc.accept().await {
                let Ok(accepting) = incoming.accept() else { continue };
                let Ok(conn) = accepting.await else { continue };
                if conn.alpn() == crate::PING_ALPN {
                    handle_ping_probe(conn);
                    continue;
                }
                if conn.alpn() != TUN_ALPN {
                    continue;
                }
                let peer = conn.remote_id();
                if let Err(e) = check_allow(allow_acc.as_ref(), peer) {
                    warn!(%peer, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    conn.close(0u32.into(), b"denied");
                    continue;
                }
                // Only accept if we are the lower id (tie-break): the other side dials.
                if should_dial(own_id, peer) {
                    conn.close(0u32.into(), b"tie-break");
                    continue;
                }
                let tun = tun_acc.clone();
                let mesh = Arc::clone(&mesh_acc);
                let tun_name = tun_name_acc.clone();
                let raise_gate = Arc::clone(&raise_gate_acc);
                tokio::spawn(async move {
                    match exchange_peer_vip(&conn, own_vip, false).await {
                        Ok(vip) => {
                            spoke_install_direct(
                                &mesh,
                                tun,
                                &tun_name,
                                own_vip,
                                peer,
                                vip,
                                conn,
                                mtu,
                                raise_gate,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(%peer, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                        }
                    }
                });
            }
        });
    }

    let mut connected_once = false;
    let mut backoff = crate::Backoff::new(crate::RECONNECT_BASE, crate::RECONNECT_MAX);
    let mut delay: Option<Duration> = None;
    loop {
        if let Some(d) = delay {
            tokio::select! {
                _ = time::sleep(d) => {}
                _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                    ui.line(styler.warn(&tr!("shutting down...")));
                    endpoint.close().await;
                    return Ok(());
                }
                _ = async {
                    match &hooks {
                        Some(h) => h.cancel.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!("{}", tr!("TUN daemon Shutdown requested"));
                    endpoint.close().await;
                    return Ok(());
                }
            }
        }

        ui.line(styler.info(&tr_fmt!("dialing {0}...", hub_id)));
        let session_started = Instant::now();
        let session = async {
            let conn = endpoint
                .connect(dial_addr.clone(), TUN_ALPN)
                .await
                .map_err(|e| {
                    crate::exit::coded(
                        crate::exit::CONNECT,
                        anyhow::Error::new(e).context(tr!("connecting to remote endpoint")),
                    )
                })?;
            let hub_vip = exchange_peer_vip(&conn, own_vip, true).await?;

            // Control stream for roster (we are dialer → open_bi).
            let (ctrl_send, mut ctrl_recv) = conn
                .open_bi()
                .await
                .context(tr!("opening TUN roster control stream"))?;
            drop(ctrl_send); // hub writes; we only read

            let user_mtu = mtu;
            let mut session_mtu = choose_mtu(user_mtu, &conn)?;
            set_tun_mtu(&tun_name, session_mtu)?;
            add_mesh_route(&tun_name)?;
            info!(peer_id = %hub_id, path = path_label(&conn), "{}", tr_fmt!(
                "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
                conn.max_datagram_size().unwrap_or_default(),
                session_mtu
            ));
            crate::spawn_path_monitor(
                conn.clone(),
                hub_id,
                endpoint.clone(),
                relay_only,
                styler,
                ui.quiet,
            );

            if let Some(h) = &hooks {
                h.state.set_path_kind(path_label(&conn)).await;
            }

            let (hub_tx, hub_rx) = mpsc::channel::<Bytes>(256);
            spawn_conn_sender(
                tun_io.clone(),
                tun_name.clone(),
                own_vip,
                hub_id,
                conn.clone(),
                hub_rx,
                user_mtu,
                Arc::clone(&raise_gate),
            );
            {
                let mut g = mesh.write().await;
                g.hub_vip = Some(hub_vip);
                g.hub_out = Some(hub_tx);
                g.roster.insert(hub_id, hub_vip);
            }

            if !connected_once {
                connected_once = true;
                if hooks.is_none() {
                    ui.line(styler.ok(&tr_fmt!("connected. your virtual IP: {0}", own_vip)));
                    ui.line(styler.dim(&tr_fmt!(
                        "hub {0} is at {1} (path {2}); peers may connect directly",
                        hub_id.fmt_short(),
                        hub_vip,
                        path_label(&conn)
                    )));
                    ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));
                }
            }

            if let Some(h) = &hooks {
                let peers: Vec<CtlPeer> = mesh
                    .read()
                    .await
                    .roster
                    .iter()
                    .map(|(id, vip)| CtlPeer {
                        vip: *vip,
                        id: id.to_string(),
                    })
                    .collect();
                h.state.set_peers(peers).await;
            }

            // Roster reader
            let endpoint_r = endpoint.clone();
            let mesh_r = Arc::clone(&mesh);
            let tun_r = tun_io.clone();
            let tun_name_r = tun_name.clone();
            let allow_r = allow.clone();
            let raise_gate_r = Arc::clone(&raise_gate);
            let quiet_r = ui.quiet;
            let roster_task = tokio::spawn(async move {
                loop {
                    match read_msg(&mut ctrl_recv).await {
                        Ok(msg) => {
                            spoke_apply_roster_msg(
                                endpoint_r.clone(),
                                Arc::clone(&mesh_r),
                                tun_r.clone(),
                                tun_name_r.clone(),
                                own_id,
                                own_vip,
                                msg,
                                user_mtu,
                                allow_r.clone(),
                                Arc::clone(&raise_gate_r),
                                quiet_r,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(error = format!("{e:#}"), "{}", tr!("roster control stream closed"));
                            break;
                        }
                    }
                }
            });

            // Hub → TUN
            let tun_h = tun_io.clone();
            let hub_vip_c = hub_vip;
            let conn_r = conn.clone();
            let hub_read = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = conn_r.closed() => break,
                        r = conn_r.read_datagram() => {
                            match r {
                                Ok(data) => {
                                    let Some(src) = ipv4_src(&data) else { continue };
                                    if !vip_in_mesh(src) && src != hub_vip_c {
                                        continue;
                                    }
                                    tun_h.send(data).await;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            let end = loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                        ui.line(styler.warn(&tr!("shutting down...")));
                        break SessionEnd::CtrlC;
                    }
                    _ = async {
                        match &hooks {
                            Some(h) => h.cancel.notified().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("{}", tr!("TUN daemon Shutdown requested"));
                        break SessionEnd::CtrlC;
                    }
                    _ = conn.closed() => {
                        info!(peer_id = %hub_id, "{}", tr!("peer disconnected"));
                        break SessionEnd::PeerGone;
                    }
                    _ = time::sleep(Duration::from_secs(2)) => {
                        let _ = refresh_tun_mtu(
                            &tun_name,
                            user_mtu,
                            &conn,
                            &mut session_mtu,
                            raise_after_now(&raise_gate),
                        );
                        if let Some(h) = &hooks {
                            h.state.set_path_kind(path_label(&conn)).await;
                        }
                    }
                }
            };

            roster_task.abort();
            hub_read.abort();
            mesh.write().await.clear_hub();
            Ok::<_, anyhow::Error>((end, true))
        }
        .await;

        let (end, had_route) = match session {
            Ok(x) => x,
            Err(e) => {
                warn!(peer_id = %hub_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                (SessionEnd::PeerGone, false)
            }
        };
        if matches!(end, SessionEnd::CtrlC) {
            if had_route {
                let _ = del_mesh_route(&tun_name);
            }
            break;
        }
        let lived = session_started.elapsed();
        if let Some(next) = backoff.after_session(lived, crate::MIN_STABLE_CONN) {
            delay = Some(next);
            info!(
                peer_id = %hub_id,
                lived_ms = lived.as_millis() as u64,
                "{}",
                tr_fmt!("reconnecting in {0}", format!("{next:?}"))
            );
        } else {
            // Stable session ended — redial without climbing backoff, but
            // still take the base delay so we don't hot-loop on a flapping hub.
            let next = crate::RECONNECT_BASE;
            delay = Some(next);
            info!(peer_id = %hub_id, "{}", tr_fmt!("reconnecting in {0}", format!("{next:?}")));
        }
    }
    let _ = del_mesh_route(&tun_name);
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

    #[test]
    fn vip_mesh_prefix_and_ipv4_headers() {
        assert!(vip_in_mesh(Ipv4Addr::new(172, 24, 1, 2)));
        assert!(!vip_in_mesh(Ipv4Addr::new(172, 25, 0, 1)));
        assert!(!vip_in_mesh(Ipv4Addr::new(10, 0, 0, 1)));

        let pkt = sample_ipv4_tcp(
            Ipv4Addr::new(172, 24, 0, 1),
            Ipv4Addr::new(172, 24, 0, 2),
            40,
        );
        assert_eq!(ipv4_src(&pkt), Some(Ipv4Addr::new(172, 24, 0, 1)));
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(172, 24, 0, 2)));
        assert!(ipv4_dst(&[]).is_none());
    }
}
