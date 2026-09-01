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
//!
//! Layer-3 VIP mesh on QUIC datagrams (hub / spoke).
//!
//! Submodules: [`hub`], [`spoke`]. Shared VIP/device/MTU/I/O helpers remain here
//! until a further `device` / `mtu` split is worth the churn.

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
    encode_hello, encode_joined, encode_left, encode_snapshot, read_hello, read_msg, should_dial,
    write_msg, RosterEntry, RosterMsg,
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
/// Low 16 bits kept from the EndpointId hash — host portion of the /16 mesh.
const VIP_HOST_MASK: u32 = 0x0000_FFFF;
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
    pending_calls: RwLock<Vec<crate::tun_ctl::PendingCall>>,
}

/// Commands from the control plane into phone-mode data plane.
#[derive(Debug, Clone)]
pub enum CallCmd {
    Dial { to: String },
    Accept { peer: String },
    Reject { peer: String },
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
            pending_calls: RwLock::new(Vec::new()),
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

    pub async fn set_pending_calls(&self, calls: Vec<crate::tun_ctl::PendingCall>) {
        *self.pending_calls.write().await = calls;
    }

    pub async fn status_response(&self) -> CtlResponse {
        CtlResponse::Status {
            role: self.role.clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            vip: self.vip.read().await.unwrap_or(Ipv4Addr::UNSPECIFIED),
            path_kind: self.path_kind.read().await.clone(),
            session: self.session.clone(),
            pending_calls: self.pending_calls.read().await.clone(),
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
    /// Phone-mode command sink (set by [`phone::run_tun_phone`]).
    call_tx: StdMutex<Option<mpsc::Sender<CallCmd>>>,
}

impl TunHooks {
    pub fn new(state: Arc<TunLiveState>) -> (Self, oneshot::Receiver<Result<()>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                cancel: Arc::new(Notify::new()),
                state,
                ready: StdMutex::new(Some(tx)),
                call_tx: StdMutex::new(None),
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

    pub fn register_call_tx(&self, tx: mpsc::Sender<CallCmd>) {
        if let Ok(mut g) = self.call_tx.lock() {
            *g = Some(tx);
        }
    }

    pub fn try_send_call_cmd(&self, cmd: CallCmd) -> Result<()> {
        let tx = self
            .call_tx
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(tr!(
                    "TUN daemon is not in phone mode (start with `tun up --role phone` or `tun call`)"
                ))
            })?;
        tx.try_send(cmd).map_err(|_| {
            anyhow::anyhow!(tr!("TUN phone call queue is full; try again"))
        })?;
        Ok(())
    }
}

fn vip_in_mesh(ip: Ipv4Addr) -> bool {
    u32::from(ip) & !VIP_HOST_MASK == VIP_BASE
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
    Ipv4Addr::from(VIP_BASE | (raw & VIP_HOST_MASK))
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
/// PMTUD probe is still at its RFC 9000 starting value (1200). There is no
/// extra "subtract N" fudge in this function — conservativeness comes from
/// clamping to that early `max_datagram_size()` (e.g. 1162 instead of the
/// design's 1280). The datagram loop re-checks periodically and raises the
/// TUN MTU once PMTUD has converged (see run_datagram_loop).
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
///
/// Hardening: canonicalize the executable directory and refuse Temporary /
/// Downloads-style locations where a planted DLL is a realistic attack. The
/// intended install layout is `Program Files\link-p2p\link-p2p.exe` + sibling
/// `wintun.dll` (service install already rejects user-writable binary paths).
#[cfg(windows)]
pub(crate) fn wintun_dll_selftest_path() -> Result<std::path::PathBuf> {
    wintun_dll_beside_exe()
}

/// Resolve `wintun.dll` beside `link-p2p.exe` (not via PATH).
///
/// Hardening: canonicalize the executable directory and refuse Temporary /
/// Downloads-style locations where a planted DLL is a realistic attack. The
/// intended install layout is `Program Files\link-p2p\link-p2p.exe` + sibling
/// `wintun.dll` (service install already rejects user-writable binary paths).
#[cfg(windows)]
fn wintun_dll_beside_exe() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context(tr!("resolving path to this executable"))?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let dir = exe
        .parent()
        .context(tr!("resolving directory of this executable"))?
        .to_path_buf();

    if is_untrusted_wintun_dir(&dir) {
        bail!(tr_fmt!(
            "refusing to load wintun.dll from a temporary or download directory ({0}); \
             install link-p2p to a trusted path (e.g. Program Files) with the official signed DLL beside the executable",
            dir.display().to_string()
        ));
    }

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
    // Prefer the canonical path so LoadLibrary sees a resolved location.
    Ok(std::fs::canonicalize(&dll).unwrap_or(dll))
}

/// Paths where a co-located DLL is untrusted (writable by the user who also
/// runs elevated TUN). Program Files / Windows are *trusted* for our layout.
#[cfg(windows)]
fn is_untrusted_wintun_dir(dir: &std::path::Path) -> bool {
    let lower = dir.to_string_lossy().to_ascii_lowercase();
    let markers = [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "/temp/",
        "/tmp/",
        "/downloads/",
    ];
    if markers.iter().any(|m| lower.contains(m)) {
        return true;
    }
    for key in ["TEMP", "TMP"] {
        if let Ok(t) = std::env::var(key) {
            let t = std::path::PathBuf::from(t);
            if let Ok(canon) = std::fs::canonicalize(&t) {
                if dir.starts_with(&canon) {
                    return true;
                }
            } else if dir.starts_with(&t) {
                return true;
            }
        }
    }
    false
}

#[cfg(all(test, windows))]
mod wintun_path_tests {
    use super::is_untrusted_wintun_dir;
    use std::path::Path;

    #[test]
    fn program_files_is_trusted() {
        assert!(!is_untrusted_wintun_dir(Path::new(
            r"C:\Program Files\link-p2p"
        )));
    }

    #[test]
    fn temp_is_untrusted() {
        assert!(is_untrusted_wintun_dir(Path::new(
            r"C:\Users\alice\AppData\Local\Temp\link-p2p"
        )));
        assert!(is_untrusted_wintun_dir(Path::new(
            r"C:\Users\alice\Downloads\link-p2p"
        )));
    }
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

/// Internet checksum (RFC 1071) over `data`.
///
/// Words are big-endian. An odd trailing byte is paired with a zero low
/// octet (`[b, 0]`), i.e. treated as the high-order half of the last word —
/// the standard "pad with zero" rule, not little-endian packing.
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

fn path_label(conn: &Connection) -> &'static str {
    crate::path_kind::path_label(conn)
}

pub(crate) fn check_allow(allow: Option<&HashSet<EndpointId>>, peer: EndpointId) -> Result<()> {
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
pub(crate) struct TunIo {
    /// Packets to write into the TUN (spoke→hub local delivery, ICMP PTB).
    to_tun: mpsc::Sender<Bytes>,
}

impl TunIo {
    async fn send(&self, pkt: Bytes) {
        let _ = self.to_tun.send(pkt).await;
    }
}

pub(crate) fn spawn_tun_io(
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
pub(crate) fn spawn_peer_sender(
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


pub(crate) mod hub;
pub(crate) mod phone;
pub(crate) mod spoke;

pub use hub::run_tun_serve;
pub use phone::run_tun_phone;
pub use spoke::run_tun_connect;

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
        // One / many all-ones words: one's-complement sum stays 0xffff → 0.
        assert_eq!(inet_checksum(&[0xff, 0xff]), 0x0000);
        assert_eq!(inet_checksum(&[0xff; 40]), 0x0000);
        // Odd length: trailing 0xff → word 0xff00.
        assert_eq!(inet_checksum(&[0xff]), !0xff00u16);
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
