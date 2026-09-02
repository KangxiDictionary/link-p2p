//! Shared endpoint session helpers used by stream, call, and TUN modes.
//!
//! Identity loading stays in [`crate::identity`]; clap lives in [`crate::cli`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{
    endpoint::{presets, Connection, QuicTransportConfig, RecvStream, SendStream, VarInt},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
};
use noq_proto::congestion::{Bbr3Config, CubicConfig};
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{info, warn, Instrument};

use crate::cli::CongestionControl;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::path_kind;
use crate::pipe;
use crate::socks5;
use crate::ssrf::{check_proxy_target, dial_checked};
use crate::style::Styler;

pub(crate) const ALPN: &[u8] = b"link-p2p/tcp-forward/1";

/// ALPN for the `ping` probe (echoes a timestamp, reports RTT and path).
/// Separate from the forwarding ALPN so a ping can target a node that is
/// also serving streams — the Router accepts both. Also registered on TUN
/// nodes (see tun.rs) so `ping` works against `tun serve` too.
pub(crate) const PING_ALPN: &[u8] = b"link-p2p/ping/0";

/// Tunables applied on top of iroh/noq transport defaults.
#[derive(Clone, Debug, Default)]
pub(crate) struct TransportTune {
    pub(crate) cc: Option<CongestionControl>,
    pub(crate) send_window: Option<u64>,
    pub(crate) stream_recv_window: Option<u64>,
}

/// User-facing status lines: respect `-q` and keep stdout clean in `--stdio`.
#[derive(Clone, Copy)]
pub(crate) struct Ui {
    pub(crate) quiet: bool,
    pub(crate) stderr_only: bool,
}

impl Ui {
    pub(crate) fn line(self, s: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        if self.stderr_only {
            eprintln!("{}", s.as_ref());
        } else {
            println!("{}", s.as_ref());
        }
    }
}

/// Shared `--max-conns` → semaphore mapping (`0` = unlimited).
pub(crate) fn conn_semaphore(max_conns: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(if max_conns == 0 {
        usize::MAX
    } else {
        max_conns
    }))
}

/// Push a JoinHandle into a shared task list, surviving a poisoned mutex.
pub(crate) fn push_task(tasks: &Mutex<Vec<JoinHandle<()>>>, task: JoinHandle<()>) {
    match tasks.lock() {
        Ok(mut g) => g.push(task),
        Err(poisoned) => poisoned.into_inner().push(task),
    }
}

/// Serve mode — exactly one of fixed forward or proxy. Encoded as an enum so
/// "neither / both" cannot be represented after CLI validation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ServeMode {
    Forward(SocketAddr),
    Proxy { allow_private: bool },
}

/// Connect local side — listen, SOCKS5, or (Unix) stdio.

pub(crate) fn resolve_peer_to(to: Option<String>, stdio: bool) -> Result<String> {
    let raw = to
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("missing peer EndpointId (--to or LINK_P2P_TO)")),
            )
        })?;
    if raw == "-" {
        #[cfg(not(unix))]
        {
            let _ = stdio;
            return Err(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("--to - (read EndpointId from stdin) is only available on Unix builds")),
            ));
        }
        #[cfg(unix)]
        {
            if stdio {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("--to - cannot be combined with --stdio (stdin conflict)")),
                ));
            }
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context(tr!("reading EndpointId from stdin"))?;
            let id = line.trim();
            if id.is_empty() {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("empty EndpointId on stdin")),
                ));
            }
            if let Some(rest) = id.strip_prefix("ENDPOINT_ID=") {
                return Ok(rest.trim().to_string());
            }
            return Ok(id.to_string());
        }
    }
    Ok(raw)
}

/// CLI `--allow` wins; otherwise parse comma-separated `LINK_P2P_ALLOW`.
pub(crate) fn merge_allow_list(cli: Vec<String>) -> Vec<String> {
    if !cli.is_empty() {
        return cli;
    }
    match std::env::var("LINK_P2P_ALLOW") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse TUN `--allow` / `LINK_P2P_ALLOW` into a set; `None` means open.
pub(crate) fn parse_tun_allow(cli: Vec<String>) -> Result<Option<HashSet<EndpointId>>> {
    let allow = merge_allow_list(cli);
    if allow.is_empty() {
        return Ok(None);
    }
    let mut set = HashSet::new();
    for s in &allow {
        let id: EndpointId = s.parse().map_err(|e| {
            exit::coded(
                exit::USAGE,
                anyhow::Error::new(e).context(tr_fmt!(
                    "'{0}' is not a valid EndpointId in --allow",
                    s
                )),
            )
        })?;
        set.insert(id);
    }
    Ok(Some(set))
}


/// Documented bring-up order for a freshly bound endpoint. Kept as a constant
/// so a unit test can pin the regression that broke custom relays behind n0
/// (`wait_online` before `install_extra_relays`).
pub(crate) const ENDPOINT_ONLINE_STEPS: &[&str] = &["install_extra_relays", "wait_online"];

/// Wait up to 30s for the endpoint to establish a network path.
///
/// Prefer [`bring_endpoint_online`] after `bind` so custom `--relay` URLs are
/// installed first when the builder still uses the N0 preset. This standalone
/// helper remains for callers that already installed relays (or use n0-only).
///
/// Quick check: `nc -u -v -w3 8.8.8.8 53` should get a response. If it
/// hangs or is refused, UDP outbound is blocked.
#[allow(dead_code)]
pub(crate) async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    wait_online_ctx(endpoint, &[], true).await
}

async fn wait_online_ctx(endpoint: &Endpoint, relay: &[String], no_n0_relays: bool) -> Result<()> {
    const ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
    match time::timeout(ONLINE_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_elapsed) => {
            let custom_hint = if !relay.is_empty() && !no_n0_relays {
                tr!(
                    "\n\
                     You passed --relay without --no-n0-relays: the endpoint still\n\
                     starts on n0's public relays. If n0 is blocked on this network,\n\
                     either add --no-n0-relays (custom relay only) or ensure UDP to\n\
                     n0 works. Custom URLs are installed before this wait; if you\n\
                     still time out, probe your relay with `link-p2p selftest`."
                )
            } else if !relay.is_empty() && no_n0_relays {
                tr!(
                    "\n\
                     --no-n0-relays is set: only your --relay URL(s) are used.\n\
                     Check that the relay is reachable (TCP) and accepts QUIC/UDP.\n\
                     Try: link-p2p selftest"
                )
            } else {
                String::new()
            };
            Err(exit::coded(
                exit::TIMEOUT,
                anyhow::anyhow!(tr_fmt!(
                    "endpoint did not come online within {0}.\n\
                     \n\
                     The most likely cause: outgoing UDP is blocked by a firewall.\n\
                     iroh/QUIC relies on UDP for both direct hole-punching and\n\
                     relay connections. Try:\n\
                       link-p2p selftest               # relay TCP probe + loopback\n\
                       nc -u -v -w3 8.8.8.8 53         # does UDP egress work at all?\n\
                       RUST_LOG=iroh=debug {1}          # see exactly where it's stuck{2}",
                    format!("{ONLINE_TIMEOUT:?}"),
                    std::env::args().next().unwrap_or_else(|| "link-p2p".into()),
                    custom_hint
                )),
            ))
        }
    }
}

/// Install any custom relays (N0-base builds), then wait until the endpoint is online.
///
/// **Order is load-bearing.** With `--relay` and without `--no-n0-relays`, the
/// builder keeps [`presets::N0`] and custom URLs are added only via
/// [`install_extra_relays`]. Waiting for `online()` *before* that install left
/// the endpoint racing solely against n0 — hanging when n0 is blocked even
/// though a self-hosted relay would have worked.
pub(crate) async fn bring_endpoint_online(
    endpoint: &Endpoint,
    relay: &[String],
    no_n0_relays: bool,
) -> Result<()> {
    debug_assert_eq!(ENDPOINT_ONLINE_STEPS[0], "install_extra_relays");
    debug_assert_eq!(ENDPOINT_ONLINE_STEPS[1], "wait_online");
    install_extra_relays(endpoint, relay, no_n0_relays).await?;
    wait_online_ctx(endpoint, relay, no_n0_relays).await
}

/// Build an endpoint.
///
/// - `relay` empty → [`presets::N0`] (public relays + discovery).
/// - `relay` non-empty and `no_n0_relays` → [`presets::Minimal`] + custom map only.
/// - `relay` non-empty and not `no_n0_relays` → N0 base (keeps discovery); call
///   [`bring_endpoint_online`] after `bind` (installs custom URLs, then waits).
///
/// `relay_only` clears IP transports (true relay-only baseline).
pub(crate) fn build_endpoint(
    secret_key: SecretKey,
    relay: &[String],
    keepalive: Duration,
    idle_timeout: Duration,
    tune: &TransportTune,
    relay_only: bool,
    no_n0_relays: bool,
) -> Result<iroh::endpoint::Builder> {
    let transport = transport_config(keepalive, idle_timeout, tune)?;
    let builder = if relay.is_empty() {
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .transport_config(transport)
    } else if no_n0_relays {
        let relay_map = RelayMap::try_from_iter(relay.iter().map(|s| s.as_str()))
            .with_context(|| {
                tr_fmt!(
                    "invalid --relay URL in list: {0}",
                    relay.join(", ")
                )
            })?;
        Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .transport_config(transport)
            .relay_mode(RelayMode::Custom(relay_map))
    } else {
        // Keep n0 discovery + public relays; extras via install_extra_relays.
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .transport_config(transport)
    };
    if relay_only {
        Ok(builder
            .clear_ip_transports()
            .addr_filter(iroh::address_lookup::AddrFilter::relay_only()))
    } else {
        Ok(builder)
    }
}

/// Insert custom relay URLs into a live endpoint that was built with n0 base.
pub(crate) async fn install_extra_relays(
    endpoint: &Endpoint,
    relay: &[String],
    no_n0_relays: bool,
) -> Result<()> {
    if no_n0_relays || relay.is_empty() {
        return Ok(());
    }
    for raw in relay {
        let url: iroh::RelayUrl = raw
            .parse()
            .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", raw))?;
        let cfg = std::sync::Arc::new(iroh::RelayConfig::from(url.clone()));
        endpoint.insert_relay(url, cfg).await;
    }
    Ok(())
}

pub(crate) fn reject_relay_only_with_to_addr(relay_only: bool, to_addr: &[SocketAddr]) -> Result<()> {
    if relay_only && !to_addr.is_empty() {
        return Err(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "--relay-only cannot be combined with --to-addr (direct IP hints)"
            )),
        ));
    }
    Ok(())
}

/// Build the [`EndpointAddr`] used to dial a peer: the peer's EndpointId,
/// optionally pinned down by a custom relay URL and/or out-of-band direct
/// address hints (`--to-addr`).
///
/// Order of preference is up to iroh: the direct IP hints are tried first
/// when reachable; the relay (if given) and discovery (if no relay is given)
/// act as fallbacks for NAT traversal. Passing only direct hints and no
/// relay means no DNS/pkarr lookup happens at all — the peer is dialed
/// straight through the given addresses.
pub(crate) fn build_dial_addr(
    peer_id: EndpointId,
    relay: &[String],
    to_addr: &[SocketAddr],
) -> Result<EndpointAddr> {
    let mut addr = EndpointAddr::from(peer_id);
    for relay_url in relay {
        let relay_url = relay_url
            .parse()
            .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
        addr = addr.with_relay_url(relay_url);
    }
    // With no custom relays, dial by EndpointId alone and let n0 discovery
    // (or --to-addr hints below) supply reachability.
    for a in to_addr {
        addr = addr.with_ip_addr(*a);
    }
    Ok(addr)
}

/// QUIC transport parameters shared by every mode.
///
/// The keepalive interval keeps NAT UDP mappings alive: they typically
/// expire after 20-30s, so a tunnel idle for longer than that would be
/// silently dropped by intermediate devices. 5s is also iroh's own default;
/// it's set here explicitly so the contract is self-documenting.
///
/// The idle timeout is relaxed from iroh's 15s default to 30s: a longer
/// window lets the peer survive brief path switches (iroh connection
/// migration) and relay hiccups without being declared dead, while still
/// detecting a genuinely gone peer within a reasonable time.
///
/// Both are CLI-tunable (`--keepalive`, `--idle-timeout`) because the right
/// value depends on the network: aggressive home-router NATs want a shorter
/// keepalive, high-latency or lossy links want a longer idle timeout.
pub(crate) fn transport_config(
    keepalive: Duration,
    idle_timeout: Duration,
    tune: &TransportTune,
) -> Result<QuicTransportConfig> {
    let mut b = QuicTransportConfig::builder()
        .keep_alive_interval(keepalive)
        .max_idle_timeout(Some(idle_timeout.try_into()?));
    // Defaults are CUBIC + ~100Mbps/100ms windows (noq). Override only when
    // the operator asked — see docs/architecture/performance.md and the transport matrix.
    match tune.cc {
        Some(CongestionControl::Cubic) => {
            b = b.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        Some(CongestionControl::Bbr3) => {
            b = b.congestion_controller_factory(Arc::new(Bbr3Config::default()));
        }
        None => {}
    }
    if let Some(w) = tune.send_window {
        b = b.send_window(w);
    }
    if let Some(w) = tune.stream_recv_window {
        b = b.stream_receive_window(VarInt::from_u64(w).map_err(|_| {
            anyhow::anyhow!(tr!("--stream-recv-window / LINK_P2P_STREAM_RECV_WINDOW out of range"))
        })?);
    }
    Ok(b.build())
}

#[derive(Debug)]
pub(crate) struct PingHandler;

impl ProtocolHandler for PingHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // connection ended
            };
            let mut ts = [0u8; 8];
            if recv.read_exact(&mut ts).await.is_err() {
                continue;
            }
            if send.write_all(&ts).await.is_err() {
                continue;
            }
            let _ = send.finish();
        }
        Ok(())
    }
}

/// Dial the target and pipe bytes between it and the given QUIC stream.
pub(crate) async fn handle_forward_stream(
    mode: ServeMode,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    match mode {
        ServeMode::Forward(addr) => {
            // Fixed-forward: consume STREAM_HELLO before dialing so accept_bi
            // completes as soon as the connect side opens the stream — not
            // when the local TCP client eventually writes (or FIN)s.
            pipe::read_stream_hello(&mut recv).await?;
            let tcp = TcpStream::connect(addr)
                .await
                .with_context(|| tr_fmt!("connecting to {0}", addr))?;
            tracing::debug!("DBG forward: connected to {addr}, starting pipe_streams");
            pipe::pipe_streams(tcp, send, recv).await
        }
        ServeMode::Proxy { allow_private } => {
            // Proxy already has an on-wire header (`write_target` / read_target).
            // Resolve once → SSRF check → dial the same CheckedTarget (no
            // second lookup — type system blocks reconnecting a fresh resolve).
            let raw = socks5::read_target(&mut recv).await?.resolve().await?;
            let checked = check_proxy_target(raw, allow_private)?;
            let addr = checked.addr();
            let tcp = dial_checked(checked).await?;
            tracing::debug!("DBG forward: connected to {addr}, starting pipe_streams");
            pipe::pipe_streams(tcp, send, recv).await
        }
    }
}

/// Path / throughput monitor for a live session.
///
/// - Every 30s: debug-log path kind + Quinn counters (path from
///   [`Connection::paths`], not `udp_tx/rx` heuristics).
/// - While not on a direct path and not `--relay-only`: every ~45s call
///   [`Endpoint::network_change`] so magicsock re-STUNs / retries hole-punch
///   (home NAT mappings drift; a single settle at connect is not enough).
/// - If traffic is active but stuck under a low ceiling while still on relay,
///   warn once that public relays rate-limit (self-host / wait for direct).
pub(crate) fn spawn_path_monitor(
    connection: Connection,
    peer: EndpointId,
    endpoint: Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
    cmd: &'static str,
) -> tokio::task::JoinHandle<()> {
    /// Sample window for path stats + slow-relay detection.
    const STATS_SECS: u64 = 30;
    /// How often to nudge magicsock while still on relay (and not relay-permanent).
    const UPGRADE_SECS: u64 = 45;
    /// After this many pure-relay (no IP candidate) samples, slow upgrades.
    const RELAY_PERM_STREAK: u8 = 4;
    /// Backed-off upgrade interval for peers that never show a direct candidate.
    const UPGRADE_SECS_PERMANENT: u64 = 300;
    /// Sustained under this (with real traffic) → treat as relay-shaped ceiling.
    const RELAY_SLOW_BPS: u64 = 128 * 1024;
    /// Ignore idle windows (keepalive alone).
    const ACTIVE_MIN_BPS: u64 = 2 * 1024;

    // Soft preference from path_stats: we cannot pick candidates (iroh owns
    // that); we only modulate how aggressively we call network_change().
    let hist = crate::path_stats::peer_direct_rates(None)
        .get(&peer.to_string())
        .copied();
    let (upgrade_secs, perm_streak, upgrade_secs_perm) = match hist {
        Some(r) if r >= 0.5 => (30_u64, 6_u8, UPGRADE_SECS_PERMANENT),
        Some(r) if r < 0.2 => (90_u64, 2_u8, UPGRADE_SECS_PERMANENT),
        _ => (UPGRADE_SECS, RELAY_PERM_STREAK, UPGRADE_SECS_PERMANENT),
    };

    let span = tracing::info_span!("path_monitor", %peer, cmd);
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let mut stats_tick = time::interval(Duration::from_secs(STATS_SECS));
        stats_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut next_upgrade = tokio::time::Instant::now() + Duration::from_secs(upgrade_secs);
        // Skip the immediate first stats tick.
        stats_tick.tick().await;

        let mut prev_bytes = {
            let s = connection.stats();
            s.udp_tx.bytes.saturating_add(s.udp_rx.bytes)
        };
        let mut slow_relay_streak: u8 = 0;
        let mut no_ip_candidate_streak: u8 = 0;
        let mut warned_relay_limit = false;
        let mut warned_relay_permanent = false;
        let mut was_direct = path_kind::path_kind(&connection).is_direct();
        let mut first_direct_at = was_direct.then_some(Duration::ZERO);

        loop {
            let upgrade_delay = if no_ip_candidate_streak >= perm_streak {
                Duration::from_secs(upgrade_secs_perm)
            } else {
                Duration::from_secs(upgrade_secs)
            };
            tokio::select! {
                _ = stats_tick.tick() => {
                    let s = connection.stats();
                    let kind = path_kind::path_kind(&connection);
                    let bytes = s.udp_tx.bytes.saturating_add(s.udp_rx.bytes);
                    let delta = bytes.saturating_sub(prev_bytes);
                    prev_bytes = bytes;
                    let bps = delta / STATS_SECS;

                    tracing::debug!(
                        %peer,
                        path = kind.as_str(),
                        paths = connection.paths().len(),
                        bps,
                        udp_tx = s.udp_tx.datagrams,
                        udp_rx = s.udp_rx.datagrams,
                        lost_packets = s.lost_packets,
                        lost_bytes = s.lost_bytes,
                        "path stats (path= from iroh paths(); udp_* are Quinn layer counters)"
                    );

                    let now_direct = kind.is_direct();
                    if now_direct && !was_direct {
                        info!(%peer, "{}", tr!("path upgraded to direct (IP)"));
                        if !quiet {
                            eprintln!(
                                "{}",
                                styler.ok(&tr!("path upgraded to direct (IP)"))
                            );
                        }
                        if first_direct_at.is_none() {
                            first_direct_at = Some(started.elapsed());
                        }
                        warned_relay_limit = false;
                        warned_relay_permanent = false;
                        slow_relay_streak = 0;
                        no_ip_candidate_streak = 0;
                    }
                    was_direct = now_direct;

                    match kind {
                        path_kind::PathKind::Relay => {
                            no_ip_candidate_streak =
                                no_ip_candidate_streak.saturating_add(1);
                        }
                        path_kind::PathKind::Direct
                        | path_kind::PathKind::RelayWithDirectCandidate => {
                            no_ip_candidate_streak = 0;
                        }
                        path_kind::PathKind::Unknown => {}
                    }
                    if !warned_relay_permanent
                        && no_ip_candidate_streak >= perm_streak
                    {
                        warned_relay_permanent = true;
                        let msg = tr!(
                            "no direct IP candidate observed — treating peer as relay-permanent (slowing hole-punch retries). CGNAT without global IPv6 often needs a self-hosted --relay"
                        );
                        tracing::warn!(%peer, "{}", msg);
                        if !quiet {
                            eprintln!("{}", styler.warn(&msg));
                        }
                    }

                    if !now_direct && (ACTIVE_MIN_BPS..RELAY_SLOW_BPS).contains(&bps) {
                        slow_relay_streak = slow_relay_streak.saturating_add(1);
                    } else {
                        slow_relay_streak = 0;
                    }
                    if !warned_relay_limit && slow_relay_streak >= 2 {
                        warned_relay_limit = true;
                        let kbps = bps / 1024;
                        let msg = tr_fmt!(
                            "low throughput while on relay (~{0} KB/s) — public relays rate-limit; self-host with --relay (and raise iroh-relay client limits) or wait for direct. See docs/architecture/performance.md",
                            kbps
                        );
                        tracing::warn!(%peer, path = kind.as_str(), bps, "{}", msg);
                        if !quiet {
                            eprintln!("{}", styler.warn(&msg));
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_upgrade), if !relay_only => {
                    next_upgrade = tokio::time::Instant::now() + upgrade_delay;
                    // Experiment gates (env, temporary):
                    // - LINK_P2P_NO_PATH_NUDGE=1  → never call network_change
                    // - LINK_P2P_FORCE_PATH_NUDGE=1 → nudge even when already
                    //   direct (stress CID churn / Tailscale re-probe)
                    let force = std::env::var_os("LINK_P2P_FORCE_PATH_NUDGE").is_some();
                    let disable = std::env::var_os("LINK_P2P_NO_PATH_NUDGE").is_some();
                    let should_nudge =
                        !disable && (force || !path_kind::path_kind(&connection).is_direct());
                    if should_nudge {
                        tracing::debug!(
                            %peer,
                            secs = upgrade_delay.as_secs(),
                            force,
                            "nudging magicsock (network_change) for path upgrade retry"
                        );
                        endpoint.network_change().await;
                    } else if disable {
                        tracing::debug!(
                            %peer,
                            "skipping path nudge (LINK_P2P_NO_PATH_NUDGE set)"
                        );
                    }
                }
                _ = connection.closed() => {
                    let kind = path_kind::path_kind(&connection);
                    crate::path_stats::record_sample_lossy(crate::path_stats::sample_for(
                        cmd,
                        peer,
                        kind,
                        first_direct_at,
                        relay_only,
                    ));
                    break;
                }
            }
        }
    }.instrument(span))
}

// ---------------------------------------------------------------------------
// connect: dial a remote node once, then for every local TCP connection open
// a fresh QUIC stream on that same connection and pipe.
// ---------------------------------------------------------------------------

/// Reconnect backoff bounds: 1s, 2s, 4s, ... capped at 30s. Shared with the
/// TUN reconnect loop (tun.rs).
pub(crate) const RECONNECT_BASE: Duration = Duration::from_secs(1);
pub(crate) const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// A connection must stay up at least this long before a successful dial
/// counts as "stable" for backoff purposes. Handshake-then-instant-kick
/// (relay identity conflict, brief path flaps) must *not* reset backoff —
/// otherwise the watcher redials in a tight loop with no sleep.
pub(crate) const MIN_STABLE_CONN: Duration = Duration::from_secs(5);

/// Exponential backoff with a cap, shared by the stream-mode reconnect
/// watcher and the TUN reconnect loop. `next()` returns the delay for the
/// *next* attempt and then advances (1s, 2s, 4s, ... capped); `reset()`
/// restarts from the base — call it only after a *stable* session, not
/// merely after `connect()` returns `Ok`.
pub(crate) struct Backoff {
    next_delay: Duration,
    base: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        Self {
            next_delay: base,
            base,
            max,
        }
    }

    pub(crate) fn next(&mut self) -> Duration {
        let d = self.next_delay;
        self.next_delay = std::cmp::min(self.next_delay * 2, self.max);
        d
    }

    pub(crate) fn reset(&mut self) {
        self.next_delay = self.base;
    }

    /// After a live session ends: reset if it was stable, otherwise advance
    /// and return the sleep before the next dial. `None` = redial immediately.
    pub(crate) fn after_session(
        &mut self,
        lived: Duration,
        min_stable: Duration,
    ) -> Option<Duration> {
        if lived >= min_stable {
            self.reset();
            None
        } else {
            Some(self.next())
        }
    }
}

/// The live QUIC connection slot shared between the reconnect watcher (the
/// only writer) and the per-stream forwarders (readers). `None` means "the
/// connection is down and we're reconnecting — new streams wait".
///
/// A `watch` channel (not a lock + poll): waiters are woken the moment the
/// watcher swaps in the new connection, so a client that arrives during a
/// reconnect window is served with zero polling delay instead of up to
/// RECONNECT_POLL of stale sleep. `watch::Sender::send` requires the value
/// to be cloneable; `Connection` is cheap to clone (an Arc inside).
#[derive(Clone)]
pub(crate) struct ConnSlot(Arc<watch::Sender<Option<Connection>>>);

impl ConnSlot {
    pub(crate) fn new(initial: Option<Connection>) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self(Arc::new(tx))
    }

    pub(crate) fn replace(&self, conn: Option<Connection>) {
        // send() returns Err only when all receivers are dropped — at that
        // point nobody is waiting for a reconnect anyway.
        let _ = self.0.send(conn);
    }

    /// Snapshot of the current connection.
    ///
    /// The returned `Connection` may become stale immediately if a reconnect
    /// watcher calls [`Self::replace`] with `None` or a new conn. Prefer
    /// [`open_stream_wait`] for dialing streams across reconnect windows;
    /// use this only for best-effort diagnostics (stats, close reason).
    pub(crate) fn borrow(&self) -> Option<Connection> {
        self.0.borrow().clone()
    }
}

/// Open a bidi stream on the current connection, waiting through reconnect
/// windows instead of failing the local client.
///
/// - Slot empty (reconnecting): wait on the watch channel — the watcher's
///   `replace(Some(..))` wakes us the instant the new connection lands.
/// - `open_bi` fails and the connection is closed: same wait — the watcher
///   will redial and swap the slot.
/// - `open_bi` fails on a still-alive connection (e.g. stream limit): give
///   up this stream only.
/// - `open_bi` hangs past `open_timeout`: log [`Connection::stats`] /
///   `close_reason` / `paths`, close **only this connection** (not the
///   endpoint), clear the slot, and wait for a redial. Callers that dial
///   must run [`spawn_reconnect_watcher`] (or equivalent) or this waits
///   forever after a hang.
pub(crate) async fn open_stream_wait(slot: &ConnSlot) -> Result<(SendStream, RecvStream)> {
    open_stream_wait_deadline(slot, Duration::from_secs(5)).await
}

/// Like [`open_stream_wait`], but with an explicit `open_bi` deadline.
pub(crate) async fn open_stream_wait_deadline(
    slot: &ConnSlot,
    open_timeout: Duration,
) -> Result<(SendStream, RecvStream)> {
    loop {
        // A fresh receiver per attempt: starts at the current value, so if
        // a connection is already present we never wait at all.
        let mut rx = slot.0.subscribe();
        let conn = (*rx.borrow_and_update()).clone();
        let Some(conn) = conn else {
            // Reconnecting: wait for the watcher to swap in a connection.
            // Err means the sender was dropped (process shutting down) — bail.
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            continue;
        };
        match time::timeout(open_timeout, conn.open_bi()).await {
            Ok(Ok(pair)) => return Ok(pair),
            Ok(Err(e)) if conn.close_reason().is_some() => {
                warn!(error = %e, "{}", tr!("connection lost; waiting for reconnect"));
                // The current value is a dead connection; wait until the
                // watcher replaces it (changed() fires only on a write, so
                // this can't spin).
                rx.changed()
                    .await
                    .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                log_open_bi_timeout(&conn);
                // Force the reconnect watcher (or peer) to install a fresh
                // connection. Do NOT close the Endpoint — only this conn.
                conn.close(0u32.into(), b"open_bi timeout");
                slot.replace(None);
                warn!("{}", tr!("open_bi timed out; waiting for reconnect"));
                rx.changed()
                    .await
                    .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            }
        }
    }
}

fn log_open_bi_timeout(conn: &Connection) {
    let stats = conn.stats();
    let close = conn.close_reason();
    let kind = path_kind::path_kind(conn);
    warn!(
        close = ?close,
        path = kind.as_str(),
        paths = conn.paths().len(),
        udp_tx = stats.udp_tx.bytes,
        udp_rx = stats.udp_rx.bytes,
        lost_packets = stats.lost_packets,
        "{}",
        tr!("open_bi timed out (connection still open; see stats/paths)")
    );
}

/// Reconnect watcher: waits for the current connection to die, then re-dials
/// with exponential backoff, swapping the slot on success.
///
/// Backoff resets only when a session lived at least [`MIN_STABLE_CONN`].
/// A handshake that succeeds and then dies in milliseconds (relay kick,
/// path flap) keeps climbing the backoff and sleeps before the next dial —
/// otherwise `connect()` success alone would reset to zero delay and spin.
///
/// Runs for the lifetime of the process. Deliberately NOT tracked in the
/// shutdown drain (`tasks`): it never finishes on its own, and the process
/// exits right after the drain anyway.
///
/// Scope note: this reconnects the QUIC *connection*; process-level restarts
/// are the systemd unit's job (contrib/systemd), they don't mix.
pub(crate) fn spawn_reconnect_watcher(
    slot: &ConnSlot,
    endpoint: &Endpoint,
    dial_addr: EndpointAddr,
    peer: EndpointId,
) {
    let slot = slot.clone();
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX);
        // Pre-existing slot connection (installed by `run_connect` before we
        // spawn) is treated as already stable so its first natural death
        // after a long transfer is not mistaken for a short-lived flap.
        let mut connected_at = if slot.0.borrow().is_some() {
            // Pre-existing connection is treated as already past the stability
            // floor so its first natural death after a long transfer is not
            // mistaken for a short-lived flap.
            Some(
                std::time::Instant::now()
                    .checked_sub(MIN_STABLE_CONN)
                    .expect("MIN_STABLE_CONN fits in Instant clock"),
            )
        } else {
            None
        };
        loop {
            let current = (*slot.0.subscribe().borrow_and_update()).clone();
            if let Some(conn) = current {
                conn.closed().await;
                slot.replace(None);
                let lived = connected_at
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO);
                connected_at = None;
                if let Some(delay) = backoff.after_session(lived, MIN_STABLE_CONN) {
                    warn!(
                        %peer,
                        lived_ms = lived.as_millis() as u64,
                        "{}",
                        tr_fmt!(
                            "connection died quickly; backing off {0} before redial",
                            format!("{delay:?}")
                        )
                    );
                    tokio::time::sleep(delay).await;
                }
            }

            match endpoint.connect(dial_addr.clone(), ALPN).await {
                Ok(conn) => {
                    connected_at = Some(std::time::Instant::now());
                    slot.replace(Some(conn));
                    info!(%peer, "{}", tr!("reconnected to peer"));
                }
                Err(e) => {
                    let delay = backoff.next();
                    // DBG-TEMP
                    tracing::debug!(%peer, error = %e, "W1 connect failed");
                    warn!(%peer, error = %e, "{}", tr_fmt!(
                        "reconnect failed; retrying in {0}",
                        format!("{delay:?}")
                    ));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    });
}


