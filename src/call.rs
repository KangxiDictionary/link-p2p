//! Symmetric `call`: both peers publish and dial (tie-break like mesh roster).
//!
//! After EndpointId tie-break the roles match stream mode:
//! - **Dialer** = `connect` (no local `alpns` / `Router` — those starved outbound
//!   STREAM frames in early `call` builds)
//! - **Waiter** = `serve` (`alpns` + `Router` accepting the peer)
//!
//! The dialer runs a reconnect watcher (same idea as `connect --listen`) so an
//! `open_bi` hang can close **only** that connection and redial without killing
//! the Endpoint.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::{Connection, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tracing::{info, warn};

use crate::config::{self, UserConfig};
use crate::contacts::{self, ResolvedPeer};
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::pipe;
use crate::relay_probe;
use crate::style::Styler;
use crate::tun_roster::should_dial;
use crate::{
    bring_endpoint_online, build_dial_addr, build_endpoint, handle_forward_stream, open_stream_wait,
    reject_relay_only_with_to_addr, spawn_path_monitor, spawn_reconnect_watcher, ConnSlot,
    PingHandler, ServeMode, TransportTune, Ui, ALPN, PING_ALPN,
};

/// How the local side of a call presents traffic.
#[derive(Clone, Copy, Debug)]
pub enum CallLocal {
    Listen(SocketAddr),
    #[cfg(unix)]
    Stdio,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_call(
    secret_key: SecretKey,
    to: &str,
    local: CallLocal,
    forward: Option<SocketAddr>,
    cli_relays: &[String],
    no_n0_relays: bool,
    relay_only: bool,
    to_addr: Vec<SocketAddr>,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    let user_cfg = config::load_or_default(&config::config_path());
    let book = contacts::load(&contacts::contacts_path()).unwrap_or_default();
    let peer = contacts::resolve(&book, to)?;
    let label = peer
        .name
        .clone()
        .unwrap_or_else(|| peer.id.fmt_short().to_string());

    let (relays, no_n0, relay_only) =
        resolve_relay_opts(cli_relays, no_n0_relays, relay_only, &user_cfg, &peer);
    reject_relay_only_with_to_addr(relay_only, &to_addr)?;
    reject_relay_only_with_to_addr(relay_only, &peer.addrs)?;

    let mut addrs = to_addr;
    addrs.extend(peer.addrs.iter().copied());

    if let Some(name) = &peer.name {
        ui.line(styler.info(&tr_fmt!("calling contact {0}...", name)));
    } else {
        ui.line(styler.info(&tr_fmt!("calling {0}...", label)));
    }
    let relays = relay_probe::order_by_connect_latency(&relays).await;

    // Know the role before bind: dialer must NOT register accept ALPNs / Router
    // (that path hung write_stream_hello — no STREAM frames left the dialer).
    let own_id = secret_key.public();
    let we_dial = should_dial(own_id, peer.id);
    ui.line(styler.dim(&if we_dial {
        tr!("we dial (EndpointId tie-break)")
    } else {
        tr!("we wait for peer to dial (EndpointId tie-break)")
    }));
    contacts::hint_share_identity(ui, &styler, own_id);

    let builder = build_endpoint(
        secret_key,
        &relays,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0,
    )?;
    let endpoint = if we_dial {
        // Pure client, same as `connect`.
        builder.bind().await
    } else {
        builder
            .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
            .bind()
            .await
    }
    .map_err(|e| {
        exit::coded(
            exit::CONNECT,
            anyhow::Error::new(e).context(tr!("binding endpoint")),
        )
    })?;
    // Machine-readable for scripts / ignored integration tests (same as serve).
    contacts::print_machine_identity(endpoint.id());
    bring_endpoint_online(&endpoint, &relays, no_n0).await?;

    let slot = ConnSlot::new(None);
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let semaphore = crate::conn_semaphore(max_conns);

    // Waiter only: accept inbound like `serve`.
    let router = if we_dial {
        None
    } else {
        let handler = CallAcceptHandler {
            expected: peer.id,
            forward,
            slot: slot.clone(),
            semaphore: semaphore.clone(),
            tasks: tasks.clone(),
            endpoint: endpoint.clone(),
            relay_only,
            styler,
            quiet: ui.quiet,
            path_monitor: Arc::new(Mutex::new(None)),
        };
        Some(
            Router::builder(endpoint.clone())
                .accept(ALPN, handler)
                .accept(PING_ALPN, PingHandler)
                .spawn(),
        )
    };

    let dial_addr = build_dial_addr(peer.id, &relays, &addrs)?;
    let path_monitor: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    let forward_loop: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    if we_dial {
        let conn = endpoint
            .connect(dial_addr.clone(), ALPN)
            .await
            .map_err(|e| {
                exit::coded(
                    exit::CONNECT,
                    anyhow::Error::new(e).context(tr!(
                        "connecting to remote endpoint — if this fails or hangs, run: link-p2p selftest"
                    )),
                )
            })?;
        install_dialer_session(
            &conn,
            peer.id,
            &endpoint,
            relay_only,
            styler,
            ui.quiet,
            forward,
            &semaphore,
            &tasks,
            &path_monitor,
            &forward_loop,
        );
        slot.replace(Some(conn));
        // Same as `connect`: when the conn dies (incl. open_bi timeout close),
        // redial and swap the slot — without closing the Endpoint.
        spawn_call_dialer_watcher(
            slot.clone(),
            endpoint.clone(),
            dial_addr,
            peer.id,
            forward,
            semaphore.clone(),
            tasks.clone(),
            path_monitor.clone(),
            forward_loop.clone(),
            relay_only,
            styler,
            ui.quiet,
        );
    } else {
        ui.line(styler.info(&tr!("waiting for peer...")));
        let mut rx = slot.subscribe();
        loop {
            if rx.borrow().is_some() {
                break;
            }
            if rx.changed().await.is_err() {
                bail!(tr!("call aborted before peer connected"));
            }
        }
    }
    ui.line(styler.ok(&tr_fmt!("connected to {0}", label)));
    contacts::hint_save_contact(ui, &styler, &peer);

    let result = match local {
        CallLocal::Listen(addr) => run_local_listen(addr, &slot, semaphore, ui, styler).await,
        #[cfg(unix)]
        CallLocal::Stdio => {
            ui.line(styler.ok(&tr!("connected. piping stdin/stdout to the remote peer.")));
            let (mut send, recv) = open_stream_wait(&slot).await?;
            write_stream_hello_timed(&mut send, &slot).await?;
            pipe::pipe_stdio(send, recv).await
        }
    };

    if let Some(router) = router {
        router.shutdown().await.ok();
    }
    let pending = std::mem::take(&mut *tasks.lock().unwrap_or_else(|e| e.into_inner()));
    pipe::drain_tasks(pending).await;
    endpoint.close().await;
    result
}

fn install_dialer_session(
    conn: &Connection,
    peer: EndpointId,
    endpoint: &Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
    forward: Option<SocketAddr>,
    semaphore: &Arc<Semaphore>,
    tasks: &Arc<Mutex<Vec<JoinHandle<()>>>>,
    path_monitor: &Arc<Mutex<Option<JoinHandle<()>>>>,
    forward_loop: &Arc<Mutex<Option<JoinHandle<()>>>>,
) {
    // Abort the previous session's background tasks so reconnect does not
    // leave duplicate path-stats / accept loops running on a dead conn.
    // `spawn_forward_accept_loop` itself cannot fail — replace always aborts
    // the prior JoinHandle first, then installs the new one (or None).
    replace_bg_task(
        path_monitor,
        Some(spawn_path_monitor(
            conn.clone(),
            peer,
            endpoint.clone(),
            relay_only,
            styler,
            quiet,
            "call",
        )),
    );
    let next_forward = forward.map(|target| {
        spawn_forward_accept_loop(conn.clone(), target, semaphore.clone(), tasks.clone())
    });
    replace_bg_task(forward_loop, next_forward);
}

fn replace_bg_task(slot: &Arc<Mutex<Option<JoinHandle<()>>>>, next: Option<JoinHandle<()>>) {
    let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(prev) = g.take() {
        prev.abort();
    }
    *g = next;
}

/// Dialer-side reconnect: like [`spawn_reconnect_watcher`], but also restarts
/// path monitor + optional `--forward` accept loop on the new connection.
#[allow(clippy::too_many_arguments)]
fn spawn_call_dialer_watcher(
    slot: ConnSlot,
    endpoint: Endpoint,
    dial_addr: EndpointAddr,
    peer: EndpointId,
    forward: Option<SocketAddr>,
    semaphore: Arc<Semaphore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    path_monitor: Arc<Mutex<Option<JoinHandle<()>>>>,
    forward_loop: Arc<Mutex<Option<JoinHandle<()>>>>,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
) {
    // Reuse connect's watcher for the redial loop, then a side task that
    // watches slot swaps and attaches forward/monitor to each new conn.
    spawn_reconnect_watcher(&slot, &endpoint, dial_addr, peer);

    tokio::spawn(async move {
        let mut rx = slot.subscribe();
        let mut seen = rx.borrow_and_update().clone();
        // Initial conn already installed monitors in run_call.
        //
        // `stable_id()` is unique for the lifetime of a Connection object
        // (quinn); we only care that consecutive slot values differ. A
        // usize wraparound ABA between two `changed()` wakes is not a
        // practical concern. `install_dialer_session` cannot fail — it only
        // aborts/replaces JoinHandles.
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let next = rx.borrow_and_update().clone();
            match (&seen, &next) {
                (_, Some(conn))
                    if seen.as_ref().map(|c| c.stable_id()) != Some(conn.stable_id()) =>
                {
                    install_dialer_session(
                        conn,
                        peer,
                        &endpoint,
                        relay_only,
                        styler,
                        quiet,
                        forward,
                        &semaphore,
                        &tasks,
                        &path_monitor,
                        &forward_loop,
                    );
                }
                _ => {}
            }
            seen = next;
        }
    });
}

/// `write_stream_hello` with a deadline so a hung send surfaces diagnostics
/// instead of looking like a silent pipe.
async fn write_stream_hello_timed(send: &mut SendStream, slot: &ConnSlot) -> Result<()> {
    const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
    let start = Instant::now();
    match timeout(HELLO_TIMEOUT, pipe::write_stream_hello(send)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            let conn = slot.borrow();
            let stats = conn.as_ref().map(Connection::stats);
            let close = conn.as_ref().and_then(Connection::close_reason);
            let path = conn
                .as_ref()
                .map(|c| crate::path_kind::path_kind(c).as_str());
            warn!(
                elapsed_secs = start.elapsed().as_secs_f64(),
                close = close.as_ref().map(std::string::ToString::to_string),
                path,
                udp_tx_bytes = stats.as_ref().map(|s| s.udp_tx.bytes),
                udp_rx_bytes = stats.as_ref().map(|s| s.udp_rx.bytes),
                udp_tx_packets = stats.as_ref().map(|s| s.udp_tx.datagrams),
                udp_rx_packets = stats.as_ref().map(|s| s.udp_rx.datagrams),
                lost_packets = stats.as_ref().map(|s| s.lost_packets),
                lost_bytes = stats.as_ref().map(|s| s.lost_bytes),
                "stream hello write timed out"
            );
            Err(anyhow::anyhow!(tr!(
                "timed out writing stream hello (open_bi ok but no STREAM frames sent) — check dialer is not also running an accept Router on the same ALPN"
            )))
        }
    }
}

/// Exit the accept loop after this many consecutive `accept_bi` failures when
/// the connection has not yet reported a close reason (defensive; normal close
/// exits on the first error).
const ACCEPT_BI_GIVE_UP: u32 = 3;

/// After this many consecutive `--forward` target failures, pause before
/// accepting more streams so a dead local target cannot pin the peer's
/// concurrency budget in a tight spawn/fail loop.
const FORWARD_FAIL_CIRCUIT: u32 = 8;
const FORWARD_FAIL_BACKOFF: Duration = Duration::from_millis(250);

fn spawn_forward_accept_loop(
    connection: Connection,
    target: SocketAddr,
    semaphore: Arc<Semaphore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_forward_accept_loop(connection, target, semaphore, tasks).await;
    })
}

/// Shared dialer/waiter `--forward` accept loop.
///
/// - `accept_bi` errors → retry briefly only if the conn is still open, else exit
///   (never spin forever spawning tasks).
/// - Semaphore is taken **after** accept so idle waiting does not hold a permit.
/// - Consecutive `handle_forward_stream` failures trip a short backoff.
async fn run_forward_accept_loop(
    connection: Connection,
    target: SocketAddr,
    semaphore: Arc<Semaphore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    use std::sync::atomic::{AtomicU32, Ordering};

    let peer = connection.remote_id();
    let fail_streak = Arc::new(AtomicU32::new(0));
    let mut accept_errors = 0u32;

    loop {
        let streak = fail_streak.load(Ordering::Relaxed);
        if streak >= FORWARD_FAIL_CIRCUIT {
            warn!(
                %peer,
                streak,
                target = %target,
                "{}",
                tr!("forward target failing repeatedly; backing off before accepting more streams")
            );
            tokio::time::sleep(FORWARD_FAIL_BACKOFF).await;
        }

        let (send, recv) = match connection.accept_bi().await {
            Ok(p) => {
                accept_errors = 0;
                p
            }
            Err(e) => {
                accept_errors = accept_errors.saturating_add(1);
                warn!(
                    %peer,
                    conn = connection.stable_id(),
                    error = %e,
                    attempt = accept_errors,
                    "{}",
                    tr!("connection ended")
                );
                if connection.close_reason().is_some() || accept_errors >= ACCEPT_BI_GIVE_UP {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let mode = ServeMode::Forward(target);
        let streak = fail_streak.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            match handle_forward_stream(mode, send, recv).await {
                Ok(()) => {
                    streak.store(0, Ordering::Relaxed);
                }
                Err(e) => {
                    let n = streak.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    warn!(%peer, error = %e, consecutive_failures = n, "{}", tr!("stream error"));
                }
            }
        });
        crate::push_task(&tasks, task);
    }
}

fn resolve_relay_opts(
    cli_relays: &[String],
    cli_no_n0: bool,
    cli_relay_only: bool,
    cfg: &UserConfig,
    peer: &ResolvedPeer,
) -> (Vec<String>, bool, bool) {
    let mut relays = config::merge_relay_urls(cli_relays, cfg);
    for u in &peer.relays {
        if !relays.iter().any(|x| x == u) {
            relays.push(u.clone());
        }
    }
    let no_n0 = cli_no_n0 || cfg.relays.no_n0;
    let relay_only = cli_relay_only || cfg.relays.relay_only;
    (relays, no_n0, relay_only)
}

async fn run_local_listen(
    local_addr: SocketAddr,
    slot: &ConnSlot,
    semaphore: Arc<Semaphore>,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;
    ui.line(styler.ok(&tr_fmt!(
        "local TCP listener on {0} forwards to the peer",
        local_addr
    )));
    let mut tasks = Vec::new();
    loop {
        tokio::select! {
            accepted = tcp_listener.accept() => {
                let (tcp_stream, client_addr) = accepted?;
                let slot = slot.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let result = async {
                        let _permit = semaphore.acquire_owned().await?;
                        let (mut send, recv) = open_stream_wait(&slot).await?;
                        write_stream_hello_timed(&mut send, &slot).await?;
                        pipe::pipe_streams(tcp_stream, send, recv).await
                    }
                    .await;
                    if let Err(e) = result {
                        warn!(%client_addr, error = %e, "{}", tr!("stream error"));
                    }
                }));
            }
            _ = tokio::signal::ctrl_c() => {
                ui.line(styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }
    pipe::drain_tasks(tasks).await;
    Ok(())
}

#[derive(Clone)]
struct CallAcceptHandler {
    expected: EndpointId,
    forward: Option<SocketAddr>,
    slot: ConnSlot,
    semaphore: Arc<Semaphore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    endpoint: Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
    path_monitor: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl std::fmt::Debug for CallAcceptHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallAcceptHandler")
            .field("expected", &self.expected)
            .field("forward", &self.forward)
            .field("relay_only", &self.relay_only)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for CallAcceptHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        if peer != self.expected {
            warn!(%peer, "{}", tr!("rejecting connection: unexpected peer for call"));
            connection.close(0u32.into(), b"unexpected peer");
            return Ok(());
        }
        info!(%peer, "{}", tr!("connection opened"));
        replace_bg_task(
            &self.path_monitor,
            Some(spawn_path_monitor(
                connection.clone(),
                peer,
                self.endpoint.clone(),
                self.relay_only,
                self.styler,
                self.quiet,
                "call",
            )),
        );
        // Always prefer the newest inbound connection (covers peer redial
        // after an open_bi timeout closed the previous one).
        self.slot.replace(Some(connection.clone()));

        let Some(target) = self.forward else {
            connection.closed().await;
            return Ok(());
        };

        run_forward_accept_loop(
            connection.clone(),
            target,
            self.semaphore.clone(),
            self.tasks.clone(),
        )
        .await;
        connection.closed().await;
        Ok(())
    }
}
