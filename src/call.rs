//! Symmetric `call`: both peers publish and dial (tie-break like mesh roster).
//!
//! Resolves a contact name / EndpointId / short code, merges config relays with
//! n0 by default, then either dials or waits — same ALPN as stream forward.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
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
    build_dial_addr, build_endpoint, install_extra_relays, open_stream_wait, reject_relay_only_with_to_addr,
    spawn_path_monitor, wait_online, ConnSlot, PingHandler, ServeMode, TransportTune, Ui, ALPN,
    PING_ALPN,
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
    let user_cfg = config::load(&config::config_path()).unwrap_or_default();
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

    ui.line(styler.info(&tr_fmt!("calling {0}...", label)));
    let relays = relay_probe::order_by_connect_latency(&relays).await;

    let endpoint = build_endpoint(
        secret_key,
        &relays,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0,
    )?
    .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
    .bind()
    .await
    .map_err(|e| {
        exit::coded(
            exit::CONNECT,
            anyhow::Error::new(e).context(tr!("binding endpoint")),
        )
    })?;
    wait_online(&endpoint).await?;
    install_extra_relays(&endpoint, &relays, no_n0).await?;

    let own_id = endpoint.id();
    let we_dial = should_dial(own_id, peer.id);
    ui.line(styler.dim(&if we_dial {
        tr!("we dial (EndpointId tie-break)")
    } else {
        tr!("we wait for peer to dial (EndpointId tie-break)")
    }));
    ui.line(styler.dim(&tr_fmt!(
        "your short code: {0}",
        contacts::encode_short_code(own_id)
    )));

    let slot = ConnSlot::new(None);
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Semaphore::new(if max_conns == 0 {
        usize::MAX
    } else {
        max_conns
    }));

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
    };
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, handler)
        .accept(PING_ALPN, PingHandler)
        .spawn();

    if we_dial {
        let dial_addr = build_dial_addr(peer.id, &relays, &addrs)?;
        let conn = endpoint
            .connect(dial_addr, ALPN)
            .await
            .map_err(|e| {
                exit::coded(
                    exit::CONNECT,
                    anyhow::Error::new(e).context(tr!("connecting to remote endpoint")),
                )
            })?;
        spawn_path_monitor(
            conn.clone(),
            peer.id,
            endpoint.clone(),
            relay_only,
            styler,
            ui.quiet,
        );
        slot.replace(Some(conn));
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

    let result = match local {
        CallLocal::Listen(addr) => {
            run_local_listen(addr, &slot, semaphore, ui, styler).await
        }
        #[cfg(unix)]
        CallLocal::Stdio => {
            ui.line(styler.ok(&tr!("connected. piping stdin/stdout to the remote peer.")));
            let (mut send, recv) = open_stream_wait(&slot).await?;
            pipe::write_stream_hello(&mut send).await?;
            pipe::pipe_stdio(send, recv).await
        }
    };

    router.shutdown().await.ok();
    let pending = std::mem::take(&mut *tasks.lock().unwrap_or_else(|e| e.into_inner()));
    pipe::drain_tasks(pending).await;
    endpoint.close().await;
    result
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
                        pipe::write_stream_hello(&mut send).await?;
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
        spawn_path_monitor(
            connection.clone(),
            peer,
            self.endpoint.clone(),
            self.relay_only,
            self.styler,
            self.quiet,
        );
        // First matching connection fills the slot for our local listen/stdio.
        if self.slot.borrow().is_none() {
            self.slot.replace(Some(connection.clone()));
        }

        let Some(target) = self.forward else {
            // No --forward: keep connection alive for outbound streams only.
            connection.closed().await;
            return Ok(());
        };

        loop {
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let (send, recv) = match connection.accept_bi().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(%peer, error = %e, "{}", tr!("connection ended"));
                    break;
                }
            };
            let mode = ServeMode::Forward(target);
            let task = tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = crate::handle_forward_stream(mode, send, recv).await {
                    warn!(%peer, error = %e, "{}", tr!("stream error"));
                }
            });
            match self.tasks.lock() {
                Ok(mut g) => g.push(task),
                Err(poisoned) => poisoned.into_inner().push(task),
            }
        }
        connection.closed().await;
        Ok(())
    }
}
