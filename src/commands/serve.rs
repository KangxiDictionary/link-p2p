//! `serve` — accept P2P streams and forward to TCP or SOCKS5 proxy targets.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::endpoint::VarInt;
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::contacts;
use crate::i18n::{tr, tr_fmt};
use crate::pipe;
use crate::runtime::{
    bring_endpoint_online, build_endpoint, conn_semaphore, handle_forward_stream, push_task,
    spawn_path_monitor, PingHandler, ServeMode, TransportTune, Ui, ALPN, PING_ALPN,
};
use crate::style::Styler;

pub(crate) async fn run_serve(
    secret_key: SecretKey,
    mode: ServeMode,
    allowed: Vec<EndpointId>,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune, relay_only, no_n0_relays)?
        .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
        .bind()
        .await
        .context(tr!("binding endpoint"))?;

    bring_endpoint_online(&endpoint, relay, no_n0_relays).await?;

    ui.line(styler.banner("link-p2p serve"));
    match mode {
        ServeMode::Forward(target) => ui.line(format!(
            "  {}",
            tr_fmt!("forwarding P2P connections to: {0}", target)
        )),
        ServeMode::Proxy { allow_private } => {
            ui.line(format!(
                "  {}",
                styler.info(&tr!(
                    "proxy mode: dialing the target address from each stream's header"
                ))
            ));
            if !allow_private {
                ui.line(format!(
                    "  {}",
                    styler.warn(&tr!(
                        "proxy targets in private/loopback ranges are blocked (use --allow-private to permit)"
                    ))
                ));
            }
        }
    }
    // The whitelist is an important security property; surface it in the
    // banner instead of hiding it in --help.
    if !allowed.is_empty() {
        ui.line(format!(
            "  {}",
            styler.info(&tr_fmt!(
                "only accepting connections from {0} allowed peer(s)",
                allowed.len()
            ))
        ));
    }
    ui.line(format!(
        "  {}",
        styler.dim(&tr!(
            "your identity (give SHORT_CODE to peers; both can `call` each other):"
        ))
    ));
    let ep = endpoint.id();
    ui.line(format!("    {}", styler.highlight(&contacts::encode_short_code(ep))));
    // Machine-readable for scripts / e2e — always stdout, even under `-q`.
    contacts::print_machine_identity(ep);
    ui.line("");
    ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));

    // Every per-stream forwarder is our own spawned task; the router's
    // accept loop doesn't know about them, so keep the handles here for the
    // drain on shutdown.
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let handler = ForwardHandler {
        mode,
        allowed: if allowed.is_empty() {
            None
        } else {
            Some(Arc::new(allowed.into_iter().collect()))
        },
        // 0 = unlimited. usize::MAX keeps the acquire() call shape uniform.
        semaphore: conn_semaphore(max_conns),
        // A second, independent cap on *connections* (not streams): an idle
        // connection costs memory + an accept task even without any stream,
        // so bound how many such connections a flood of dials can open.
        conn_semaphore: conn_semaphore(max_conns),
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

    tokio::signal::ctrl_c().await?;
    ui.line(styler.warn(&tr!("shutting down...")));
    router.shutdown().await?;
    // router.shutdown() only stops the router's own accept loop — the
    // per-stream forwarders are our tasks, so give them the same bounded
    // drain window as run_connect.
    let pending = std::mem::take(&mut *tasks.lock().unwrap_or_else(|e| e.into_inner()));
    pipe::drain_tasks(pending).await;
    Ok(())
}

/// Reject a connection with a QUIC close frame instead of silently dropping
/// it, so the peer sees a decisive error rather than a timeout. Best-effort:
/// if the connection is already dead, there's nothing to close.
fn reject_connection(connection: &Connection, peer: EndpointId) {
    warn!(%peer, "{}", tr!("rejecting connection: peer is not in the --allow list"));
    connection.close(VarInt::from_u32(0), b"peer not allowed");
}

#[derive(Debug)]
struct ForwardHandler {
    mode: ServeMode,
    /// Peer whitelist: `None` accepts anyone (`serve` without `--allow`),
    /// `Some(set)` rejects every connection whose EndpointId is not in it.
    allowed: Option<Arc<HashSet<EndpointId>>>,
    /// Bounds the number of concurrently forwarded streams.
    semaphore: Arc<Semaphore>,
    /// Bounds the number of concurrently *open connections* (idle ones
    /// included), independent of the stream cap.
    conn_semaphore: Arc<Semaphore>,
    /// Every spawned per-stream forwarder, so Ctrl+C can drain them
    /// (bounded, see DRAIN_TIMEOUT) instead of cutting them off mid-flush.
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    endpoint: Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
}

impl ProtocolHandler for ForwardHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        info!(%peer, "{}", tr!("connection opened"));

        // Authorization: with `--allow`, only whitelisted peers get past this
        // point. iroh's QUIC handshake already authenticated the peer's key
        // (remote_id is its public identity), so this is a real check, not a
        // claim. Close the connection so the peer learns immediately.
        if let Some(allowed) = &self.allowed {
            if !allowed.contains(&peer) {
                reject_connection(&connection, peer);
                return Ok(());
            }
        }

        // Bound concurrent *connections* (not just streams): a flood of idle
        // dials would otherwise each hold an accept task + connection state
        // forever. Acquired before the accept loop; released when the whole
        // connection ends.
        tracing::debug!(%peer, "waiting for connection permit");
        let _conn_permit = match self.conn_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // semaphore closed; shouldn't happen
        };
        tracing::debug!(%peer, "connection permit acquired, entering accept_bi loop");

        // One QUIC connection can carry many independent streams. Each stream
        // here corresponds to one TCP connection on the far side (see
        // run_connect below), so we keep accepting streams until the peer
        // closes the whole connection.
        spawn_path_monitor(
            connection.clone(),
            peer,
            self.endpoint.clone(),
            self.relay_only,
            self.styler,
            self.quiet,
            "serve",
        );
        loop {
            // Bound the number of concurrently forwarded streams. We acquire
            // the permit *before* accept_bi so a hostile peer flooding streams
            // can't make us spawn unbounded tasks/sockets: the extra streams
            // just queue up at the QUIC layer until a slot frees.
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed; shouldn't happen
            };
            tracing::debug!(%peer, "waiting for bidi stream (accept_bi)");
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => {
                    tracing::debug!(%peer, "bidi stream accepted");
                    pair
                }
                Err(e) => {
                    // This fires both on a clean shutdown (peer closed the
                    // connection) and on real transport errors. iroh doesn't
                    // give us a cheap way to tell those apart here, so log
                    // unconditionally rather than silently dropping real
                    // failures — a clean close is just a bit of harmless noise.
                    warn!(%peer, error = %e, "{}", tr!("connection ended"));
                    break;
                }
            };
            let mode = self.mode;
            let task = tokio::spawn(async move {
                // The permit lives as long as this stream does; dropping it
                // after handle_forward_stream frees the slot.
                let _permit = permit;
                if let Err(e) = handle_forward_stream(mode, send, recv).await {
                    warn!(%peer, error = %e, "{}", tr!("stream error"));
                }
            });
            push_task(&self.tasks, task);
        }

        connection.closed().await;
        info!(%peer, "{}", tr!("connection closed"));
        Ok(())
    }
}
