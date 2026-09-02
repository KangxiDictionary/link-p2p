//! Stream phone listen/forward helpers used by [`crate::stream_daemon`].
//!
//! Dialer must not also register accept ALPNs on the same ALPN (that starved
//! outbound STREAM frames in early builds) — the standing daemon owns accept.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, SendStream};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tracing::warn;

use crate::i18n::{tr, tr_fmt};
use crate::pipe;
use crate::{handle_forward_stream, open_stream_wait, ConnSlot, ServeMode};

/// Exit the accept loop after this many consecutive `accept_bi` failures when
/// the connection has not yet reported a close reason (defensive; normal close
/// exits on the first error).
const ACCEPT_BI_GIVE_UP: u32 = 3;

/// After this many consecutive `--forward` target failures, pause before
/// accepting more streams so a dead local target cannot pin the peer's
/// concurrency budget in a tight spawn/fail loop.
const FORWARD_FAIL_CIRCUIT: u32 = 8;
const FORWARD_FAIL_BACKOFF: Duration = Duration::from_millis(250);

pub(crate) fn spawn_forward_accept_loop(
    connection: Connection,
    target: SocketAddr,
    semaphore: Arc<Semaphore>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_forward_accept_loop(connection, target, semaphore, tasks).await;
    })
}

/// Shared `--forward` accept loop for an established phone session.
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

/// Local TCP listen loop for the stream phone daemon (no Ctrl-C; ends when aborted).
pub(crate) async fn run_local_listen_daemon(
    local_addr: SocketAddr,
    slot: ConnSlot,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;
    tracing::info!(%local_addr, "call daemon local TCP listener ready");
    loop {
        let (tcp_stream, client_addr) = tcp_listener.accept().await?;
        let slot = slot.clone();
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
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
        });
    }
}
