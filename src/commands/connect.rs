//! `connect` — dial a peer and expose local TCP / SOCKS5 / stdio.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::SecretKey;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::cli::ConnectMode;
use crate::contacts;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::pipe;
use crate::runtime::{
    bring_endpoint_online, build_dial_addr, build_endpoint, conn_semaphore, open_stream_wait,
    reject_relay_only_with_to_addr, spawn_path_monitor, spawn_reconnect_watcher, ConnSlot,
    TransportTune, Ui, ALPN,
};
use crate::socks5;
use crate::style::Styler;

pub(crate) async fn run_connect(
    secret_key: SecretKey,
    to: &str,
    mode: ConnectMode,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    reject_relay_only_with_to_addr(relay_only, &to_addr)?;

    let book = contacts::load(&contacts::contacts_path()).unwrap_or_default();
    let peer = contacts::resolve(&book, to).map_err(|e| exit::coded(exit::USAGE, e))?;
    let label = peer
        .name
        .clone()
        .unwrap_or_else(|| peer.id.fmt_short().to_string());

    let mut addrs = to_addr;
    addrs.extend(peer.addrs.iter().copied());
    reject_relay_only_with_to_addr(relay_only, &addrs)?;

    let own_id = secret_key.public();
    contacts::print_machine_identity(own_id);

    let endpoint = build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0_relays,
    )?
    .bind()
    .await
    .map_err(|e| {
        exit::coded(
            exit::CONNECT,
            anyhow::Error::new(e).context(tr!("binding endpoint")),
        )
    })?;
    bring_endpoint_online(&endpoint, relay, no_n0_relays).await?;

    let dial_addr = build_dial_addr(peer.id, relay, &addrs)?;
    if !addrs.is_empty() {
        ui.line(styler.dim(&tr_fmt!(
            "dialing with address hint(s): {0}",
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    if let Some(name) = &peer.name {
        ui.line(styler.info(&tr_fmt!("dialing contact {0}...", name)));
    } else {
        ui.line(styler.info(&tr_fmt!("dialing {0}...", label)));
    }
    let start = std::time::Instant::now();
    let connection = endpoint
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
    tracing::debug!(
        peer = %peer.id,
        elapsed_ms = start.elapsed().as_millis() as u64,
        "dial completed"
    );

    #[cfg(unix)]
    if matches!(mode, ConnectMode::Stdio) {
        ui.line(styler.ok(&tr!("connected. piping stdin/stdout to the remote peer.")));
        contacts::hint_save_contact(ui, &styler, &peer);
        let (mut send, recv) = connection
            .open_bi()
            .await
            .context(tr!("opening stream"))?;
        pipe::write_stream_hello(&mut send).await?;
        let result = pipe::pipe_stdio(send, recv).await;
        endpoint.close().await;
        return result;
    }

    let (local_addr, is_socks5) = match mode {
        ConnectMode::Listen(a) => (a, false),
        ConnectMode::Socks5(a) => (a, true),
        #[cfg(unix)]
        ConnectMode::Stdio => {
            return Err(anyhow::anyhow!(
                "internal: ConnectMode::Stdio should have returned earlier"
            ));
        }
    };

    let slot = ConnSlot::new(Some(connection.clone()));
    spawn_reconnect_watcher(&slot, &endpoint, dial_addr, peer.id);
    spawn_path_monitor(
        connection,
        peer.id,
        endpoint.clone(),
        relay_only,
        styler,
        ui.quiet,
        "connect",
    );

    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;
    ui.line(styler.ok(&tr_fmt!(
        "connected. local TCP listener on {0} now forwards to the remote peer.",
        local_addr
    )));
    contacts::hint_save_contact(ui, &styler, &peer);

    let semaphore = conn_semaphore(max_conns);
    let mut tasks = Vec::new();

    loop {
        tokio::select! {
            accepted = tcp_listener.accept() => {
                let (mut tcp_stream, client_addr) = accepted?;
                tracing::debug!(%client_addr, %local_addr, "local TCP client accepted");
                let slot = slot.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let result = async {
                        let _permit = semaphore.acquire_owned().await?;
                        if is_socks5 {
                            let target = socks5::accept_handshake(&mut tcp_stream).await?;
                            let (mut send, recv) = open_stream_wait(&slot).await?;
                            socks5::write_target(&mut send, &target).await?;
                            pipe::pipe_streams(tcp_stream, send, recv).await
                        } else {
                            let (mut send, recv) = open_stream_wait(&slot).await?;
                            pipe::write_stream_hello(&mut send).await?;
                            pipe::pipe_streams(tcp_stream, send, recv).await
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        warn!(%client_addr, error = %e, "{}", tr!("forwarder error"));
                    }
                }));
            }
            _ = tokio::signal::ctrl_c() => {
                ui.line(styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }

    // Dropping the listener stops accepts; drain in-flight pipes briefly.
    drop(tcp_listener);
    pipe::drain_tasks(tasks).await;
    endpoint.close().await;
    Ok(())
}
