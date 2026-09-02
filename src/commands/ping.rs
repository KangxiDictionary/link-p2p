//! `ping` — RTT / path probe over the dedicated ping ALPN.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use iroh::{EndpointId, SecretKey};

use crate::cli::OutputFormat;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::path_kind;
use crate::runtime::{
    bring_endpoint_online, build_dial_addr, build_endpoint, reject_relay_only_with_to_addr,
    TransportTune, Ui, PING_ALPN,
};
use crate::style::Styler;

async fn ping_exchange(connection: &iroh::endpoint::Connection) -> Result<u64> {
    let start = std::time::Instant::now();
    let (mut send, mut recv) = connection.open_bi().await?;
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    send.write_all(&ts_ms.to_be_bytes()).await?;
    send.finish()?;
    let mut echo = [0u8; 8];
    recv.read_exact(&mut echo).await?;
    let rtt_us = start.elapsed().as_micros() as u64;
    if i64::from_be_bytes(echo) != ts_ms {
        bail!(tr!("peer echoed a mismatched ping timestamp"));
    }
    Ok(rtt_us)
}

fn path_kind_human(kind: path_kind::PathKind) -> String {
    match kind {
        path_kind::PathKind::Direct => tr!("path: direct (IP)"),
        path_kind::PathKind::Relay => tr!("path: relay"),
        path_kind::PathKind::RelayWithDirectCandidate => {
            tr!("path: relay (direct IP candidate open, not selected)")
        }
        path_kind::PathKind::Unknown => tr!("path: unknown"),
    }
}

/// `link-p2p ping`: dial with the ping ALPN, exchange timestamps over one-shot
/// streams, and report RTT plus path.
///
/// Magicsock often finishes the handshake on relay first and upgrades to
/// direct in the background. Measuring RTT *before* that upgrade (then
/// labeling the path after `settle_path_kind`) produced contradictory
/// "direct but 600ms+" readings. We therefore report **both**:
/// - **initial**: RTT + path snapshot right after connect (often still relay)
/// - **settled**: wait up to 2s for a direct upgrade, then measure again
///
/// JSON keeps `rtt_us` / `path` as the settled values (the ones to trust for
/// "how good is the path now?") and adds `initial_*` for diagnosis.
pub(crate) async fn run_ping(
    secret_key: SecretKey,
    to: &str,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    format: OutputFormat,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    reject_relay_only_with_to_addr(relay_only, &to_addr)?;
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune, relay_only, no_n0_relays)?
        .bind()
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("binding endpoint"))))?;
    bring_endpoint_online(&endpoint, relay, no_n0_relays).await?;

    let remote_id: EndpointId = to.parse().map_err(|e| {
        exit::coded(
            exit::USAGE,
            anyhow::Error::new(e).context(tr_fmt!("'{0}' is not a valid EndpointId", to)),
        )
    })?;

    let dial_addr = build_dial_addr(remote_id, relay, &to_addr)?;

    if format == OutputFormat::Text {
        ui.line(styler.info(&tr_fmt!("pinging {0}...", remote_id)));
    }
    let connection = endpoint
        .connect(dial_addr, PING_ALPN)
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("connecting to remote endpoint"))))?;

    // Snapshot + measure immediately (handshake path — often still relay).
    let initial_kind = path_kind::path_kind(&connection);
    let initial_rtt_us = ping_exchange(&connection).await?;

    // Wait for magicsock relay→direct upgrade when IP transports are enabled.
    // With --relay-only there is nothing to wait for.
    let settle_budget = if relay_only {
        Duration::ZERO
    } else {
        Duration::from_secs(2)
    };
    let settle_start = std::time::Instant::now();
    let settled_kind = path_kind::settle_path_kind(&connection, settle_budget).await;
    let settled_rtt_us = ping_exchange(&connection).await?;

    let stats = connection.stats();
    let initial_path = initial_kind.as_str();
    let settled_path = settled_kind.as_str();
    let upgrade_for_log = if settled_kind.is_direct() {
        Some(if initial_kind.is_direct() {
            Duration::ZERO
        } else {
            settle_start.elapsed()
        })
    } else {
        None
    };
    crate::path_stats::record_sample_lossy(crate::path_stats::sample_for(
        "ping",
        remote_id,
        settled_kind,
        upgrade_for_log,
        relay_only,
    ));

    match format {
        OutputFormat::Json => {
            // Always stdout — machine output for jq, even under -q.
            // `rtt_us` / `path` are settled (trust these); `initial_*` diagnose
            // the post-handshake race.
            println!(
                "{{\"peer\":\"{peer}\",\"rtt_us\":{rtt},\"path\":\"{path}\",\
\"initial_rtt_us\":{init_rtt},\"initial_path\":\"{init_path}\",\
\"settled_rtt_us\":{rtt},\"settled_path\":\"{path}\"}}",
                peer = remote_id,
                rtt = settled_rtt_us,
                path = settled_path,
                init_rtt = initial_rtt_us,
                init_path = initial_path,
            );
        }
        OutputFormat::Text => {
            ui.line(styler.ok(&tr_fmt!(
                "pong from {0}",
                remote_id.fmt_short()
            )));
            ui.line(styler.dim(&tr_fmt!(
                "initial: RTT {0}µs, {1}",
                initial_rtt_us,
                path_kind_human(initial_kind)
            )));
            ui.line(styler.dim(&tr_fmt!(
                "settled: RTT {0}µs, {1}",
                settled_rtt_us,
                path_kind_human(settled_kind)
            )));
            tracing::debug!(
                initial_path = initial_path,
                settled_path = settled_path,
                initial_rtt_us,
                settled_rtt_us,
                udp_tx = stats.udp_tx.datagrams,
                udp_rx = stats.udp_rx.datagrams,
                "ping path from iroh paths(); udp_* are not used for classification"
            );
        }
    }
    endpoint.close().await;
    Ok(())
}

