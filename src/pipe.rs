//! Bidirectional byte pipes between a local I/O pair and a QUIC stream.
//!
//! One shared `select!` loop drives both directions: a clean half-close does
//! not cancel the other direction; an error aborts and RESET/STOPS the peer.

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::Instrument;

use crate::i18n::tr;

/// Error code when we abort a QUIC stream mid-transfer.
pub(crate) const STREAM_ABORT_CODE: VarInt = VarInt::from_u32(1);

/// How long Ctrl+C waits for in-flight forwards to flush.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP ↔ QUIC bidi stream.
pub(crate) async fn pipe_streams(tcp: TcpStream, send: SendStream, recv: RecvStream) -> Result<()> {
    let span = tracing::debug_span!(
        "pipe",
        sent_bytes = tracing::field::Empty,
        recv_bytes = tracing::field::Empty
    );
    let record_span = span.clone();
    let fut = async move {
        let (mut tcp_read, mut tcp_write) = tcp.into_split();
        let (sent, recvd) = pipe_halves(
            &mut tcp_read,
            &mut tcp_write,
            send,
            recv,
            /*shutdown_local=*/ true,
        )
        .await?;
        record_span.record("sent_bytes", sent);
        record_span.record("recv_bytes", recvd);
        Ok(())
    };
    fut.instrument(span).await
}

/// stdin/stdout ↔ QUIC (`connect --stdio`). Unix builds only.
#[cfg(unix)]
pub(crate) async fn pipe_stdio(send: SendStream, recv: RecvStream) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let (_sent, _recvd) = pipe_halves(
        &mut stdin,
        &mut stdout,
        send,
        recv,
        /*shutdown_local=*/ false,
    )
    .await?;
    let _ = stdout.flush().await;
    Ok(())
}

/// Shared two-direction copy. `shutdown_local` runs `AsyncWriteExt::shutdown`
/// on the local write half after remote→local EOF (TCP FIN); stdio only flushes.
async fn pipe_halves<R, W>(
    local_read: &mut R,
    local_write: &mut W,
    mut send: SendStream,
    mut recv: RecvStream,
    shutdown_local: bool,
) -> Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client_to_remote = async {
        let n = copy(local_read, &mut send).await?;
        send.finish().context(tr!("finishing send stream"))?;
        Ok::<_, anyhow::Error>(n)
    };
    let remote_to_client = async {
        let r = copy(&mut recv, local_write).await;
        if shutdown_local {
            let _ = local_write.shutdown().await;
        }
        r
    };

    let mut client_to_remote = Box::pin(client_to_remote);
    let mut remote_to_client = Box::pin(remote_to_client);
    let (mut res_client, mut res_remote) = (None, None);
    while res_client.is_none() || res_remote.is_none() {
        tokio::select! {
            r = &mut client_to_remote, if res_client.is_none() => {
                let err = r.is_err();
                res_client = Some(r);
                if err { break; }
            }
            r = &mut remote_to_client, if res_remote.is_none() => {
                let err = r.is_err();
                res_remote = Some(r);
                if err { break; }
            }
        }
    }
    drop(client_to_remote);
    drop(remote_to_client);

    match (res_client, res_remote) {
        (Some(a), Some(b)) => Ok((a?, b?)),
        (Some(a), None) => {
            let _ = recv.stop(STREAM_ABORT_CODE);
            a.map(|n| (n, 0))
        }
        (None, Some(b)) => {
            let _ = send.reset(STREAM_ABORT_CODE);
            b.map(|n| (0, n))
        }
        (None, None) => {
            // Invariant: the select loop always records at least one side
            // before exiting; treat as no-op transfer rather than panic.
            debug_assert!(false, "pipe loop exited with neither side finished");
            Ok((0, 0))
        }
    }
}

async fn copy<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(reader, writer)
        .await
        .context(tr!("copying stream data"))
}

/// Wait up to [`DRAIN_TIMEOUT`] for spawned forwarder tasks to finish.
pub(crate) async fn drain_tasks(mut tasks: Vec<JoinHandle<()>>) {
    let deadline = time::sleep(DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    while !tasks.is_empty() {
        tokio::select! {
            biased;
            _ = &mut deadline => break,
            _ = &mut tasks[0] => {
                tasks.remove(0);
            }
        }
    }
}
