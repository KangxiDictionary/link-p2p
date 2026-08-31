//! Bidirectional byte pipes between a local I/O pair and a QUIC stream.
//!
//! One shared `select!` loop drives both directions: a clean half-close does
//! not cancel the other direction; an error aborts and RESET/STOPS the peer.
//!
//! # QUIC stream visibility (read this before adding a new stream feature)
//!
//! QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)) has **no**
//! "stream opened" control frame. `open_bi()` / `open_uni()` only allocate a
//! local stream id and local state; the peer learns the stream exists when the
//! first STREAM frame that references that id arrives — even empty data with
//! FIN counts. Until then, the acceptor's `accept_bi()` waits forever while
//! connection-level keepalive still looks healthy.
//!
//! Therefore: the side that opens a stream **must** write something at a
//! deterministic time (a real header, or a sentinel like [`STREAM_HELLO`]).
//! Do not assume "the far side will speak first" — download-first and
//! server-banner protocols (SSH, many TCP services) never send on the dialer
//! side until they have seen the peer. Proxy/SOCKS5 already satisfies this
//! via `write_target`; fixed-forward (`serve --forward` / `connect --listen`
//! / `--stdio`) uses [`STREAM_HELLO`] for the same reason.

use anyhow::{bail, Context, Result};
use iroh::endpoint::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::Instrument;

use crate::i18n::{tr, tr_fmt};

/// Error code when we abort a QUIC stream mid-transfer.
pub(crate) const STREAM_ABORT_CODE: VarInt = VarInt::from_u32(1);

/// How long Ctrl+C waits for in-flight forwards to flush.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// First bytes on every fixed-forward QUIC stream (`serve --forward` with
/// `connect --listen` / `--stdio`). Makes the dialer's `open_bi()` visible on
/// the wire. Tied to ALPN `link-p2p/tcp-forward/1` — must bump together.
pub(crate) const STREAM_HELLO: &[u8; 4] = b"LPF1";

/// Write [`STREAM_HELLO`] so the peer's `accept_bi` can complete.
///
/// No flush: callers pass an unbuffered iroh `SendStream` (same rule as
/// `socks5::write_target`).
pub(crate) async fn write_stream_hello<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    w.write_all(STREAM_HELLO)
        .await
        .context(tr!("writing stream hello"))?;
    Ok(())
}

/// Consume and validate [`STREAM_HELLO`]. Failures are immediate and logged
/// by the caller — they must not hang like a silent `accept_bi` wait.
pub(crate) async fn read_stream_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut hello = [0u8; 4];
    r.read_exact(&mut hello)
        .await
        .context(tr!("reading stream hello"))?;
    if &hello != STREAM_HELLO {
        bail!(tr_fmt!(
            "bad stream hello (expected LPF1, got {0})",
            format!(
                "{:02x}{:02x}{:02x}{:02x}",
                hello[0], hello[1], hello[2], hello[3]
            )
        ));
    }
    Ok(())
}

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
    // Abort-on-error (not wait-for-both): once one direction fails, the peer
    // is unlikely to drain the other half cleanly, and waiting can hang on a
    // stuck `copy`. Dropping the unfinished future + STOP/RESET below is the
    // intentional teardown; the match arms below always run that abort when
    // only one side finished.
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
///
/// All handles are polled concurrently (via [`tokio::task::JoinSet`]); the
/// wait is capped so Ctrl+C cannot hang forever on a stuck peer.
pub(crate) async fn drain_tasks(tasks: Vec<JoinHandle<()>>) {
    let mut set = tokio::task::JoinSet::new();
    for handle in tasks {
        set.spawn(async move {
            let _ = handle.await;
        });
    }
    let _ = time::timeout(DRAIN_TIMEOUT, async {
        while set.join_next().await.is_some() {}
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stream_hello_round_trip() {
        let mut buf = Vec::new();
        write_stream_hello(&mut buf).await.unwrap();
        assert_eq!(buf.as_slice(), STREAM_HELLO.as_slice());
        read_stream_hello(&mut buf.as_slice()).await.unwrap();
    }

    #[tokio::test]
    async fn stream_hello_rejects_garbage() {
        let _lang = crate::i18n::pin_english_catalog();
        let junk: &[u8] = b"XXXX";
        let err = read_stream_hello(&mut &*junk).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bad stream hello"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn stream_hello_rejects_short_read() {
        let _lang = crate::i18n::pin_english_catalog();
        let short: &[u8] = b"LP";
        let err = read_stream_hello(&mut &*short).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reading stream hello"),
            "unexpected error: {msg}"
        );
    }
}
