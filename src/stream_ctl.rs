//! Local stream phone daemon control protocol (not TUN).
//!
//! Frame: `SPC1` magic + version byte + `u32` BE length + JSON body.
//! Distinct from TUN [`crate::tun_ctl`] (`LPC1`) so sockets never cross-talk.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::exit;
use crate::i18n::{tr, tr_fmt};

pub const CTL_MAGIC: &[u8; 4] = b"SPC1";
pub const CTL_VERSION: u8 = 1;
pub const CTL_MAX_BODY: u32 = 1024 * 1024;
pub const PROBE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);
pub const CTL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
pub const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub fn runtime_dir() -> PathBuf {
    crate::config::config_dir()
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("call.sock")
}

pub fn pid_path() -> PathBuf {
    runtime_dir().join("call.pid")
}

pub fn lock_path() -> PathBuf {
    runtime_dir().join("call.lock")
}

pub fn log_path() -> PathBuf {
    runtime_dir().join("call.log")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCall {
    pub peer: String,
    pub since_unix_ms: u64,
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPeer {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlRequest {
    Status,
    Peers,
    Shutdown,
    /// Outbound dial; optional listen/forward apply to the local side of the session.
    Call {
        to: String,
        #[serde(default)]
        listen: Option<SocketAddr>,
        #[serde(default)]
        forward: Option<SocketAddr>,
        #[serde(default)]
        to_addr: Vec<SocketAddr>,
    },
    Accept { peer: String },
    Reject { peer: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlResponse {
    Status {
        role: String,
        uptime_secs: u64,
        session: String,
        phase: String,
        #[serde(default)]
        listen: Option<SocketAddr>,
        #[serde(default)]
        forward: Option<SocketAddr>,
        pending_calls: Vec<PendingCall>,
    },
    Peers { peers: Vec<StreamPeer> },
    Ok,
    Err { code: i32, message: String },
}

pub fn encode_frame(version: u8, body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).context(tr!("control body too large"))?;
    if len > CTL_MAX_BODY {
        bail!(tr_fmt!(
            "control body exceeds max ({0} bytes)",
            CTL_MAX_BODY
        ));
    }
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(CTL_MAGIC);
    out.push(version);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn parse_header(hdr: &[u8; 9]) -> Result<(u8, u32)> {
    if &hdr[..4] != CTL_MAGIC {
        bail!(tr!("bad control magic (expected SPC1)"));
    }
    let version = hdr[4];
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
    if len > CTL_MAX_BODY {
        bail!(tr_fmt!(
            "control body exceeds max ({0} bytes)",
            CTL_MAX_BODY
        ));
    }
    Ok((version, len))
}

fn check_version(version: u8) -> Result<()> {
    if version == CTL_VERSION {
        return Ok(());
    }
    bail!(exit::coded(
        exit::USAGE,
        anyhow::anyhow!(tr_fmt!(
            "stream call daemon protocol mismatch (daemon v{0}, CLI v{1})",
            version,
            CTL_VERSION
        )),
    ));
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    r.read_exact(&mut hdr)
        .await
        .context(tr!("read control header"))?;
    let (version, len) = parse_header(&hdr)?;
    let mut body = vec![0u8; len as usize];
    if len > 0 {
        r.read_exact(&mut body)
            .await
            .context(tr!("read control body"))?;
    }
    Ok((version, body))
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    version: u8,
    body: &[u8],
) -> Result<()> {
    let frame = encode_frame(version, body)?;
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_request<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<CtlRequest> {
    let (version, body) = read_frame(r).await?;
    check_version(version)?;
    serde_json::from_slice(&body).context(tr!("decode control request"))
}

pub async fn read_response<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<CtlResponse> {
    let (version, body) = read_frame(r).await?;
    check_version(version)?;
    serde_json::from_slice(&body).context(tr!("decode control response"))
}

pub async fn write_request<W: AsyncWriteExt + Unpin>(w: &mut W, req: &CtlRequest) -> Result<()> {
    let body = serde_json::to_vec(req).context(tr!("encode control request"))?;
    write_frame(w, CTL_VERSION, &body).await
}

pub async fn write_response<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    resp: &CtlResponse,
) -> Result<()> {
    let body = serde_json::to_vec(resp).context(tr!("encode control response"))?;
    write_frame(w, CTL_VERSION, &body).await
}

pub fn not_running() -> anyhow::Error {
    exit::coded(
        exit::DAEMON_NOT_RUNNING,
        anyhow::anyhow!(tr!(
            "stream call daemon is not running (try: link-p2p call up)"
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn not_running_code() {
        assert_eq!(
            exit::code_from(&not_running()),
            exit::DAEMON_NOT_RUNNING
        );
    }

    #[tokio::test]
    async fn status_request_round_trip() {
        let req = CtlRequest::Status;
        let mut buf = Vec::new();
        write_request(&mut buf, &req).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_request(&mut cur).await.unwrap();
        assert!(matches!(got, CtlRequest::Status));
    }

    #[tokio::test]
    async fn status_response_round_trip() {
        let resp = CtlResponse::Status {
            role: "phone".into(),
            uptime_secs: 3,
            session: "abc".into(),
            phase: "idle".into(),
            listen: None,
            forward: None,
            pending_calls: vec![PendingCall {
                peer: "peer".into(),
                since_unix_ms: 1,
                direction: "in".into(),
            }],
        };
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_response(&mut cur).await.unwrap();
        match got {
            CtlResponse::Status {
                role,
                uptime_secs,
                session,
                phase,
                pending_calls,
                ..
            } => {
                assert_eq!(role, "phone");
                assert_eq!(uptime_secs, 3);
                assert_eq!(session, "abc");
                assert_eq!(phase, "idle");
                assert_eq!(pending_calls.len(), 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_bad_magic() {
        let mut bad = b"XXXX".to_vec();
        bad.push(CTL_VERSION);
        bad.extend_from_slice(&0u32.to_be_bytes());
        let mut cur = Cursor::new(bad);
        let err = read_request(&mut cur).await.unwrap_err();
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(msg.contains("magic") || msg.contains("spc1"), "{msg}");
    }

    #[tokio::test]
    async fn rejects_version_mismatch() {
        let body = serde_json::to_vec(&CtlRequest::Status).unwrap();
        let frame = encode_frame(CTL_VERSION + 1, &body).unwrap();
        let mut cur = Cursor::new(frame);
        let err = read_request(&mut cur).await.unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
    }

    #[test]
    fn encode_rejects_oversized_body() {
        let body = vec![0u8; (CTL_MAX_BODY as usize) + 1];
        assert!(encode_frame(CTL_VERSION, &body).is_err());
    }
}
