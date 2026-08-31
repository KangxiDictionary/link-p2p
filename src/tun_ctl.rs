//! Local TUN daemon control protocol (not the QUIC roster wire format).
//!
//! Frame: `LPC1` magic + version byte + `u32` BE length + JSON body.
//! Distinct from [`crate::tun_roster::ROSTER_MAGIC`] (`LPR2`) on purpose —
//! control-plane messages are variable-size and versioned independently of
//! the mesh roster stream.
//!
//! ## Runtime paths (SSOT)
//!
//! Two modes — selected by the **`--system` CLI flag only** (never an env var):
//!
//! | Resource | [`RuntimeMode::AdHoc`] | [`RuntimeMode::System`] |
//! |---|---|---|
//! | Control (Unix) | `$CONFIG/link-p2p/tun.sock` | Linux: `/run/link-p2p/tun.sock`; macOS: `/var/run/link-p2p/tun.sock` |
//! | Control (Windows) | hashed pipe under user config | `\\.\pipe\link-p2p-tun-system` ([`WINDOWS_SYSTEM_PIPE_SDDL`]) |
//! | Lock | `tun.lock` beside socket | same runtime dir (`%ProgramData%\link-p2p` on Windows) |
//! | Pid file | `tun.pid` (hint + session persistence) | **none** (supervisor owns the process) |
//! | Log file | `tun.log` (not rotated) | **none** (journald / plist / SCM paths) |
//! | Session token | in pid file + Status | **in-memory only**, still in Status |
//!
//! Path helpers ([`socket_path`], [`lock_path`], …) are **pure** — they never
//! touch the filesystem or require privilege. Bind/create is the caller's job.
//!
//! **Identity** is separate from control paths: system services must pass
//! `--identity` (see [`default_system_identity_path`]); do not rely on the
//! service account's `$HOME/.config/link-p2p/identity.key`.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::tun_roster::RosterEntry;

/// Where the TUN daemon stores its control socket / lock / optional pid+log.
///
/// Selected explicitly via `--system` on CLI subcommands — not inferred from
/// euid, not passed through spawn env vars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeMode {
    /// User ad-hoc `tun up` — paths under [`crate::config::config_dir`].
    #[default]
    AdHoc,
    /// Supervisor-managed service — fixed paths, no pid/log files.
    System,
}

impl RuntimeMode {
    pub fn from_system_flag(system: bool) -> Self {
        if system {
            Self::System
        } else {
            Self::AdHoc
        }
    }
}

/// Base directory for control socket + lock (and ad-hoc pid/log).
///
/// Pure function — no IO, no privilege checks.
pub fn runtime_dir(mode: RuntimeMode) -> PathBuf {
    match mode {
        RuntimeMode::AdHoc => crate::config::config_dir(),
        RuntimeMode::System => system_runtime_dir(),
    }
}

fn system_runtime_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/link-p2p")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/link-p2p")
    }
    #[cfg(windows)]
    {
        // Lock / identity live under ProgramData; the named pipe path is
        // separate (see [`socket_path`] / [`windows_system_pipe_name`]).
        match std::env::var_os("ProgramData") {
            Some(pd) => PathBuf::from(pd).join("link-p2p"),
            None => PathBuf::from(r"C:\ProgramData\link-p2p"),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        PathBuf::from("/run/link-p2p")
    }
}

/// Default identity key path for supervisor-managed (`--system`) installs.
///
/// Windows: `%ProgramData%\link-p2p\identity.key`. Elsewhere:
/// `/etc/link-p2p/identity.key`.
pub fn default_system_identity_path() -> PathBuf {
    #[cfg(windows)]
    {
        system_runtime_dir().join("identity.key")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/link-p2p/identity.key")
    }
}

/// SDDL for the Windows system named pipe (`\\.\pipe\link-p2p-tun-system`).
///
/// `BUILTIN\Users` get connect (GR/GW); SYSTEM and Administrators get full
/// control. Privileged ctl ops (`Shutdown`) are still gated in-process via
/// impersonation — DACL alone is not enough.
pub const WINDOWS_SYSTEM_PIPE_SDDL: &str = "D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)";

/// Unix domain socket path, or Windows named pipe path.
pub fn socket_path(mode: RuntimeMode) -> PathBuf {
    #[cfg(windows)]
    if mode == RuntimeMode::System {
        return PathBuf::from(windows_system_pipe_name());
    }
    #[cfg(windows)]
    if mode == RuntimeMode::AdHoc {
        return PathBuf::from(windows_adhoc_pipe_name());
    }
    runtime_dir(mode).join("tun.sock")
}

/// Optional pid file — ad-hoc only. System mode returns `None` (supervisor
/// tracks the process; ctl session token lives in memory).
pub fn pid_path(mode: RuntimeMode) -> Option<PathBuf> {
    match mode {
        RuntimeMode::AdHoc => Some(runtime_dir(mode).join("tun.pid")),
        RuntimeMode::System => None,
    }
}

/// Optional detached log — ad-hoc background `tun up` only.
pub fn log_path(mode: RuntimeMode) -> Option<PathBuf> {
    match mode {
        RuntimeMode::AdHoc => Some(runtime_dir(mode).join("tun.log")),
        RuntimeMode::System => None,
    }
}

/// Exclusive lock held for the whole daemon lifetime.
pub fn lock_path(mode: RuntimeMode) -> PathBuf {
    runtime_dir(mode).join("tun.lock")
}

/// Whether this mode uses a Unix domain socket (vs Windows named pipe).
pub fn uses_unix_socket(mode: RuntimeMode) -> bool {
    #[cfg(windows)]
    {
        let _ = mode;
        false
    }
    #[cfg(not(windows))]
    {
        let _ = mode;
        true
    }
}

/// Ad-hoc Windows named pipe (hashed from user config dir).
#[cfg(windows)]
pub fn windows_adhoc_pipe_name() -> String {
    let dir = crate::config::config_dir();
    let h = blake3::hash(dir.to_string_lossy().as_bytes());
    let b = h.as_bytes();
    let short = format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
    );
    format!(r"\\.\pipe\link-p2p-tun-{short}")
}

/// System-service Windows named pipe (fixed name; DACL must grant CLI users).
#[cfg(windows)]
pub fn windows_system_pipe_name() -> String {
    r"\\.\pipe\link-p2p-tun-system".into()
}

/// Control-plane magic. Do not reuse roster `LPR2`.
pub const CTL_MAGIC: &[u8; 4] = b"LPC1";

/// Protocol version. Bump when request/response shapes are incompatible.
pub const CTL_VERSION: u8 = 1;

/// Max JSON body size (1 MiB) — peers lists stay small; this caps abuse.
pub const CTL_MAX_BODY: u32 = 1024 * 1024;

/// How long a liveness `connect` may block before we treat the socket as dead.
pub const PROBE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

/// Server-side bound for reading/writing one control frame. IPC over a local
/// socket completes in microseconds normally; this only fires on stuck or
/// abusive peers so one connection can never stall the control loop.
pub const CTL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// How long the parent waits for the child's ready line after spawn.
pub const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// One peer as exported to control-plane clients (JSON-friendly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlPeer {
    pub vip: Ipv4Addr,
    /// EndpointId as hex string (same display form as CLI elsewhere).
    pub id: String,
}

impl From<&RosterEntry> for CtlPeer {
    fn from(e: &RosterEntry) -> Self {
        Self {
            vip: e.vip,
            id: e.id.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlRequest {
    Status,
    Peers,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlResponse {
    Status {
        role: String,
        uptime_secs: u64,
        vip: Ipv4Addr,
        path_kind: String,
        /// Random session token for this daemon instance — confirms the
        /// control socket belongs to the expected process (guards stale socket
        /// files and PID reuse). Ad-hoc mode also mirrors this in `tun.pid`;
        /// system mode keeps it in memory only.
        #[serde(default)]
        session: String,
    },
    Peers {
        peers: Vec<CtlPeer>,
    },
    Ok,
    Err {
        code: i32,
        message: String,
    },
}

impl CtlResponse {
    /// Turn a control-plane error into a process [`exit::CodedError`].
    pub fn into_anyhow(self) -> Result<()> {
        match self {
            Self::Ok => Ok(()),
            Self::Err { code, message } => Err(exit::coded(code, anyhow::anyhow!(message))),
            other => Err(exit::coded(
                exit::OTHER,
                anyhow::anyhow!(tr_fmt!(
                    "unexpected control response (wanted Ok/Err, got {0})",
                    format!("{other:?}")
                )),
            )),
        }
    }
}

/// Encode a request or response body to the on-wire frame (owned bytes).
pub fn encode_frame(version: u8, body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).context(tr!("control body too large"))?;
    if len > CTL_MAX_BODY {
        bail!(tr_fmt!("control body exceeds max ({0} bytes)", CTL_MAX_BODY));
    }
    let mut out = Vec::with_capacity(4 + 1 + 4 + body.len());
    out.extend_from_slice(CTL_MAGIC);
    out.push(version);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

pub fn encode_request(req: &CtlRequest) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(req).context(tr!("encode control request"))?;
    encode_frame(CTL_VERSION, &body)
}

pub fn encode_response(resp: &CtlResponse) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(resp).context(tr!("encode control response"))?;
    encode_frame(CTL_VERSION, &body)
}

/// Decode header; return `(version, body_len)`.
fn parse_header(hdr: &[u8; 9]) -> Result<(u8, u32)> {
    if &hdr[..4] != CTL_MAGIC {
        bail!(tr!("bad control magic (expected LPC1)"));
    }
    let version = hdr[4];
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
    if len > CTL_MAX_BODY {
        bail!(tr_fmt!("control body exceeds max ({0} bytes)", CTL_MAX_BODY));
    }
    Ok((version, len))
}

fn check_version(version: u8) -> Result<()> {
    if version == CTL_VERSION {
        return Ok(());
    }
    let msg = if version > CTL_VERSION {
        tr_fmt!(
            "TUN daemon protocol is newer (v{0}) than this CLI (v{1}); upgrade link-p2p",
            version,
            CTL_VERSION
        )
    } else {
        tr_fmt!(
            "TUN daemon protocol is older (v{0}) than this CLI (v{1}); restart the daemon or downgrade the CLI",
            version,
            CTL_VERSION
        )
    };
    bail!(exit::coded(
        exit::USAGE,
        ProtocolMismatch::new(version, CTL_VERSION, msg),
    ));
}

/// Marker for a live-but-incompatible control protocol version.
///
/// Callers detect version mismatches via this type (downcast through the
/// error chain), **not** by substring-matching the message: the message is
/// `tr_fmt!`-translated, so English tokens like "protocol" / "upgrade" are
/// absent under other locales.
#[derive(Debug)]
pub struct ProtocolMismatch {
    pub daemon_version: u8,
    pub cli_version: u8,
    message: String,
}

impl ProtocolMismatch {
    pub fn new(daemon_version: u8, cli_version: u8, message: impl Into<String>) -> Self {
        Self {
            daemon_version,
            cli_version,
            message: message.into(),
        }
    }

    /// Find this marker anywhere in `err`'s chain, including inside a
    /// `CodedError` wrapper.
    ///
    /// A plain `err.chain()` walk misses it there: `CodedError::source()`
    /// returns `self.source.source()`, which collapses the inner
    /// `anyhow::Error` wrapper (whose own source is `None`). So check the
    /// wrapper's stored `source` field directly as well.
    pub fn from_error(err: &anyhow::Error) -> Option<&ProtocolMismatch> {
        err.chain().find_map(|c| {
            if let Some(pm) = c.downcast_ref::<ProtocolMismatch>() {
                Some(pm)
            } else if let Some(ce) = c.downcast_ref::<crate::exit::CodedError>() {
                ce.source.downcast_ref::<ProtocolMismatch>()
            } else {
                None
            }
        })
    }
}

impl fmt::Display for ProtocolMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolMismatch {}

/// Decode a full frame already buffered (header + body).
pub fn decode_request_frame(frame: &[u8]) -> Result<CtlRequest> {
    if frame.len() < 9 {
        bail!(tr!("control frame truncated"));
    }
    let mut hdr = [0u8; 9];
    hdr.copy_from_slice(&frame[..9]);
    let (version, len) = parse_header(&hdr)?;
    check_version(version)?;
    let body = frame
        .get(9..9 + len as usize)
        .context(tr!("control frame truncated"))?;
    serde_json::from_slice(body).context(tr!("decode control request"))
}

pub fn decode_response_frame(frame: &[u8]) -> Result<CtlResponse> {
    if frame.len() < 9 {
        bail!(tr!("control frame truncated"));
    }
    let mut hdr = [0u8; 9];
    hdr.copy_from_slice(&frame[..9]);
    let (version, len) = parse_header(&hdr)?;
    check_version(version)?;
    let body = frame
        .get(9..9 + len as usize)
        .context(tr!("control frame truncated"))?;
    serde_json::from_slice(body).context(tr!("decode control response"))
}

/// Read one framed message from `r`.
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

/// Error used when status/peers/down cannot reach a daemon.
pub fn not_running(mode: RuntimeMode) -> anyhow::Error {
    let msg = match mode {
        RuntimeMode::AdHoc => tr!("TUN daemon is not running (try: link-p2p tun up)"),
        RuntimeMode::System => tr!(
            "TUN system daemon is not running (try: link-p2p tun status --system, or check the service manager)"
        ),
    };
    exit::coded(exit::DAEMON_NOT_RUNNING, anyhow::anyhow!(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::io::Cursor;

    #[test]
    fn adhoc_paths_under_config_dir() {
        let base = crate::config::config_dir();
        let mode = RuntimeMode::AdHoc;
        #[cfg(not(windows))]
        assert_eq!(socket_path(mode), base.join("tun.sock"));
        #[cfg(windows)]
        assert_eq!(socket_path(mode).to_string_lossy(), windows_adhoc_pipe_name());
        assert_eq!(pid_path(mode), Some(base.join("tun.pid")));
        assert_eq!(log_path(mode), Some(base.join("tun.log")));
        assert_eq!(lock_path(mode), base.join("tun.lock"));
    }

    #[test]
    fn system_and_adhoc_paths_do_not_overlap() {
        let adhoc = socket_path(RuntimeMode::AdHoc);
        let system = socket_path(RuntimeMode::System);
        assert_ne!(adhoc, system);
        assert!(pid_path(RuntimeMode::System).is_none());
        assert!(log_path(RuntimeMode::System).is_none());

        #[cfg(target_os = "linux")]
        assert_eq!(system, PathBuf::from("/run/link-p2p/tun.sock"));
        #[cfg(target_os = "linux")]
        assert_eq!(lock_path(RuntimeMode::System), PathBuf::from("/run/link-p2p/tun.lock"));

        #[cfg(target_os = "macos")]
        assert_eq!(system, PathBuf::from("/var/run/link-p2p/tun.sock"));

        #[cfg(windows)]
        {
            assert_eq!(
                system.to_string_lossy(),
                r"\\.\pipe\link-p2p-tun-system"
            );
            assert_ne!(
                windows_adhoc_pipe_name(),
                windows_system_pipe_name()
            );
            let sys_dir = runtime_dir(RuntimeMode::System);
            assert_eq!(lock_path(RuntimeMode::System), sys_dir.join("tun.lock"));
            assert!(
                sys_dir.to_string_lossy().contains("link-p2p"),
                "system runtime dir should be under ProgramData\\link-p2p, got {sys_dir:?}"
            );
            // Pipe path must not be used as the lock directory.
            assert!(!sys_dir.to_string_lossy().contains(r"\\.\pipe"));
        }

        // Identity defaults must not collide with ad-hoc config identity.
        let sys_id = default_system_identity_path();
        let adhoc_id = crate::config::config_dir().join("identity.key");
        assert_ne!(sys_id, adhoc_id);
        assert_ne!(runtime_dir(RuntimeMode::System), runtime_dir(RuntimeMode::AdHoc));
    }

    #[test]
    fn windows_system_pipe_sddl_constant() {
        assert_eq!(
            WINDOWS_SYSTEM_PIPE_SDDL,
            "D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)"
        );
    }

    #[test]
    fn path_helpers_are_pure_no_io() {
        // Callable without privilege or existing directories.
        let _ = runtime_dir(RuntimeMode::System);
        let _ = socket_path(RuntimeMode::System);
        let _ = lock_path(RuntimeMode::System);
        let _ = default_system_identity_path();
    }

    #[test]
    fn request_response_roundtrip_sync() {
        let reqs = [
            CtlRequest::Status,
            CtlRequest::Peers,
            CtlRequest::Shutdown,
        ];
        for req in &reqs {
            let frame = encode_request(req).unwrap();
            assert_eq!(&frame[..4], CTL_MAGIC);
            assert_eq!(frame[4], CTL_VERSION);
            let got = decode_request_frame(&frame).unwrap();
            assert_eq!(&got, req);
        }

        let sk = SecretKey::generate();
        let peers = vec![CtlPeer {
            vip: Ipv4Addr::new(172, 24, 0, 1),
            id: sk.public().to_string(),
        }];
        let resps = [
            CtlResponse::Status {
                role: "hub".into(),
                uptime_secs: 42,
                vip: Ipv4Addr::new(172, 24, 0, 1),
                path_kind: "direct".into(),
                session: "abc".into(),
            },
            CtlResponse::Peers { peers },
            CtlResponse::Ok,
            CtlResponse::Err {
                code: exit::DENIED,
                message: "peer not allowed".into(),
            },
        ];
        for resp in &resps {
            let frame = encode_response(resp).unwrap();
            let got = decode_response_frame(&frame).unwrap();
            assert_eq!(&got, resp);
        }
    }

    #[tokio::test]
    async fn async_io_roundtrip() {
        let req = CtlRequest::Peers;
        let mut buf = Vec::new();
        write_request(&mut buf, &req).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_request(&mut cur).await.unwrap();
        assert_eq!(got, req);

        let resp = CtlResponse::Ok;
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_response(&mut cur).await.unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn version_mismatch_newer_daemon() {
        // Pin the process catalog to English while the message is baked and
        // asserted; the zh_CN help test can otherwise race us and make the
        // tr_fmt! output Chinese (the marker assertions below stay
        // locale-independent regardless).
        let _lang = crate::i18n::ENV_LOCK.lock().unwrap();
        crate::i18n::reset_catalog();
        crate::i18n::init();
        let body = serde_json::to_vec(&CtlRequest::Status).unwrap();
        let frame = encode_frame(CTL_VERSION + 1, &body).unwrap();
        let err = decode_request_frame(&frame).unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
        let msg = format!("{err:#}");
        assert!(msg.contains("newer") || msg.contains("upgrade"), "{msg}");
        // Locale-independent marker is present, so callers can detect the
        // mismatch without substring-matching a translated message.
        assert!(ProtocolMismatch::from_error(&err).is_some());
        let pm = ProtocolMismatch::from_error(&err).unwrap();
        assert_eq!(pm.daemon_version, CTL_VERSION + 1);
        assert_eq!(pm.cli_version, CTL_VERSION);
    }

    #[test]
    fn version_mismatch_older_daemon() {
        // Pin English while the message is baked/asserted (see the newer
        // variant above).
        let _lang = crate::i18n::ENV_LOCK.lock().unwrap();
        crate::i18n::reset_catalog();
        crate::i18n::init();
        // Encode with a fake lower version in the header.
        let body = serde_json::to_vec(&CtlRequest::Status).unwrap();
        let mut frame = encode_frame(CTL_VERSION, &body).unwrap();
        frame[4] = 0; // older than CTL_VERSION (1)
        let err = decode_request_frame(&frame).unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
        let msg = format!("{err:#}");
        assert!(msg.contains("older") || msg.contains("restart"), "{msg}");
    }

    #[test]
    fn bad_magic() {
        let mut frame = encode_request(&CtlRequest::Status).unwrap();
        frame[0] = b'X';
        assert!(decode_request_frame(&frame).is_err());
    }

    #[test]
    fn err_response_maps_exit_code() {
        let resp = CtlResponse::Err {
            code: exit::TIMEOUT,
            message: "waited too long".into(),
        };
        let err = resp.into_anyhow().unwrap_err();
        assert_eq!(exit::code_from(&err), exit::TIMEOUT);
    }

    #[test]
    fn not_running_code() {
        assert_eq!(
            exit::code_from(&not_running(RuntimeMode::AdHoc)),
            exit::DAEMON_NOT_RUNNING
        );
        assert_eq!(
            exit::code_from(&not_running(RuntimeMode::System)),
            exit::DAEMON_NOT_RUNNING
        );
    }

    #[test]
    fn ctl_peer_from_roster() {
        let sk = SecretKey::generate();
        let e = RosterEntry {
            vip: Ipv4Addr::new(172, 24, 9, 9),
            id: sk.public(),
        };
        let p = CtlPeer::from(&e);
        assert_eq!(p.vip, e.vip);
        assert_eq!(p.id, e.id.to_string());
    }
}
