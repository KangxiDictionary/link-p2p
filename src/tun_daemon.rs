//! TUN daemon lifecycle: lock, liveness probe, spawn, ready handshake, CLI.
//!
//! Checklist #2–#5: control socket + flock + spawn/ready + live worker +
//! `tun up/down/status/peers`. Skeleton workers (no TUN) keep unprivileged tests
//! fast; live workers need CAP_NET_ADMIN / root.
//!
//! Liveness: **socket Status handshake is truth**; the pid file is a hint plus
//! a session token against PID reuse. Mutual exclusion is `fslock` on
//! `tun.lock`, held for the whole daemon lifetime.

use std::fs::{self};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use fslock::LockFile;
use iroh::EndpointId;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader};
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::contacts;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::style::Styler;
use crate::tun_ctl::{
    self, write_request, write_response, CtlPeer, CtlRequest, CtlResponse,
    RuntimeMode, CTL_READ_TIMEOUT, PROBE_CONNECT_TIMEOUT, READY_TIMEOUT,
};

const ENV_WORKER: &str = "LINK_P2P_TUN_WORKER";
const ENV_READY: &str = "LINK_P2P_TUN_READY";
const ENV_ROLE: &str = "LINK_P2P_TUN_ROLE";
const ENV_SESSION: &str = "LINK_P2P_TUN_SESSION";
/// Tests set this so the worker stays in the foreground of the test harness.
const ENV_SKELETON: &str = "LINK_P2P_TUN_SKELETON";
/// Test-only: worker sleeps without sending ready (parent should TIMEOUT).
const ENV_STUCK_READY: &str = "LINK_P2P_TUN_TEST_STUCK_READY";
/// Test-only: override ready wait (milliseconds).
const ENV_READY_TIMEOUT_MS: &str = "LINK_P2P_TUN_READY_TIMEOUT_MS";
/// Test-only: pin the parent's ready listener to this address so a test can
/// race a fake connection against the real worker's ready handshake.
const ENV_TEST_READY_ADDR: &str = "LINK_P2P_TUN_TEST_READY_ADDR";
/// Nonce passed to the worker so the parent can tell its child's ready line
/// from any stray connection to the ephemeral ready port.
const ENV_READY_NONCE: &str = "LINK_P2P_TUN_READY_NONCE";

/// Bounded window for in-flight control requests after `Shutdown` is raised.
const CTL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Socket mode for the control socket: ad-hoc is owner-only; system mode is
/// world-connectable (the daemon itself authorizes `Shutdown` via peer creds).
#[cfg(unix)]
fn socket_mode(mode: RuntimeMode) -> u32 {
    if mode == RuntimeMode::System {
        0o666
    } else {
        0o600
    }
}

/// Format a ready line as the worker sends it: `{nonce} {suffix}` when the
/// parent handed us a nonce, plain `suffix` otherwise (in-process tests).
fn ready_line(suffix: &str) -> String {
    match std::env::var(ENV_READY_NONCE) {
        Ok(n) if !n.is_empty() => format!("{n} {suffix}"),
        _ => suffix.to_string(),
    }
}

/// Output format for `tun status` / `tun peers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliFormat {
    Text,
    Json,
}

/// Options for detached daemon spawn (`tun up` without `--foreground`).
#[derive(Debug, Clone, Default)]
pub struct SpawnOpts {
    pub role: String,
    pub to: Option<String>,
    pub mtu: Option<u16>,
    pub tun_ip: Option<Ipv4Addr>,
    pub allow: Vec<String>,
}

/// Parameters for supervisor-managed `tun up --foreground --system`.
pub struct SupervisedUpOpts {
    pub role: String,
    pub to: Option<String>,
    pub tun_ip: Option<Ipv4Addr>,
    pub mtu: u16,
    pub allow: Option<std::collections::HashSet<iroh::EndpointId>>,
    pub to_addr: Vec<std::net::SocketAddr>,
    pub secret_key: iroh::SecretKey,
    pub relays: Vec<String>,
    pub relay_only: bool,
    pub no_n0_relays: bool,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub tune: crate::TransportTune,
}

fn ready_timeout() -> Duration {
    if let Ok(ms) = std::env::var(ENV_READY_TIMEOUT_MS) {
        if let Ok(n) = ms.parse::<u64>() {
            return Duration::from_millis(n.max(50));
        }
    }
    READY_TIMEOUT
}

/// Resolve `--role` / `--to` defaults and contradictions for `tun up`.
pub fn resolve_up_role(role: Option<&str>, to: Option<&str>) -> Result<String> {
    let role = role.map(|s| s.to_ascii_lowercase());
    match (role.as_deref(), to) {
        (Some("hub"), Some(_)) => bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "`--role hub` cannot be combined with `--to` (hub does not dial a peer)"
            )),
        )),
        (Some("spoke"), None) => bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "`--role spoke` requires `--to <hub EndpointId>`"
            )),
        )),
        (Some("hub") | None, None) => Ok("hub".into()),
        (Some("spoke") | None, Some(_)) => Ok("spoke".into()),
        (Some(other), _) => bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr_fmt!(
                "invalid `--role {0}` (expected hub or spoke)",
                other
            )),
        )),
    }
}

/// Human-readable uptime for text `tun status`.
pub fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Written under `config_dir()/tun.pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidRecord {
    pub pid: u32,
    pub session: String,
    pub started_unix_ms: u64,
}

impl PidRecord {
    pub fn encode(&self) -> String {
        format!(
            "pid={}\nsession={}\nstarted_unix_ms={}\n",
            self.pid, self.session, self.started_unix_ms
        )
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut pid = None;
        let mut session = None;
        let mut started_unix_ms = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("pid=") {
                pid = Some(
                    rest.parse::<u32>()
                        .context(tr!("invalid pid in tun.pid"))?,
                );
            } else if let Some(rest) = line.strip_prefix("session=") {
                session = Some(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("started_unix_ms=") {
                started_unix_ms = Some(
                    rest.parse::<u64>()
                        .context(tr!("invalid started_unix_ms in tun.pid"))?,
                );
            }
        }
        Ok(Self {
            pid: pid.context(tr!("tun.pid missing pid="))?,
            session: session.context(tr!("tun.pid missing session="))?,
            started_unix_ms: started_unix_ms.context(tr!("tun.pid missing started_unix_ms="))?,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| {
            tr_fmt!("reading pid file {0}", path.display().to_string())
        })?;
        Self::parse(&text)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let tmp = path.with_extension("pid.tmp");
        fs::write(&tmp, self.encode()).with_context(|| {
            tr_fmt!("writing pid file {0}", tmp.display().to_string())
        })?;
        fs::rename(&tmp, path).with_context(|| {
            tr_fmt!("writing pid file {0}", path.display().to_string())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Result of a liveness probe. Socket handshake wins over the pid file.
#[derive(Debug)]
pub enum Liveness {
    NotRunning,
    Running {
        status: CtlResponse,
        pid: Option<PidRecord>,
    },
}

pub fn random_session() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("getrandom");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        // `None` = existence check (kill with signal 0).
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        // Windows: do not trust PID alone; socket handshake is authoritative.
        false
    }
}

/// True when this process was spawned as the TUN daemon worker.
pub fn is_worker_process() -> bool {
    std::env::var_os(ENV_WORKER).is_some()
}

// ——— Unix control socket helpers ——————————————————————————————————————

#[cfg(unix)]
#[allow(clippy::wildcard_imports)] // keeps the unix control helpers readable
mod ctl_sock {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    pub async fn connect_timed(path: &Path, limit: Duration) -> Result<UnixStream> {
        match timeout(limit, UnixStream::connect(path)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => bail!(tr!("TUN control socket connect timed out")),
        }
    }

    pub async fn handshake_status(path: &Path) -> Result<CtlResponse> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT).await?;
        write_request(&mut stream, &CtlRequest::Status).await?;
        let resp = timeout(PROBE_CONNECT_TIMEOUT, tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!(tr!("TUN control Status timed out")))??;
        Ok(resp)
    }

    pub async fn handshake_peers(path: &Path) -> Result<CtlResponse> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT).await?;
        write_request(&mut stream, &CtlRequest::Peers).await?;
        let resp = timeout(PROBE_CONNECT_TIMEOUT, tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!(tr!("TUN control Peers timed out")))??;
        Ok(resp)
    }

    /// If a live daemon answers, return its Status. Otherwise unlink a stale
    /// socket file (failed / timed-out connect) so a new bind can succeed.
    /// Protocol/version errors are propagated (do not unlink a live peer's sock).
    pub async fn prepare_bind(path: &Path) -> Result<Option<CtlResponse>> {
        if !path.exists() {
            return Ok(None);
        }
        match handshake_status(path).await {
            Ok(status @ CtlResponse::Status { .. }) => Ok(Some(status)),
            Ok(other) => bail!(tr_fmt!(
                "unexpected Status response from TUN daemon: {0}",
                format!("{other:?}")
            )),
            Err(e) if is_protocol_error(&e) => Err(e),
            Err(_) => {
                let _ = fs::remove_file(path);
                Ok(None)
            }
        }
    }

    pub fn bind_listener(path: &Path, mode: u32) -> Result<UnixListener> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        // Tighten the process umask while binding so the socket file is never
        // born with broader permissions than intended (no bind→chmod window
        // where a local peer could sneak in before the chmod lands).
        let old = rustix::process::umask(rustix::fs::Mode::from_bits(0o177).unwrap());
        let bound = UnixListener::bind(path);
        rustix::process::umask(old);
        let listener = bound.with_context(|| {
            tr_fmt!("binding TUN control socket {0}", path.display().to_string())
        })?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        Ok(listener)
    }

    pub async fn send_shutdown(path: &Path, mode: RuntimeMode) -> Result<()> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT)
            .await
            .map_err(|_| tun_ctl::not_running(mode))?;
        write_request(&mut stream, &CtlRequest::Shutdown).await?;
        let resp = timeout(ready_timeout(), tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| {
                exit::coded(
                    exit::TIMEOUT,
                    anyhow::anyhow!(tr!("TUN daemon Shutdown timed out")),
                )
            })??;
        match resp {
            CtlResponse::Ok => Ok(()),
            CtlResponse::Err { code, message } => Err(exit::coded(code, anyhow::anyhow!(message))),
            other => bail!(tr_fmt!(
                "unexpected Shutdown response: {0}",
                format!("{other:?}")
            )),
        }
    }
}

#[cfg(windows)]
#[allow(clippy::wildcard_imports)]
mod ctl_sock {
    use super::*;
    use tokio::net::windows::named_pipe::NamedPipeClient;

    fn pipe_name(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    pub async fn connect_timed(path: &Path, limit: Duration) -> Result<NamedPipeClient> {
        let name = pipe_name(path);
        let connect = async {
            loop {
                match crate::win_pipe::connect_client(&name) {
                    Ok(c) => return Ok(c),
                    Err(e) if crate::win_pipe::is_pipe_busy(&e) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        match timeout(limit, connect).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(_) => bail!(tr!("TUN control socket connect timed out")),
        }
    }

    pub async fn handshake_status(path: &Path) -> Result<CtlResponse> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT).await?;
        write_request(&mut stream, &CtlRequest::Status).await?;
        let resp = timeout(PROBE_CONNECT_TIMEOUT, tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!(tr!("TUN control Status timed out")))??;
        Ok(resp)
    }

    pub async fn handshake_peers(path: &Path) -> Result<CtlResponse> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT).await?;
        write_request(&mut stream, &CtlRequest::Peers).await?;
        let resp = timeout(PROBE_CONNECT_TIMEOUT, tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!(tr!("TUN control Peers timed out")))??;
        Ok(resp)
    }

    /// Try a Status handshake. On failure return `Ok(None)` — named pipes are
    /// not filesystem paths, so there is nothing to unlink.
    pub async fn prepare_bind(path: &Path) -> Result<Option<CtlResponse>> {
        match handshake_status(path).await {
            Ok(status @ CtlResponse::Status { .. }) => Ok(Some(status)),
            Ok(other) => bail!(tr_fmt!(
                "unexpected Status response from TUN daemon: {0}",
                format!("{other:?}")
            )),
            Err(e) if is_protocol_error(&e) => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// Accepts overlapping named-pipe instances (one per client).
    pub struct PipeAcceptor {
        name: String,
        system: bool,
    }

    impl PipeAcceptor {
        pub async fn accept(&self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
            let handle = crate::win_pipe::create_server_instance(&self.name, self.system)?;
            let server = crate::win_pipe::into_server(handle)?;
            server
                .connect()
                .await
                .context(tr!("waiting for named-pipe client"))?;
            Ok(server)
        }
    }

    pub fn bind_listener(path: &Path, mode: RuntimeMode) -> Result<PipeAcceptor> {
        Ok(PipeAcceptor {
            name: pipe_name(path),
            system: mode == RuntimeMode::System,
        })
    }

    pub async fn send_shutdown(path: &Path, mode: RuntimeMode) -> Result<()> {
        let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT)
            .await
            .map_err(|_| tun_ctl::not_running(mode))?;
        write_request(&mut stream, &CtlRequest::Shutdown).await?;
        let resp = timeout(ready_timeout(), tun_ctl::read_response(&mut stream))
            .await
            .map_err(|_| {
                exit::coded(
                    exit::TIMEOUT,
                    anyhow::anyhow!(tr!("TUN daemon Shutdown timed out")),
                )
            })??;
        match resp {
            CtlResponse::Ok => Ok(()),
            CtlResponse::Err { code, message } => Err(exit::coded(code, anyhow::anyhow!(message))),
            other => bail!(tr_fmt!(
                "unexpected Shutdown response: {0}",
                format!("{other:?}")
            )),
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod ctl_sock {
    use super::*;

    pub async fn handshake_status(_path: &Path) -> Result<CtlResponse> {
        bail!(tr!("TUN daemon control socket is Unix-only in this build"))
    }

    pub async fn handshake_peers(_path: &Path) -> Result<CtlResponse> {
        bail!(tr!("TUN daemon control socket is Unix-only in this build"))
    }

    pub async fn prepare_bind(_path: &Path) -> Result<Option<CtlResponse>> {
        bail!(tr!("TUN daemon control socket is Unix-only in this build"))
    }

    pub async fn send_shutdown(_path: &Path, mode: RuntimeMode) -> Result<()> {
        Err(tun_ctl::not_running(mode))
    }
}

/// Probe whether a daemon is running. Socket handshake is authoritative.
///
/// Protocol / version mismatches are **returned as `Err`** (not folded into
/// [`Liveness::NotRunning`]) so the CLI can print the human-readable upgrade
/// message from `tun_ctl`.
pub async fn probe(mode: RuntimeMode) -> Result<Liveness> {
    let sock = tun_ctl::socket_path(mode);
    let pid_rec = tun_ctl::pid_path(mode).and_then(|p| PidRecord::read(&p).ok());

    match ctl_sock::handshake_status(&sock).await {
        Ok(status) => {
            let session = match &status {
                CtlResponse::Status { session, .. } => session.clone(),
                other => {
                    bail!(tr_fmt!(
                        "unexpected Status response from TUN daemon: {0}",
                        format!("{other:?}")
                    ));
                }
            };
            if let Some(rec) = &pid_rec {
                if !session.is_empty() && rec.session != session {
                    tracing::warn!(
                        pid_session = %rec.session,
                        sock_session = %session,
                        "TUN pid file session does not match control Status; trusting socket"
                    );
                }
            }
            Ok(Liveness::Running {
                status,
                pid: pid_rec,
            })
        }
        Err(e) => {
            if is_protocol_error(&e) {
                return Err(e);
            }
            if let Some(rec) = &pid_rec {
                if !process_exists(rec.pid) {
                    if let Some(pid_path) = tun_ctl::pid_path(mode) {
                        let _ = fs::remove_file(pid_path);
                    }
                }
            }
            // Unix: unlink a stale socket file. Windows named pipes are not
            // filesystem paths — never remove_file the pipe name.
            #[cfg(unix)]
            if sock.exists() {
                let _ = fs::remove_file(&sock);
            }
            Ok(Liveness::NotRunning)
        }
    }
}

/// A live daemon answered but speaks an incompatible control protocol
/// version. Marker-based, so the check is **locale-independent**: the message
/// is `tr_fmt!`-translated and must not be substring-matched (English tokens
/// like "protocol" / "upgrade" vanish under other locales).
fn is_protocol_error(err: &anyhow::Error) -> bool {
    tun_ctl::ProtocolMismatch::from_error(err).is_some()
}

fn ensure_runtime_dir(mode: RuntimeMode) -> Result<PathBuf> {
    let dir = tun_ctl::runtime_dir(mode);
    match mode {
        RuntimeMode::AdHoc => {
            fs::create_dir_all(&dir)
                .with_context(|| tr_fmt!("creating config dir {0}", dir.display().to_string()))?;
            // The ad-hoc dir holds the private key + control socket; make it
            // owner-only so nothing in it is ever world-readable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            }
        }
        RuntimeMode::System => {
            // Unix: /run or /var/run. Windows: %ProgramData%\link-p2p (lock file).
            fs::create_dir_all(&dir).with_context(|| {
                tr_fmt!(
                    "creating system runtime dir {0} (needs root or RuntimeDirectory=)",
                    dir.display().to_string()
                )
            })?;
        }
    }
    Ok(dir)
}

fn try_acquire_lock(mode: RuntimeMode) -> Result<LockFile> {
    ensure_runtime_dir(mode)?;
    let path = tun_ctl::lock_path(mode);
    let mut lock = LockFile::open(&path)
        .with_context(|| tr_fmt!("opening TUN lock {0}", path.display().to_string()))?;
    if !lock
        .try_lock()
        .with_context(|| tr_fmt!("locking TUN lock {0}", path.display().to_string()))?
    {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "TUN daemon lock is held (another tun up is running or the daemon is up); try tun status / tun down"
            )),
        ));
    }
    Ok(lock)
}

/// Spawn a detached **live** daemon (creates TUN — needs privilege).
///
/// Same ready/lock contract as [`spawn_skeleton`], but does **not** set
/// `LINK_P2P_TUN_SKELETON`. Used by `tun up` and by `#[ignore]` tests.
pub async fn spawn_live(opts: &SpawnOpts) -> Result<PidRecord> {
    #[cfg(not(unix))]
    {
        let _ = opts;
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "TUN background daemon (`tun up` without `--foreground`) is not yet supported on this platform; use `tun up --foreground` or `tun serve` / `tun connect`"
            )),
        ));
    }
    #[cfg(unix)]
    {
        spawn_daemon_unix(opts, /*skeleton=*/ false).await
    }
}

/// Spawn a detached skeleton daemon (no TUN). Parent returns after ready OK.
///
/// On Unix the child binds `tun.sock`. Windows builds currently reject this path
/// until named-pipe control lands.
pub async fn spawn_skeleton(role: &str) -> Result<PidRecord> {
    let opts = SpawnOpts {
        role: role.to_string(),
        ..Default::default()
    };
    #[cfg(not(unix))]
    {
        let _ = opts;
        bail!(tr!("TUN daemon spawn is Unix-only in this build"));
    }
    #[cfg(unix)]
    {
        spawn_daemon_unix(&opts, /*skeleton=*/ true).await
    }
}

#[cfg(unix)]
async fn spawn_daemon_unix(opts: &SpawnOpts, skeleton: bool) -> Result<PidRecord> {
    let mode = RuntimeMode::AdHoc;
    match probe(mode).await? {
        Liveness::Running { status, pid } => {
            let (role, session) = match &status {
                CtlResponse::Status { role, session, .. } => (role.as_str(), session.as_str()),
                _ => ("?", "?"),
            };
            let session = pid
                .as_ref()
                .map(|p| p.session.as_str())
                .unwrap_or(session);
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr_fmt!(
                    "tun daemon already running (role={0}, pid file session {1})",
                    role,
                    session
                )),
            ));
        }
        Liveness::NotRunning => {}
    }

    let session = random_session();
    let ready = match std::env::var(ENV_TEST_READY_ADDR) {
        Ok(addr) => TcpListener::bind(&addr).await,
        Err(_) => TcpListener::bind("127.0.0.1:0").await,
    }
    .context(tr!("binding TUN ready listener"))?;
    let ready_addr = ready.local_addr().context(tr!("ready listener local_addr"))?;

    ensure_runtime_dir(mode)?;
    let log_path = tun_ctl::log_path(mode).context(tr!("TUN log path missing in ad-hoc mode"))?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| tr_fmt!("opening TUN log {0}", log_path.display().to_string()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
    }

    let exe = std::env::current_exe().context(tr!("resolving current executable"))?;
    // Ready nonce: only the child knows it, so a stray connection to the
    // ephemeral ready port can never impersonate the worker's handshake.
    let nonce = random_session();
    let mut cmd = Command::new(&exe);
    cmd.env(ENV_WORKER, "1")
        .env(ENV_READY, ready_addr.to_string())
        .env(ENV_ROLE, &opts.role)
        .env(ENV_SESSION, &session)
        .env(ENV_READY_NONCE, &nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().context(tr!("cloning TUN log handle"))?))
        .stderr(Stdio::from(log));
    if skeleton {
        cmd.env(ENV_SKELETON, "1");
    }
    if let Some(to) = &opts.to {
        cmd.env("LINK_P2P_TUN_TO", to);
    }
    if let Some(mtu) = opts.mtu {
        cmd.env("LINK_P2P_TUN_MTU", mtu.to_string());
    }
    if let Some(ip) = opts.tun_ip {
        cmd.env("LINK_P2P_TUN_IP", ip.to_string());
    }
    if !opts.allow.is_empty() {
        cmd.env("LINK_P2P_ALLOW", opts.allow.join(","));
    }

    let mut child = cmd.spawn().context(tr!("spawning TUN daemon worker"))?;

    let wait = ready_timeout();
    let nonce_prefix = format!("{nonce} ");
    let ready_result = timeout(wait, async {
        // Keep accepting until a line carrying our nonce arrives (or timeout).
        // A missing/wrong nonce means the connection is not our worker —
        // ignore it and keep waiting rather than treating it as ready.
        loop {
            let Ok((mut stream, _)) = ready.accept().await else {
                continue;
            };
            let mut reader = AsyncBufReader::new(&mut stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                continue;
            }
            if let Some(rest) = line.strip_prefix(&nonce_prefix) {
                return Ok::<_, anyhow::Error>(rest.to_string());
            }
        }
    })
    .await;

    let ready_line = match ready_result {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_residuals_if_dead(mode).await;
            return Err(e).context(tr!("reading TUN daemon ready signal"));
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_residuals_if_dead(mode).await;
            // Drop ready listener explicitly so the ephemeral port is released.
            drop(ready);
            bail!(exit::coded(
                exit::TIMEOUT,
                anyhow::anyhow!(tr_fmt!(
                    "timed out waiting for tun daemon to become ready; check {0}",
                    log_path.display().to_string()
                )),
            ));
        }
    };
    drop(ready);

    let line = ready_line.trim();
    if let Some(err) = line.strip_prefix("ERROR:") {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_residuals_if_dead(mode).await;
        bail!(exit::coded(
            exit::CONNECT,
            anyhow::anyhow!(tr_fmt!("TUN daemon failed to start: {0}", err.trim())),
        ));
    }
    if line != "OK" {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_residuals_if_dead(mode).await;
        bail!(tr_fmt!(
            "TUN daemon ready signal malformed: {0}",
            line.to_string()
        ));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        match probe(mode).await? {
            Liveness::Running { status, .. } => break status,
            Liveness::NotRunning if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Liveness::NotRunning => bail!(tr!(
                "TUN daemon reported ready but control socket is not answering; check tun.log"
            )),
        }
    };
    let CtlResponse::Status {
        session: sock_session,
        ..
    } = status
    else {
        bail!(tr!("TUN daemon Status response missing"));
    };
    if sock_session != session {
        bail!(tr!("TUN daemon session mismatch after ready"));
    }

    let rec = PidRecord {
        pid: child.id(),
        session,
        started_unix_ms: now_unix_ms(),
    };
    let _ = child;
    Ok(rec)
}

/// If probe says nothing is answering, ensure pid/socket leftovers are gone.
async fn cleanup_residuals_if_dead(mode: RuntimeMode) {
    match probe(mode).await {
        Ok(Liveness::NotRunning | Liveness::Running { .. }) => {}
        Err(_) => {
            #[cfg(unix)]
            {
                let _ = fs::remove_file(tun_ctl::socket_path(mode));
            }
            if let Some(p) = tun_ctl::pid_path(mode) {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// Background `tun up` (not `--foreground`). Ad-hoc mode only.
pub async fn cmd_up_background(
    mode: RuntimeMode,
    role: &str,
    to: Option<&str>,
    mtu: u16,
    tun_ip: Option<Ipv4Addr>,
    allow: &[String],
    styler: &Styler,
) -> Result<()> {
    if mode == RuntimeMode::System {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "`tun up --system` requires `--foreground` (supervisor-managed services must not self-daemonize)"
            )),
        ));
    }
    #[cfg(not(unix))]
    {
        let _ = (role, to, mtu, tun_ip, allow, styler);
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "TUN background daemon (`tun up` without `--foreground`) is not yet supported on this platform; use `tun up --foreground` or `tun serve` / `tun connect`"
            )),
        ));
    }
    #[cfg(unix)]
    {
        let opts = SpawnOpts {
            role: role.to_string(),
            to: to.map(|s| s.to_string()),
            mtu: Some(mtu),
            tun_ip,
            allow: allow.to_vec(),
        };
        let rec = spawn_live(&opts).await?;

        println!(
            "{}",
            styler.ok(&tr_fmt!(
                "tun daemon started in background (pid {0})",
                rec.pid
            ))
        );
        println!("  {}", tr!("use `link-p2p tun status` to check state"));
        println!("  {}", tr!("use `link-p2p tun down` to stop it"));
        if let Liveness::Running { status, .. } = probe(RuntimeMode::AdHoc).await? {
            print_status_text(&status);
        }
        Ok(())
    }
}

/// Ask a running daemon to shut down via the control protocol.
#[cfg_attr(not(windows), allow(dead_code))]
pub async fn send_ctl_shutdown(mode: RuntimeMode) -> Result<()> {
    let sock = tun_ctl::socket_path(mode);
    ctl_sock::send_shutdown(&sock, mode).await
}

/// Supervisor-managed foreground daemon (`tun up --foreground --system`).
pub async fn run_supervised_foreground(
    opts: SupervisedUpOpts,
    ui: crate::Ui,
    styler: Styler,
) -> Result<()> {
    let session = random_session();
    let role = opts.role.clone();
    run_worker_inner(
        RuntimeMode::System,
        &role,
        &session,
        /*skeleton=*/ false,
        /*detach=*/ false,
        DataPlaneSource::Explicit(opts, ui, styler),
    )
    .await
}

/// Idempotent `tun down`.
pub async fn cmd_down(mode: RuntimeMode, styler: &Styler) -> Result<()> {
    match probe(mode).await? {
        Liveness::NotRunning => {
            println!("{}", tr!("tun daemon is not running"));
            Ok(())
        }
        Liveness::Running { .. } => {
            let sock = tun_ctl::socket_path(mode);
            match ctl_sock::send_shutdown(&sock, mode).await {
                Ok(()) => {}
                Err(e) if exit::code_from(&e) == exit::DAEMON_NOT_RUNNING => {
                    println!("{}", tr!("tun daemon is not running"));
                    return Ok(());
                }
                Err(e) => return Err(e),
            }

            let deadline = Instant::now() + ready_timeout();
            while Instant::now() < deadline {
                if matches!(probe(mode).await?, Liveness::NotRunning) {
                    if let Some(p) = tun_ctl::pid_path(mode) {
                        let _ = fs::remove_file(p);
                    }
                    println!("{}", styler.ok(&tr!("tun daemon stopped")));
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            eprintln!(
                "{}",
                styler.warn(&tr!(
                    "daemon may still be shutting down; check service logs"
                ))
            );
            Ok(())
        }
    }
}

/// `tun status`.
pub async fn cmd_status(mode: RuntimeMode, format: CliFormat) -> Result<()> {
    match probe(mode).await? {
        Liveness::NotRunning => Err(tun_ctl::not_running(mode)),
        Liveness::Running { status, .. } => {
            match format {
                CliFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                }
                CliFormat::Text => print_status_text(&status),
            }
            Ok(())
        }
    }
}

/// `tun peers`.
pub async fn cmd_peers(mode: RuntimeMode, format: CliFormat) -> Result<()> {
    match probe(mode).await? {
        Liveness::NotRunning => return Err(tun_ctl::not_running(mode)),
        Liveness::Running { .. } => {}
    }

    let resp = ctl_sock::handshake_peers(&tun_ctl::socket_path(mode))
        .await
        .map_err(|e| {
            if is_protocol_error(&e) || exit::code_from(&e) == exit::USAGE {
                e
            } else {
                tun_ctl::not_running(mode)
            }
        })?;

    match resp {
        CtlResponse::Peers { mut peers } => match format {
            CliFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&CtlResponse::Peers { peers })?);
            }
            CliFormat::Text => {
                peers.sort_by_key(|p| p.vip.octets());
                if peers.is_empty() {
                    println!("{}", tr!("(no peers)"));
                } else {
                    println!("{:<15} SHORT", "VIP");
                    for p in peers {
                        println!("{:<15} {}", p.vip, peer_short_code(&p));
                    }
                }
            }
        },
        other => bail!(tr_fmt!(
            "unexpected Peers response from TUN daemon: {0}",
            format!("{other:?}")
        )),
    }
    Ok(())
}

fn peer_short_code(p: &CtlPeer) -> String {
    match p.id.parse::<EndpointId>() {
        Ok(id) => contacts::encode_short_code(id),
        Err(_) => {
            if p.id.len() > 8 {
                p.id[..8].to_string()
            } else {
                p.id.clone()
            }
        }
    }
}

fn print_status_text(status: &CtlResponse) {
    if let CtlResponse::Status {
        role,
        uptime_secs,
        vip,
        path_kind,
        ..
    } = status
    {
        println!("role:     {role}");
        println!("vip:      {vip}");
        println!("path:     {path_kind}");
        println!("uptime:   {}", format_uptime(*uptime_secs));
    }
}

/// Ask the daemon to shut down and wait until the control socket is gone.
pub async fn request_shutdown() -> Result<()> {
    request_shutdown_mode(RuntimeMode::AdHoc).await
}

pub async fn request_shutdown_mode(mode: RuntimeMode) -> Result<()> {
    match probe(mode).await? {
        Liveness::NotRunning => return Err(tun_ctl::not_running(mode)),
        Liveness::Running { .. } => {}
    }
    ctl_sock::send_shutdown(&tun_ctl::socket_path(mode), mode).await?;

    let deadline = Instant::now() + ready_timeout();
    while Instant::now() < deadline {
        if matches!(probe(mode).await?, Liveness::NotRunning) {
            if let Some(p) = tun_ctl::pid_path(mode) {
                let _ = fs::remove_file(p);
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    if let Some(pid_path) = tun_ctl::pid_path(mode) {
        if let Ok(rec) = PidRecord::read(&pid_path) {
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(rec.pid as i32), Signal::SIGTERM);
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = kill(Pid::from_raw(rec.pid as i32), Signal::SIGKILL);
            }
            let _ = rec;
        }
    }
    #[cfg(unix)]
    {
        let _ = fs::remove_file(tun_ctl::socket_path(mode));
    }
    if let Some(p) = tun_ctl::pid_path(mode) {
        let _ = fs::remove_file(p);
    }
    tracing::warn!("{}", tr!("TUN daemon Shutdown timed out; forced cleanup"));
    Ok(())
}

/// Connect helper used before the control listener is up (ready channel).
async fn connect_ready(addr: &str) -> Result<TcpStream> {
    let addr: std::net::SocketAddr = addr
        .parse()
        .with_context(|| tr_fmt!("bad TUN ready address {0}", addr.to_string()))?;
    timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!(tr!("connect to ready listener timed out")))?
        .context(tr!("connect to ready listener"))
}

enum DataPlaneSource {
    Env,
    Explicit(SupervisedUpOpts, crate::Ui, Styler),
}

/// Worker entrypoint (`LINK_P2P_TUN_WORKER=1`). Blocks until Shutdown.
pub async fn run_worker() -> Result<()> {
    let role = std::env::var(ENV_ROLE).unwrap_or_else(|_| "hub".into());
    let session = std::env::var(ENV_SESSION).unwrap_or_else(|_| random_session());
    let ready_addr = std::env::var(ENV_READY).ok();
    let skeleton = std::env::var_os(ENV_SKELETON).is_some();

    let result = run_worker_inner(
        RuntimeMode::AdHoc,
        &role,
        &session,
        skeleton,
        !skeleton,
        DataPlaneSource::Env,
    )
    .await;
    if let (Err(e), Some(addr)) = (&result, ready_addr.as_ref()) {
        if let Ok(mut stream) = connect_ready(addr).await {
            let msg = format!("{}\n", ready_line(&format!("ERROR: {e:#}")));
            let _ = stream.write_all(msg.as_bytes()).await;
        }
    }
    result
}

async fn run_worker_inner(
    mode: RuntimeMode,
    role: &str,
    session: &str,
    skeleton: bool,
    detach: bool,
    data_plane: DataPlaneSource,
) -> Result<()> {
    if std::env::var_os(ENV_STUCK_READY).is_some() {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    #[cfg(unix)]
    if detach {
        nix::unistd::setsid().context(tr!("setsid for TUN daemon"))?;
    }

    let mut lock = try_acquire_lock(mode)?;

    #[cfg(unix)]
    let listener = {
        let sock = tun_ctl::socket_path(mode);
        if let Some(CtlResponse::Status { .. }) = ctl_sock::prepare_bind(&sock).await? {
            drop_lock(&mut lock);
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("TUN daemon is already running (try: link-p2p tun status)")),
            ));
        }
        match ctl_sock::bind_listener(&sock, socket_mode(mode)) {
            Ok(l) => l,
            Err(e) => {
                drop_lock(&mut lock);
                return Err(e);
            }
        }
    };

    #[cfg(windows)]
    let listener = {
        let _ = detach;
        let sock = tun_ctl::socket_path(mode);
        if let Some(CtlResponse::Status { .. }) = ctl_sock::prepare_bind(&sock).await? {
            drop_lock(&mut lock);
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("TUN daemon is already running (try: link-p2p tun status)")),
            ));
        }
        match ctl_sock::bind_listener(&sock, mode) {
            Ok(l) => l,
            Err(e) => {
                drop_lock(&mut lock);
                return Err(e);
            }
        }
    };

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (role, session, skeleton, detach, data_plane);
        drop_lock(&mut lock);
        bail!(tr!("TUN daemon worker is Unix-only in this build"));
    }

    #[cfg(any(unix, windows))]
    {
        if let Some(pid_path) = tun_ctl::pid_path(mode) {
            let rec = PidRecord {
                pid: std::process::id(),
                session: session.to_string(),
                started_unix_ms: now_unix_ms(),
            };
            if let Err(e) = rec.write(&pid_path) {
                #[cfg(unix)]
                {
                    let _ = fs::remove_file(tun_ctl::socket_path(mode));
                }
                drop_lock(&mut lock);
                return Err(e);
            }
        }

        let result = if skeleton {
            run_skeleton_control(listener, role, session).await
        } else {
            run_live_control_and_data(listener, role, session, mode, data_plane).await
        };

        cleanup_worker_files(mode);
        drop_lock(&mut lock);
        result
    }
}

/// Skeleton control loop (no TUN). Used by unit/integration lifecycle tests.
#[cfg(unix)]
async fn run_skeleton_control(
    listener: tokio::net::UnixListener,
    role: &str,
    session: &str,
) -> Result<()> {
    // Ready immediately — no privileged init.
    if let Ok(addr) = std::env::var(ENV_READY) {
        let mut stream = connect_ready(&addr).await?;
        stream
            .write_all(format!("{}\n", ready_line("OK")).as_bytes())
            .await
            .context(tr!("sending TUN ready OK"))?;
    }

    let state = crate::tun::TunLiveState::new(role, session);
    // Placeholder VIP so Status is well-formed without a real interface.
    state.set_vip(Ipv4Addr::new(172, 24, 0, 1)).await;

    let (hooks, _ready_rx) = crate::tun::TunHooks::new(Arc::clone(&state));
    let hooks = Arc::new(hooks);
    serve_ctl_until_shutdown(listener, hooks, /*require_privilege_for_shutdown=*/ false).await
}

#[cfg(windows)]
async fn run_skeleton_control(
    listener: ctl_sock::PipeAcceptor,
    role: &str,
    session: &str,
) -> Result<()> {
    if let Ok(addr) = std::env::var(ENV_READY) {
        let mut stream = connect_ready(&addr).await?;
        stream
            .write_all(format!("{}\n", ready_line("OK")).as_bytes())
            .await
            .context(tr!("sending TUN ready OK"))?;
    }

    let state = crate::tun::TunLiveState::new(role, session);
    state.set_vip(Ipv4Addr::new(172, 24, 0, 1)).await;

    let (hooks, _ready_rx) = crate::tun::TunHooks::new(Arc::clone(&state));
    let hooks = Arc::new(hooks);
    serve_ctl_until_shutdown(listener, hooks, /*require_privilege_for_shutdown=*/ false).await
}

/// Real TUN + roster under the same lock/socket/ready contract as the skeleton.
#[cfg(unix)]
async fn run_live_control_and_data(
    listener: tokio::net::UnixListener,
    role: &str,
    session: &str,
    mode: RuntimeMode,
    data_plane: DataPlaneSource,
) -> Result<()> {
    let state = crate::tun::TunLiveState::new(role, session);
    let (hooks, ready_rx) = crate::tun::TunHooks::new(Arc::clone(&state));
    let hooks = Arc::new(hooks);

    let ctl_hooks = Arc::clone(&hooks);
    let require_privilege = mode == RuntimeMode::System;
    let ctl = tokio::spawn(async move {
        serve_ctl_until_shutdown(listener, ctl_hooks, require_privilege).await
    });

    let data_hooks = Arc::clone(&hooks);
    let role_owned = role.to_string();
    let data = tokio::spawn(async move {
        match data_plane {
            DataPlaneSource::Env => run_live_data_plane(&role_owned, data_hooks).await,
            DataPlaneSource::Explicit(opts, ui, styler) => {
                run_live_data_plane_explicit(&role_owned, data_hooks, opts, ui, styler).await
            }
        }
    });

    join_live_control_and_data(hooks, ctl, data, ready_rx, mode).await
}

#[cfg(windows)]
async fn run_live_control_and_data(
    listener: ctl_sock::PipeAcceptor,
    role: &str,
    session: &str,
    mode: RuntimeMode,
    data_plane: DataPlaneSource,
) -> Result<()> {
    let state = crate::tun::TunLiveState::new(role, session);
    let (hooks, ready_rx) = crate::tun::TunHooks::new(Arc::clone(&state));
    let hooks = Arc::new(hooks);

    let ctl_hooks = Arc::clone(&hooks);
    let require_privilege = mode == RuntimeMode::System;
    let ctl = tokio::spawn(async move {
        serve_ctl_until_shutdown(listener, ctl_hooks, require_privilege).await
    });

    let data_hooks = Arc::clone(&hooks);
    let role_owned = role.to_string();
    let data = tokio::spawn(async move {
        match data_plane {
            DataPlaneSource::Env => run_live_data_plane(&role_owned, data_hooks).await,
            DataPlaneSource::Explicit(opts, ui, styler) => {
                run_live_data_plane_explicit(&role_owned, data_hooks, opts, ui, styler).await
            }
        }
    });

    join_live_control_and_data(hooks, ctl, data, ready_rx, mode).await
}

/// Shared ready/shutdown join for live control+data (Unix socket or Windows pipe).
#[cfg(any(unix, windows))]
async fn join_live_control_and_data(
    hooks: Arc<crate::tun::TunHooks>,
    ctl: tokio::task::JoinHandle<Result<()>>,
    data: tokio::task::JoinHandle<Result<()>>,
    ready_rx: tokio::sync::oneshot::Receiver<Result<()>>,
    mode: RuntimeMode,
) -> Result<()> {
    let ready_addr = std::env::var(ENV_READY).ok();
    let log_hint = tun_ctl::log_path(mode)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "service logs".to_string());
    match timeout(READY_TIMEOUT, ready_rx).await {
        Ok(Ok(Ok(()))) => {
            if let Some(addr) = &ready_addr {
                let mut stream = connect_ready(addr).await?;
                stream
                    .write_all(format!("{}\n", ready_line("OK")).as_bytes())
                    .await
                    .context(tr!("sending TUN ready OK"))?;
            }
        }
        Ok(Ok(Err(e))) => {
            if let Some(addr) = &ready_addr {
                if let Ok(mut stream) = connect_ready(addr).await {
                    let msg = format!("{}\n", ready_line(&format!("ERROR: {e:#}")));
                    let _ = stream.write_all(msg.as_bytes()).await;
                }
            }
            hooks.request_shutdown();
            let _ = data.await;
            let _ = ctl.await;
            return Err(e);
        }
        Ok(Err(_)) => {
            let err = anyhow::anyhow!(tr!("TUN data plane dropped ready signal"));
            if let Some(addr) = &ready_addr {
                if let Ok(mut stream) = connect_ready(addr).await {
                    let msg = format!("{}\n", ready_line(&format!("ERROR: {err:#}")));
                    let _ = stream.write_all(msg.as_bytes()).await;
                }
            }
            hooks.request_shutdown();
            let _ = data.await;
            let _ = ctl.await;
            return Err(err);
        }
        Err(_) => {
            let err = exit::coded(
                exit::TIMEOUT,
                anyhow::anyhow!(tr_fmt!(
                    "TUN daemon did not signal ready within {0}s; check {1}",
                    READY_TIMEOUT.as_secs(),
                    log_hint
                )),
            );
            if let Some(addr) = &ready_addr {
                if let Ok(mut stream) = connect_ready(addr).await {
                    let msg = format!("{}\n", ready_line(&format!("ERROR: {err:#}")));
                    let _ = stream.write_all(msg.as_bytes()).await;
                }
            }
            hooks.request_shutdown();
            let _ = data.await;
            let _ = ctl.await;
            return Err(err);
        }
    }

    // Shutdown order: ctl receives Shutdown → hooks.cancel → data plane exits
    // (LEFT via connection drop / endpoint.close) → ctl task ends → we return.
    let data_res = data.await.context(tr!("TUN data plane task join"))?;
    hooks.request_shutdown();
    let _ = ctl.await;
    data_res
}

#[cfg(unix)]
async fn serve_ctl_until_shutdown(
    listener: tokio::net::UnixListener,
    hooks: Arc<crate::tun::TunHooks>,
    require_privilege_for_shutdown: bool,
) -> Result<()> {
    // Each accepted connection runs in its own task, so one client that
    // stalls mid-request can never block Status/Peers/Shutdown for everyone
    // else. Shutdown is a watch signal; the accept loop stops taking new
    // connections, then drains in-flight tasks within a bounded window.
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let hooks = Arc::clone(&hooks);
                let shutdown_tx = shutdown_tx.clone();
                tasks.spawn(handle_one_connection(
                    stream,
                    hooks,
                    shutdown_tx,
                    require_privilege_for_shutdown,
                ));
            }
        }
    }

    // Drain: give in-flight requests a bounded window to finish their
    // response, then stop regardless.
    let drain = tokio::time::sleep(CTL_DRAIN_TIMEOUT);
    tokio::pin!(drain);
    loop {
        tokio::select! {
            _ = &mut drain => break,
            res = tasks.join_next() => {
                if res.is_none() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Serve one control request. Timeout-bound both directions: a client that
/// never sends a frame, or never reads our response, dies on its own without
/// affecting any other connection.
#[cfg(unix)]
async fn handle_one_connection(
    mut stream: tokio::net::UnixStream,
    hooks: Arc<crate::tun::TunHooks>,
    shutdown_tx: watch::Sender<bool>,
    require_privilege: bool,
) {
    let req = match timeout(CTL_READ_TIMEOUT, tun_ctl::read_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        _ => return, // read timeout or bad frame: drop this connection only
    };

    let resp = match req {
        CtlRequest::Status => hooks.state.status_response().await,
        CtlRequest::Peers => hooks.state.peers_response().await,
        CtlRequest::Shutdown => {
            if require_privilege && !peer_is_privileged(&stream) {
                CtlResponse::Err {
                    code: exit::DENIED,
                    message: tr!(
                        "permission denied: only root or the service account may stop the TUN daemon"
                    ),
                }
            } else {
                // Signal the accept loop to stop taking new connections; the
                // data-plane teardown happens in the drain/join phase. The
                // client still gets its Ok immediately.
                let _ = shutdown_tx.send(true);
                hooks.request_shutdown();
                CtlResponse::Ok
            }
        }
    };
    let _ = timeout(CTL_READ_TIMEOUT, write_response(&mut stream, &resp)).await;
}

/// Whether the peer behind `stream` may stop the daemon. Only consulted in
/// system mode (socket is world-connectable there); fails closed — an error
/// reading peer credentials is treated as unprivileged.
#[cfg(unix)]
fn peer_is_privileged(stream: &tokio::net::UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) => cred.uid() == 0 || cred.uid() == nix::unistd::geteuid().as_raw(),
        Err(_) => false,
    }
}

#[cfg(windows)]
async fn serve_ctl_until_shutdown(
    acceptor: ctl_sock::PipeAcceptor,
    hooks: Arc<crate::tun::TunHooks>,
    require_privilege_for_shutdown: bool,
) -> Result<()> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            accepted = acceptor.accept() => {
                let Ok(stream) = accepted else { continue };
                let hooks = Arc::clone(&hooks);
                let shutdown_tx = shutdown_tx.clone();
                tasks.spawn(handle_one_connection(
                    stream,
                    hooks,
                    shutdown_tx,
                    require_privilege_for_shutdown,
                ));
            }
        }
    }

    let drain = tokio::time::sleep(CTL_DRAIN_TIMEOUT);
    tokio::pin!(drain);
    loop {
        tokio::select! {
            _ = &mut drain => break,
            res = tasks.join_next() => {
                if res.is_none() {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn handle_one_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    hooks: Arc<crate::tun::TunHooks>,
    shutdown_tx: watch::Sender<bool>,
    require_privilege: bool,
) {
    let req = match timeout(CTL_READ_TIMEOUT, tun_ctl::read_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        _ => return,
    };

    let resp = match req {
        CtlRequest::Status => hooks.state.status_response().await,
        CtlRequest::Peers => hooks.state.peers_response().await,
        CtlRequest::Shutdown => {
            if require_privilege && !crate::win_pipe::peer_is_admin(&stream) {
                CtlResponse::Err {
                    code: exit::DENIED,
                    message: tr!(
                        "permission denied: only an elevated administrator may stop the TUN daemon"
                    ),
                }
            } else {
                let _ = shutdown_tx.send(true);
                hooks.request_shutdown();
                CtlResponse::Ok
            }
        }
    };
    let _ = timeout(CTL_READ_TIMEOUT, write_response(&mut stream, &resp)).await;
}

#[cfg(any(unix, windows))]
async fn run_live_data_plane(role: &str, hooks: Arc<crate::tun::TunHooks>) -> Result<()> {
    // Quiet logging into tun.log (stdio already redirected by parent spawn).
    let ui = crate::Ui {
        quiet: true,
        stderr_only: true,
    };
    let styler = crate::style::apply_color_mode(crate::style::ColorMode::Never);

    let passphrase = std::env::var("LINK_P2P_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty());
    let identity = crate::resolve_identity_path(None)?;
    let secret_key = crate::load_or_create_secret_key(&identity, passphrase.as_deref())
        .context(tr!("loading/creating persistent identity"))?;

    let user_cfg = crate::config::load_or_default(&crate::config::config_path());
    let mut relays = crate::config::merge_relay_urls(&[], &user_cfg);
    relays = crate::relay_probe::order_by_connect_latency(&relays).await;
    let no_n0 = user_cfg.relays.no_n0;
    let relay_only = user_cfg.relays.relay_only
        || std::env::var_os("LINK_P2P_RELAY_ONLY").is_some();

    let mtu: u16 = std::env::var("LINK_P2P_TUN_MTU")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1280);
    let tun_ip: Option<Ipv4Addr> = std::env::var("LINK_P2P_TUN_IP")
        .ok()
        .and_then(|s| s.parse().ok());
    let allow = parse_allow_env()?;

    let tune = crate::TransportTune::default();
    let keepalive = Duration::from_secs(5);
    let idle_timeout = Duration::from_secs(30);

    match role {
        "hub" | "serve" => {
            crate::tun::run_tun_serve(
                secret_key,
                tun_ip,
                mtu,
                &relays,
                relay_only,
                no_n0,
                keepalive,
                idle_timeout,
                tune,
                allow,
                ui,
                styler,
                Some(hooks),
            )
            .await
        }
        "spoke" | "connect" => {
            let to = std::env::var("LINK_P2P_TUN_TO")
                .or_else(|_| std::env::var("LINK_P2P_TO"))
                .context(tr!(
                    "spoke daemon requires LINK_P2P_TUN_TO (hub EndpointId)"
                ))?;
            crate::tun::run_tun_connect(
                secret_key,
                &to,
                tun_ip,
                mtu,
                &relays,
                relay_only,
                no_n0,
                Vec::new(),
                keepalive,
                idle_timeout,
                tune,
                allow,
                ui,
                styler,
                Some(hooks),
            )
            .await
        }
        other => {
            let err = anyhow::anyhow!(tr_fmt!("unknown TUN daemon role {0}", other));
            hooks.signal_ready(Err(anyhow::anyhow!("{err:#}")));
            Err(err)
        }
    }
}

#[cfg(any(unix, windows))]
async fn run_live_data_plane_explicit(
    role: &str,
    hooks: Arc<crate::tun::TunHooks>,
    opts: SupervisedUpOpts,
    ui: crate::Ui,
    styler: Styler,
) -> Result<()> {
    match role {
        "hub" | "serve" => {
            crate::tun::run_tun_serve(
                opts.secret_key,
                opts.tun_ip,
                opts.mtu,
                &opts.relays,
                opts.relay_only,
                opts.no_n0_relays,
                opts.keepalive,
                opts.idle_timeout,
                opts.tune,
                opts.allow,
                ui,
                styler,
                Some(hooks),
            )
            .await
        }
        "spoke" | "connect" => {
            let to = opts
                .to
                .context(tr!("spoke daemon requires --to <hub EndpointId>"))?;
            crate::tun::run_tun_connect(
                opts.secret_key,
                &to,
                opts.tun_ip,
                opts.mtu,
                &opts.relays,
                opts.relay_only,
                opts.no_n0_relays,
                opts.to_addr,
                opts.keepalive,
                opts.idle_timeout,
                opts.tune,
                opts.allow,
                ui,
                styler,
                Some(hooks),
            )
            .await
        }
        other => {
            let err = anyhow::anyhow!(tr_fmt!("unknown TUN daemon role {0}", other));
            hooks.signal_ready(Err(anyhow::anyhow!("{err:#}")));
            Err(err)
        }
    }
}

fn parse_allow_env() -> Result<Option<std::collections::HashSet<iroh::EndpointId>>> {
    let raw = match std::env::var("LINK_P2P_ALLOW") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(None),
    };
    let mut set = std::collections::HashSet::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let id: iroh::EndpointId = part
            .parse()
            .map_err(|e| anyhow::Error::new(e).context(tr_fmt!("bad LINK_P2P_ALLOW id {0}", part)))?;
        set.insert(id);
    }
    Ok(Some(set))
}

fn cleanup_worker_files(mode: RuntimeMode) {
    // Named pipes are not filesystem files — only unlink Unix sockets.
    #[cfg(unix)]
    {
        let _ = fs::remove_file(tun_ctl::socket_path(mode));
    }
    if let Some(p) = tun_ctl::pid_path(mode) {
        let _ = fs::remove_file(p);
    }
}

fn drop_lock(lock: &mut LockFile) {
    let _ = lock.unlock();
}

/// In-process skeleton for unit tests (same lock/socket rules, no spawn).
#[cfg(test)]
pub async fn run_skeleton_in_process(role: &str, session: &str) -> Result<()> {
    std::env::set_var(ENV_SKELETON, "1");
    run_worker_inner(
        RuntimeMode::AdHoc,
        role,
        session,
        true,
        false,
        DataPlaneSource::Env,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tun_ctl::RuntimeMode;

    const MODE: RuntimeMode = RuntimeMode::AdHoc;
    use std::sync::Mutex;

    /// Serialize tests that touch process-global `config_dir` / env.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Pin the process catalog to the English fallback so message-text
    /// assertions are deterministic even if the zh_CN help test runs
    /// concurrently (it would otherwise make `tr!` return Chinese while the
    /// message is baked). Must be taken **before** the call that bakes the
    /// message and held until the assertion — the returned ENV_LOCK guard
    /// serializes against the zh test. `current_thread` runtime is required
    /// for tokio tests so the guard can be held across awaits.
    fn pin_english_catalog() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::i18n::ENV_LOCK.lock().unwrap();
        std::env::remove_var("LANGUAGE");
        std::env::set_var("LANG", "C");
        std::env::set_var("LC_ALL", "C");
        crate::i18n::reset_catalog();
        crate::i18n::init();
        guard
    }

    struct TempConfig {
        _dir: tempfile_dir::TempDir,
        prev_xdg: Option<std::ffi::OsString>,
    }

    mod tempfile_dir {
        use std::path::{Path, PathBuf};
        pub struct TempDir(PathBuf);
        impl TempDir {
            pub fn new() -> Self {
                let mut p = std::env::temp_dir();
                p.push(format!("link-p2p-tun-test-{}", super::random_session()));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    impl TempConfig {
        fn install() -> Self {
            let dir = tempfile_dir::TempDir::new();
            let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            Self {
                _dir: dir,
                prev_xdg,
            }
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            match &self.prev_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn system_up_background_is_rejected() {
        let styler = crate::style::apply_color_mode(crate::style::ColorMode::Never);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(cmd_up_background(
                RuntimeMode::System,
                "hub",
                None,
                1280,
                None,
                &[],
                &styler,
            ))
            .unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
    }

    #[test]
    fn pid_record_roundtrip() {
        let r = PidRecord {
            pid: 4242,
            session: "deadbeef".into(),
            started_unix_ms: 123,
        };
        let parsed = PidRecord::parse(&r.encode()).unwrap();
        assert_eq!(parsed, r);
    }

    #[tokio::test]
    async fn probe_not_running_on_empty_dir() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        match probe(MODE).await.unwrap() {
            Liveness::NotRunning => {}
            Liveness::Running { .. } => panic!("expected NotRunning"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn in_process_status_and_shutdown() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let session = random_session();
        let session2 = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session2).await.unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Liveness::Running { status, .. } = probe(MODE).await.unwrap() {
                match status {
                    CtlResponse::Status {
                        role,
                        session: s,
                        ..
                    } => {
                        assert_eq!(role, "hub");
                        assert_eq!(s, session);
                        break;
                    }
                    other => panic!("bad status {other:?}"),
                }
            }
            assert!(Instant::now() <= deadline, "daemon did not become Running");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        request_shutdown().await.unwrap();
        handle.await.unwrap();
        assert!(matches!(probe(MODE).await.unwrap(), Liveness::NotRunning));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lock_prevents_second_in_process_daemon() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let session = random_session();
        let session_a = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session_a).await.unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }) {
            assert!(Instant::now() <= deadline, "first daemon not up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let err = run_skeleton_in_process("spoke", &random_session())
            .await
            .unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);

        request_shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_socket_file_is_unlinked_on_probe() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        ensure_runtime_dir(MODE).unwrap();
        let sock = tun_ctl::socket_path(MODE);
        fs::write(&sock, b"").unwrap();
        assert!(sock.exists());
        assert!(matches!(probe(MODE).await.unwrap(), Liveness::NotRunning));
        assert!(!sock.exists(), "stale socket should be removed");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN / root to create a real TUN; run: cargo test -- --ignored live_hub_daemon"]
    async fn live_hub_daemon_status_has_real_vip() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();

        let up = spawn_live(&SpawnOpts {
            role: "hub".into(),
            ..Default::default()
        })
        .await;
        assert!(
            up.is_ok(),
            "live hub spawn failed (need root?): {:?}",
            up.as_ref().err().map(|e| format!("{e:#}"))
        );

        match probe(MODE).await.unwrap() {
            Liveness::Running {
                status: CtlResponse::Status { vip, path_kind, .. },
                ..
            } => {
                assert_ne!(vip, Ipv4Addr::UNSPECIFIED);
                assert!(!path_kind.is_empty());
            }
            other => panic!("expected Running after live spawn: {other:?}"),
        }

        request_shutdown().await.unwrap();
    }

    #[test]
    fn resolve_up_role_defaults_and_conflicts() {
        assert_eq!(resolve_up_role(None, None).unwrap(), "hub");
        assert_eq!(resolve_up_role(None, Some("abc")).unwrap(), "spoke");
        assert_eq!(resolve_up_role(Some("hub"), None).unwrap(), "hub");
        assert_eq!(resolve_up_role(Some("spoke"), Some("abc")).unwrap(), "spoke");
        assert_eq!(
            exit::code_from(&resolve_up_role(Some("hub"), Some("abc")).unwrap_err()),
            exit::USAGE
        );
        assert_eq!(
            exit::code_from(&resolve_up_role(Some("spoke"), None).unwrap_err()),
            exit::USAGE
        );
        assert_eq!(
            exit::code_from(&resolve_up_role(Some("weird"), None).unwrap_err()),
            exit::USAGE
        );
    }

    #[test]
    fn format_uptime_buckets() {
        assert_eq!(format_uptime(5), "5s");
        assert_eq!(format_uptime(65), "1m5s");
        assert_eq!(format_uptime(3661), "1h1m1s");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_when_not_running_is_daemon_not_running() {
        let _g = TEST_LOCK.lock().unwrap();
        let _lang = pin_english_catalog();
        let _t = TempConfig::install();
        let err = cmd_status(MODE, CliFormat::Text).await.unwrap_err();
        assert_eq!(exit::code_from(&err), exit::DAEMON_NOT_RUNNING);
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(
            msg.contains("not running"),
            "expected friendly message, got {msg}"
        );
        assert!(!msg.contains("connection refused"));
    }

    #[tokio::test]
    async fn down_is_idempotent_when_not_running() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let styler = crate::style::apply_color_mode(crate::style::ColorMode::Never);
        cmd_down(MODE, &styler).await.unwrap();
        cmd_down(MODE, &styler).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn up_fails_when_already_running_without_side_effects() {
        let _g = TEST_LOCK.lock().unwrap();
        let _lang = pin_english_catalog();
        let _t = TempConfig::install();
        let styler = crate::style::apply_color_mode(crate::style::ColorMode::Never);
        let session = random_session();
        let session2 = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session2).await.unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }) {
            assert!(Instant::now() <= deadline, "daemon not up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let err = cmd_up_background(MODE, "hub", None, 1280, None, &[], &styler)
            .await
            .unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
        // Original daemon still answering — we must not have killed it.
        assert!(matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }));
        let msg = format!("{err:#}");
        assert!(msg.contains("already running"), "{msg}");

        request_shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_ready_timeout_kills_stuck_worker() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        std::env::set_var(ENV_READY_TIMEOUT_MS, "400");
        std::env::set_var(ENV_STUCK_READY, "1");
        let err = spawn_skeleton("hub").await.unwrap_err();
        std::env::remove_var(ENV_STUCK_READY);
        std::env::remove_var(ENV_READY_TIMEOUT_MS);
        assert_eq!(exit::code_from(&err), exit::TIMEOUT, "{err:#}");
        assert!(matches!(probe(MODE).await.unwrap(), Liveness::NotRunning));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stuck_client_does_not_block_status() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let session = random_session();
        let session2 = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session2).await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }) {
            assert!(Instant::now() <= deadline, "daemon not up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // A client that connects and then never writes a request must not
        // stall the control loop for everyone else.
        let sock = tun_ctl::socket_path(MODE);
        let stuck = tokio::net::UnixStream::connect(&sock).await.unwrap();
        std::mem::forget(stuck); // keep the fd open, never send anything

        let status = tokio::time::timeout(Duration::from_secs(2), ctl_sock::handshake_status(&sock))
            .await;
        assert!(
            matches!(status, Ok(Ok(_))),
            "a stuck client must not block Status: {status:?}"
        );
        let peers = tokio::time::timeout(Duration::from_secs(2), ctl_sock::handshake_peers(&sock))
            .await;
        assert!(
            matches!(peers, Ok(Ok(_))),
            "a stuck client must not block Peers: {peers:?}"
        );

        request_shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_status_requests_all_succeed() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let session = random_session();
        let session2 = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session2).await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }) {
            assert!(Instant::now() <= deadline, "daemon not up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Lock in that the control loop serves connections concurrently:
        // every request must complete within a bounded deadline even with
        // many in flight (a serialized loop would still pass today, but a
        // future regression back to per-connection blocking must not).
        let sock = tun_ctl::socket_path(MODE);
        let mut pending = Vec::new();
        for _ in 0..16 {
            pending.push(tokio::time::timeout(
                Duration::from_secs(5),
                ctl_sock::handshake_status(&sock),
            ));
        }
        for fut in pending {
            assert!(fut.await.unwrap().is_ok(), "concurrent Status must succeed");
        }

        request_shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ready_handshake_rejects_wrong_nonce() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        // The real worker never sends ready (stuck hook); only a fake
        // nonce-less "OK" reaches the ready port. The parent must keep
        // waiting → TIMEOUT — never treat the fake line as success.
        std::env::set_var(ENV_STUCK_READY, "1");
        std::env::set_var(ENV_READY_TIMEOUT_MS, "1500");
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        std::env::set_var(ENV_TEST_READY_ADDR, addr.to_string());

        let fake = tokio::spawn(async move {
            for _ in 0..200 {
                if let Ok(mut s) = tokio::net::TcpStream::connect(addr).await {
                    let _ = s.write_all(b"OK\n").await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let result = spawn_skeleton("hub").await;
        // Clean up env before any assert so a red run cannot poison later
        // tests (STUCK_READY would hang any subsequent in-process worker).
        std::env::remove_var(ENV_TEST_READY_ADDR);
        std::env::remove_var(ENV_STUCK_READY);
        std::env::remove_var(ENV_READY_TIMEOUT_MS);
        let _ = tokio::time::timeout(Duration::from_secs(3), fake).await;

        let err = match result {
            Ok(rec) => panic!("spawn succeeded when it must time out: {rec:?}"),
            Err(e) => e,
        };
        assert_eq!(exit::code_from(&err), exit::TIMEOUT, "{err:#}");
    }

    #[test]
    fn protocol_mismatch_detection_is_locale_independent() {
        // Message deliberately non-English (what the CLI sees under zh_CN):
        // detection must not rely on msgid substrings like "protocol"/"upgrade".
        let err = exit::coded(
            exit::USAGE,
            tun_ctl::ProtocolMismatch::new(2, 1, "TUN daemon 协议更新；请升级 link-p2p".to_string()),
        );
        assert!(is_protocol_error(&err), "{err:#}");
        // Same wording but not wrapped in the marker → not a protocol error.
        let plain = anyhow::anyhow!("TUN daemon 协议更新；请升级 link-p2p");
        assert!(!is_protocol_error(&plain));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn probe_surfaces_version_mismatch() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixListener;

        let _g = TEST_LOCK.lock().unwrap();
        let _lang = pin_english_catalog();
        let _t = TempConfig::install();
        ensure_runtime_dir(MODE).unwrap();
        let sock = tun_ctl::socket_path(MODE);
        let _ = fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read (and ignore) the client's Status request.
            let _ = tun_ctl::read_request(&mut stream).await;
            let body = serde_json::to_vec(&CtlResponse::Status {
                role: "hub".into(),
                uptime_secs: 1,
                vip: Ipv4Addr::new(172, 24, 0, 1),
                path_kind: "unknown".into(),
                session: "x".into(),
            })
            .unwrap();
            let frame = tun_ctl::encode_frame(tun_ctl::CTL_VERSION + 1, &body).unwrap();
            stream.write_all(&frame).await.unwrap();
        });

        let err = probe(MODE).await.unwrap_err();
        let _ = serve.await;
        assert_eq!(exit::code_from(&err), exit::USAGE);
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(
            msg.contains("protocol") && (msg.contains("newer") || msg.contains("upgrade")),
            "expected version-mismatch wording, got {msg}"
        );
        let _ = fs::remove_file(tun_ctl::socket_path(MODE));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_and_peers_while_running() {
        let _g = TEST_LOCK.lock().unwrap();
        let _t = TempConfig::install();
        let session = random_session();
        let session2 = session.clone();
        let handle = tokio::spawn(async move {
            run_skeleton_in_process("hub", &session2).await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(probe(MODE).await.unwrap(), Liveness::Running { .. }) {
            assert!(Instant::now() <= deadline, "daemon not up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        cmd_status(MODE, CliFormat::Text).await.unwrap();
        cmd_status(MODE, CliFormat::Json).await.unwrap();
        cmd_peers(MODE, CliFormat::Text).await.unwrap();
        cmd_peers(MODE, CliFormat::Json).await.unwrap();

        let styler = crate::style::apply_color_mode(crate::style::ColorMode::Never);
        cmd_down(MODE, &styler).await.unwrap();
        // Idempotent second down.
        cmd_down(MODE, &styler).await.unwrap();
        let _ = handle.await;
    }
}
