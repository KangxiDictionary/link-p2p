//! Stream phone daemon: standing callee + ctl Dial/Accept/Reject.
//!
//! Ad-hoc only (user config dir). Background spawn is Unix; Windows can run
//! `call up --foreground`. Wire protocol: [`crate::stream_ctl`] (`SPC1`).

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use fslock::LockFile;
use iroh::EndpointId;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::contacts;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::phone_ring::{self, RING_TIMEOUT};
use crate::stream_ctl::{
    self, CtlRequest, CtlResponse, PendingCall, StreamPeer, CTL_READ_TIMEOUT, PROBE_CONNECT_TIMEOUT,
    READY_TIMEOUT,
};
use crate::style::{apply_color_mode, ColorMode, Styler};
use crate::{
    bring_endpoint_online, build_dial_addr, build_endpoint, load_or_create_secret_key,
    resolve_identity_path, ConnSlot, TransportTune, Ui, ALPN, PING_ALPN,
};

const ENV_WORKER: &str = "LINK_P2P_CALL_WORKER";
const ENV_READY: &str = "LINK_P2P_CALL_READY";
const ENV_SESSION: &str = "LINK_P2P_CALL_SESSION";
const ENV_READY_NONCE: &str = "LINK_P2P_CALL_READY_NONCE";
const ENV_LISTEN: &str = "LINK_P2P_CALL_LISTEN";
const ENV_FORWARD: &str = "LINK_P2P_CALL_FORWARD";
const ENV_IDENTITY: &str = "LINK_P2P_IDENTITY";

#[derive(Debug, Clone)]
pub struct UpOpts {
    pub listen: Option<SocketAddr>,
    pub forward: Option<SocketAddr>,
    pub foreground: bool,
}

#[derive(Debug, Clone)]
enum CallCmd {
    Dial {
        to: String,
        listen: Option<SocketAddr>,
        forward: Option<SocketAddr>,
        to_addr: Vec<SocketAddr>,
    },
    Accept { peer: String },
    Reject { peer: String },
    Shutdown,
}

struct LiveState {
    started: Instant,
    session: String,
    phase: RwLock<String>,
    listen: Option<SocketAddr>,
    forward: Option<SocketAddr>,
    pending: RwLock<Vec<PendingCall>>,
    peers: RwLock<Vec<StreamPeer>>,
}

impl LiveState {
    fn new(session: String, listen: Option<SocketAddr>, forward: Option<SocketAddr>) -> Self {
        Self {
            started: Instant::now(),
            session,
            phase: RwLock::new("idle".into()),
            listen,
            forward,
            pending: RwLock::new(Vec::new()),
            peers: RwLock::new(Vec::new()),
        }
    }

    async fn status(&self) -> CtlResponse {
        CtlResponse::Status {
            role: "phone".into(),
            uptime_secs: self.started.elapsed().as_secs(),
            session: self.session.clone(),
            phase: self.phase.read().await.clone(),
            listen: self.listen,
            forward: self.forward,
            pending_calls: self.pending.read().await.clone(),
        }
    }
}

#[derive(Debug)]
pub enum Liveness {
    Running { status: CtlResponse },
    NotRunning,
}

#[derive(Debug, Clone)]
pub struct PidRecord {
    pub pid: u32,
    pub session: String,
    pub started_unix_ms: u64,
}

impl PidRecord {
    fn encode(&self) -> String {
        format!(
            "pid={}\nsession={}\nstarted_unix_ms={}\n",
            self.pid, self.session, self.started_unix_ms
        )
    }

    fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.encode())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn random_session() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    Instant::now().hash(&mut h);
    std::process::id().hash(&mut h);
    format!("{:016x}", h.finish())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn ready_timeout() -> Duration {
    std::env::var("LINK_P2P_CALL_READY_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(READY_TIMEOUT)
}

pub fn is_worker_process() -> bool {
    std::env::var_os(ENV_WORKER).is_some()
}

fn try_acquire_lock() -> Result<LockFile> {
    let path = stream_ctl::lock_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut lock = LockFile::open(&path)
        .with_context(|| tr_fmt!("opening call lock {0}", path.display().to_string()))?;
    if !lock
        .try_lock()
        .with_context(|| tr_fmt!("locking {0}", path.display().to_string()))?
    {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!("stream call daemon is already running")),
        ));
    }
    Ok(lock)
}

async fn connect_ctl() -> Result<UnixStream> {
    let path = stream_ctl::socket_path();
    timeout(PROBE_CONNECT_TIMEOUT, UnixStream::connect(&path))
        .await
        .map_err(|_| stream_ctl::not_running())?
        .map_err(|_| stream_ctl::not_running())
}

async fn send_request(req: &CtlRequest) -> Result<CtlResponse> {
    let mut stream = connect_ctl().await?;
    timeout(CTL_READ_TIMEOUT, async {
        stream_ctl::write_request(&mut stream, req).await?;
        stream_ctl::read_response(&mut stream).await
    })
    .await
    .map_err(|_| {
        exit::coded(
            exit::CONNECT,
            anyhow::anyhow!(tr!("stream call control request timed out")),
        )
    })?
}

async fn send_expect_ok(req: &CtlRequest) -> Result<()> {
    match send_request(req).await? {
        CtlResponse::Ok => Ok(()),
        CtlResponse::Err { code, message } => {
            bail!(exit::coded(code, anyhow::anyhow!(message)))
        }
        other => bail!(tr_fmt!(
            "unexpected control response: {0}",
            format!("{other:?}")
        )),
    }
}

pub async fn probe() -> Result<Liveness> {
    match send_request(&CtlRequest::Status).await {
        Ok(status @ CtlResponse::Status { .. }) => Ok(Liveness::Running { status }),
        Ok(other) => bail!(tr_fmt!(
            "unexpected Status response from call daemon: {0}",
            format!("{other:?}")
        )),
        Err(_) => Ok(Liveness::NotRunning),
    }
}

/// Spawn background worker (Unix) or run foreground data plane.
pub async fn cmd_up(
    opts: UpOpts,
    identity: Option<&Path>,
    secret_key: iroh::SecretKey,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    if opts.foreground {
        return run_foreground(
            opts.listen,
            opts.forward,
            secret_key,
            relay,
            no_n0,
            relay_only,
            keepalive,
            idle_timeout,
            tune,
            max_conns,
            ui,
            styler,
        )
        .await;
    }

    #[cfg(unix)]
    {
        let _ = (secret_key, keepalive, idle_timeout, tune, max_conns);
        let Some(identity) = identity else {
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!(
                    "background `call up` needs a persistent identity (omit --ephemeral or use --foreground)"
                )),
            ));
        };
        let rec = spawn_daemon_unix(&opts, identity, relay, no_n0, relay_only).await?;
        ui.line(styler.ok(&tr_fmt!(
            "stream call daemon started (pid {0})",
            rec.pid
        )));
        if let Ok(log) = stream_ctl::log_path().into_os_string().into_string() {
            ui.line(styler.dim(&tr_fmt!("logs: {0}", log)));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (
            identity, secret_key, relay, no_n0, relay_only, keepalive, idle_timeout, tune,
            max_conns,
        );
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "background `call up` is Unix-only; use `call up --foreground` on this platform"
            )),
        ));
    }
}

#[cfg(unix)]
async fn spawn_daemon_unix(
    opts: &UpOpts,
    identity: &Path,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
) -> Result<PidRecord> {
    match probe().await? {
        Liveness::Running { .. } => bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!("stream call daemon is already running")),
        )),
        Liveness::NotRunning => {}
    }

    let session = random_session();
    let ready = TcpListener::bind("127.0.0.1:0")
        .await
        .context(tr!("binding call ready listener"))?;
    let ready_addr = ready.local_addr()?;
    let dir = stream_ctl::runtime_dir();
    fs::create_dir_all(&dir)?;
    let log_path = stream_ctl::log_path();
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| tr_fmt!("opening call log {0}", log_path.display().to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
    }

    let exe = std::env::current_exe().context(tr!("resolving current executable"))?;
    let nonce = random_session();
    let mut cmd = std::process::Command::new(&exe);
    cmd.env(ENV_WORKER, "1")
        .env(ENV_READY, ready_addr.to_string())
        .env(ENV_SESSION, &session)
        .env(ENV_READY_NONCE, &nonce)
        .env(ENV_IDENTITY, identity)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(
            log.try_clone().context(tr!("cloning call log handle"))?,
        ))
        .stderr(std::process::Stdio::from(log));
    if let Some(a) = opts.listen {
        cmd.env(ENV_LISTEN, a.to_string());
    }
    if let Some(a) = opts.forward {
        cmd.env(ENV_FORWARD, a.to_string());
    }
    if !relay.is_empty() {
        cmd.env("LINK_P2P_RELAY", relay.join(","));
    }
    if no_n0 {
        cmd.env("LINK_P2P_NO_N0_RELAYS", "1");
    }
    if relay_only {
        cmd.env("LINK_P2P_RELAY_ONLY", "1");
    }
    // Pass through common env the parent process already has.
    for key in [
        "LINK_P2P_PASSPHRASE",
        "RUST_LOG",
        "LANGUAGE",
        "LANG",
        "LC_ALL",
        "LINK_P2P_LOCALEDIR",
        "XDG_CONFIG_HOME",
    ] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }

    let mut child = cmd.spawn().context(tr!("spawning call daemon worker"))?;
    let wait = ready_timeout();
    let nonce_prefix = format!("{nonce} ");
    let ready_result = timeout(wait, async {
        loop {
            let Ok((mut stream, _)) = ready.accept().await else {
                continue;
            };
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut line = String::new();
            use tokio::io::AsyncBufReadExt;
            if reader.read_line(&mut line).await.is_err() {
                continue;
            }
            if let Some(rest) = line.strip_prefix(&nonce_prefix) {
                return Ok::<_, anyhow::Error>(rest.to_string());
            }
        }
    })
    .await;

    match ready_result {
        Ok(Ok(line)) if line.trim_start().starts_with("OK") => {}
        Ok(Ok(line)) => {
            let _ = child.kill();
            bail!(tr_fmt!("call daemon failed to start: {0}", line.trim()));
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            return Err(e);
        }
        Err(_) => {
            let _ = child.kill();
            bail!(tr!("timed out waiting for call daemon ready"));
        }
    }

    // Probe ctl.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match probe().await? {
            Liveness::Running {
                status: CtlResponse::Status { session: s, .. },
            } if s == session => break,
            Liveness::Running { .. } => {
                bail!(tr!("call daemon started with unexpected session"));
            }
            Liveness::NotRunning if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Liveness::NotRunning => bail!(tr!("call daemon did not become ready")),
        }
    }

    Ok(PidRecord {
        pid: child.id(),
        session,
        started_unix_ms: now_unix_ms(),
    })
}

pub async fn run_worker() -> Result<()> {
    crate::i18n::init();
    let identity = match std::env::var_os(ENV_IDENTITY) {
        Some(p) => std::path::PathBuf::from(p),
        None => resolve_identity_path(None)?,
    };
    let passphrase = std::env::var("LINK_P2P_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty());
    let secret_key = load_or_create_secret_key(&identity, passphrase.as_deref())?;
    let relay: Vec<String> = std::env::var("LINK_P2P_RELAY")
        .ok()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let no_n0 = std::env::var_os("LINK_P2P_NO_N0_RELAYS").is_some();
    let relay_only = std::env::var_os("LINK_P2P_RELAY_ONLY").is_some();
    let keepalive = Duration::from_secs(5);
    let idle_timeout = Duration::from_secs(30);
    let tune = TransportTune::default();
    let max_conns = 1024usize;

    let session = std::env::var(ENV_SESSION).unwrap_or_else(|_| random_session());
    let ready_addr = std::env::var(ENV_READY).ok();
    let nonce = std::env::var(ENV_READY_NONCE).unwrap_or_default();
    let listen = std::env::var(ENV_LISTEN)
        .ok()
        .and_then(|s| s.parse().ok());
    let forward = std::env::var(ENV_FORWARD)
        .ok()
        .and_then(|s| s.parse().ok());

    let result = run_daemon_inner(
        session,
        listen,
        forward,
        true,
        secret_key,
        &relay,
        no_n0,
        relay_only,
        keepalive,
        idle_timeout,
        tune,
        max_conns,
        Ui {
            quiet: true,
            stderr_only: false,
        },
        apply_color_mode(ColorMode::Never),
    )
    .await;

    if let (Err(e), Some(addr)) = (&result, ready_addr.as_ref()) {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            let msg = format!("{nonce} ERROR: {e:#}\n");
            let _ = stream.write_all(msg.as_bytes()).await;
        }
    }
    result
}

async fn run_foreground(
    listen: Option<SocketAddr>,
    forward: Option<SocketAddr>,
    secret_key: iroh::SecretKey,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    match probe().await? {
        Liveness::Running { .. } => bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!("stream call daemon is already running")),
        )),
        Liveness::NotRunning => {}
    }
    let session = random_session();
    run_daemon_inner(
        session,
        listen,
        forward,
        false,
        secret_key,
        relay,
        no_n0,
        relay_only,
        keepalive,
        idle_timeout,
        tune,
        max_conns,
        ui,
        styler,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_daemon_inner(
    session: String,
    listen: Option<SocketAddr>,
    forward: Option<SocketAddr>,
    detach: bool,
    secret_key: iroh::SecretKey,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    #[cfg(unix)]
    if detach {
        rustix::process::setsid().context(tr!("setsid for call daemon"))?;
    }
    #[cfg(not(unix))]
    let _ = detach;

    let mut lock = try_acquire_lock()?;
    let sock = stream_ctl::socket_path();
    if sock.exists() {
        let _ = fs::remove_file(&sock);
    }
    if let Some(parent) = sock.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&sock)
        .with_context(|| tr_fmt!("binding call control socket {0}", sock.display().to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&sock, fs::Permissions::from_mode(0o600));
    }

    let pid_rec = PidRecord {
        pid: std::process::id(),
        session: session.clone(),
        started_unix_ms: now_unix_ms(),
    };
    pid_rec.write(&stream_ctl::pid_path())?;

    let state = Arc::new(LiveState::new(session.clone(), listen, forward));
    let (cmd_tx, cmd_rx) = mpsc::channel::<CallCmd>(32);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<()>>();

    let phone = tokio::spawn(run_phone_plane(
        secret_key,
        relay.to_vec(),
        no_n0,
        relay_only,
        keepalive,
        idle_timeout,
        tune,
        max_conns,
        listen,
        forward,
        state.clone(),
        cmd_rx,
        ready_tx,
        ui,
        styler,
    ));

    // Wait for endpoint bind before signaling parent.
    match ready_rx.await {
        Ok(Ok(())) => {
            if let Ok(addr) = std::env::var(ENV_READY) {
                let nonce = std::env::var(ENV_READY_NONCE).unwrap_or_default();
                if let Ok(mut s) = tokio::net::TcpStream::connect(&addr).await {
                    let _ = s.write_all(format!("{nonce} OK\n").as_bytes()).await;
                }
            }
        }
        Ok(Err(e)) => {
            drop_lock(&mut lock);
            let _ = fs::remove_file(&sock);
            return Err(e);
        }
        Err(_) => {
            drop_lock(&mut lock);
            let _ = fs::remove_file(&sock);
            bail!(tr!("call phone plane exited before ready"));
        }
    }

    info!(%session, "stream call daemon ready");
    let ctl = tokio::spawn(ctl_accept_loop(listener, state.clone(), cmd_tx.clone()));

    let _ = phone.await;
    ctl.abort();
    drop_lock(&mut lock);
    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(stream_ctl::pid_path());
    Ok(())
}

fn drop_lock(lock: &mut LockFile) {
    let _ = lock.unlock();
}

async fn ctl_accept_loop(
    listener: UnixListener,
    state: Arc<LiveState>,
    cmd_tx: mpsc::Sender<CallCmd>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        let cmd_tx = cmd_tx.clone();
        tokio::spawn(async move {
            let _ = handle_one_ctl(&mut stream, &state, &cmd_tx).await;
        });
    }
}

async fn handle_one_ctl(
    stream: &mut UnixStream,
    state: &LiveState,
    cmd_tx: &mpsc::Sender<CallCmd>,
) -> Result<()> {
    let req = timeout(CTL_READ_TIMEOUT, stream_ctl::read_request(stream))
        .await
        .map_err(|_| anyhow::anyhow!(tr!("stream call control request timed out")))??;
    let resp = match req {
        CtlRequest::Status => state.status().await,
        CtlRequest::Peers => CtlResponse::Peers {
            peers: state.peers.read().await.clone(),
        },
        CtlRequest::Shutdown => {
            let _ = cmd_tx.send(CallCmd::Shutdown).await;
            CtlResponse::Ok
        }
        CtlRequest::Call {
            to,
            listen,
            forward,
            to_addr,
        } => {
            match cmd_tx
                .try_send(CallCmd::Dial {
                    to,
                    listen,
                    forward,
                    to_addr,
                }) {
                Ok(()) => CtlResponse::Ok,
                Err(_) => CtlResponse::Err {
                    code: exit::OTHER,
                    message: tr!("call daemon is busy"),
                },
            }
        }
        CtlRequest::Accept { peer } => {
            let _ = cmd_tx.send(CallCmd::Accept { peer }).await;
            CtlResponse::Ok
        }
        CtlRequest::Reject { peer } => {
            let _ = cmd_tx.send(CallCmd::Reject { peer }).await;
            CtlResponse::Ok
        }
    };
    timeout(CTL_READ_TIMEOUT, stream_ctl::write_response(stream, &resp))
        .await
        .map_err(|_| anyhow::anyhow!(tr!("stream call control request timed out")))??;
    Ok(())
}

// --- CLI commands ---

pub async fn cmd_down(ui: Ui, styler: Styler) -> Result<()> {
    match probe().await? {
        Liveness::NotRunning => {
            ui.line(styler.dim(&tr!("stream call daemon is not running")));
            Ok(())
        }
        Liveness::Running { .. } => {
            send_expect_ok(&CtlRequest::Shutdown).await?;
            // Wait briefly for sock to disappear.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if matches!(probe().await?, Liveness::NotRunning) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            ui.line(styler.ok(&tr!("stream call daemon stopped")));
            Ok(())
        }
    }
}

pub async fn cmd_status(ui: Ui, styler: Styler) -> Result<()> {
    match probe().await? {
        Liveness::NotRunning => Err(stream_ctl::not_running()),
        Liveness::Running { status } => {
            if let CtlResponse::Status {
                role,
                uptime_secs,
                session,
                phase,
                listen,
                forward,
                pending_calls,
            } = status
            {
                ui.line(styler.ok(&tr_fmt!("role {0}  phase {1}", role, phase)));
                ui.line(styler.dim(&tr_fmt!(
                    "uptime {0}s  session {1}",
                    uptime_secs,
                    session
                )));
                if let Some(a) = listen {
                    ui.line(styler.dim(&tr_fmt!("listen {0}", a)));
                }
                if let Some(a) = forward {
                    ui.line(styler.dim(&tr_fmt!("forward {0}", a)));
                }
                if !pending_calls.is_empty() {
                    ui.line(styler.info(&tr_fmt!(
                        "{0} ringing call(s) — `link-p2p call ring`",
                        pending_calls.len()
                    )));
                }
            }
            Ok(())
        }
    }
}

pub async fn cmd_ring(ui: Ui, styler: Styler) -> Result<()> {
    match probe().await? {
        Liveness::NotRunning => Err(stream_ctl::not_running()),
        Liveness::Running { status } => {
            let CtlResponse::Status { pending_calls, .. } = status else {
                bail!(tr!("unexpected status response"));
            };
            if pending_calls.is_empty() {
                ui.line(styler.dim(&tr!("no ringing calls")));
            } else {
                for c in pending_calls {
                    println!("{}\t{}", c.peer, c.since_unix_ms);
                }
            }
            Ok(())
        }
    }
}

pub async fn cmd_accept(peer: &str, ui: Ui, styler: Styler) -> Result<()> {
    send_expect_ok(&CtlRequest::Accept {
        peer: peer.to_string(),
    })
    .await?;
    ui.line(styler.ok(&tr_fmt!("accepted call from {0}", peer)));
    Ok(())
}

pub async fn cmd_reject(peer: &str, ui: Ui, styler: Styler) -> Result<()> {
    send_expect_ok(&CtlRequest::Reject {
        peer: peer.to_string(),
    })
    .await?;
    ui.line(styler.ok(&tr_fmt!("rejected call from {0}", peer)));
    Ok(())
}

pub async fn cmd_call(
    to: &str,
    listen: Option<SocketAddr>,
    forward: Option<SocketAddr>,
    to_addr: Vec<SocketAddr>,
    no_wait: bool,
    // Used when auto-spawning daemon.
    identity: Option<&Path>,
    secret_key: iroh::SecretKey,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    match probe().await? {
        Liveness::NotRunning => {
            ui.line(styler.dim(&tr!("starting stream call daemon…")));
            cmd_up(
                UpOpts {
                    listen,
                    forward,
                    foreground: false,
                },
                identity,
                secret_key,
                relay,
                no_n0,
                relay_only,
                keepalive,
                idle_timeout,
                tune,
                max_conns,
                ui,
                styler,
            )
            .await?;
        }
        Liveness::Running { .. } => {}
    }

    ui.line(styler.info(&tr_fmt!("calling {0}… waiting for answer", to)));
    send_expect_ok(&CtlRequest::Call {
        to: to.to_string(),
        listen,
        forward,
        to_addr,
    })
    .await?;

    if no_wait {
        ui.line(styler.dim(&tr!("dial queued on the standing daemon")));
        return Ok(());
    }

    // Poll briefly for peers / phase connected.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Liveness::Running {
            status:
                CtlResponse::Status {
                    phase,
                    pending_calls: _,
                    ..
                },
        } = probe().await?
        {
            if phase == "connected" {
                ui.line(styler.ok(&tr_fmt!("connected to {0}", to)));
                return Ok(());
            }
        }
        // Also check peers list.
        if let Ok(CtlResponse::Peers { peers }) = send_request(&CtlRequest::Peers).await {
            if !peers.is_empty() {
                ui.line(styler.ok(&tr_fmt!("connected to {0}", to)));
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    ui.line(styler.dim(&tr!(
        "waiting for answer — peer must have `call up` (or `call accept` if ringing); check `call status`"
    )));
    Ok(())
}

// --- phone data plane ---

struct Ringing {
    peer: EndpointId,
    conn: iroh::endpoint::Connection,
    since: Instant,
    since_unix_ms: u64,
}

#[allow(clippy::too_many_arguments)]
async fn run_phone_plane(
    secret_key: iroh::SecretKey,
    relay: Vec<String>,
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    default_listen: Option<SocketAddr>,
    default_forward: Option<SocketAddr>,
    state: Arc<LiveState>,
    mut cmd_rx: mpsc::Receiver<CallCmd>,
    ready_tx: oneshot::Sender<Result<()>>,
    ui: Ui,
    styler: Styler,
) {
    let result = run_phone_plane_inner(
        secret_key,
        &relay,
        no_n0,
        relay_only,
        keepalive,
        idle_timeout,
        tune,
        max_conns,
        default_listen,
        default_forward,
        state,
        &mut cmd_rx,
        ready_tx,
        ui,
        styler,
    )
    .await;
    if let Err(e) = result {
        warn!(error = %e, "stream phone plane exited");
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_phone_plane_inner(
    secret_key: iroh::SecretKey,
    relay: &[String],
    no_n0: bool,
    relay_only: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    max_conns: usize,
    default_listen: Option<SocketAddr>,
    default_forward: Option<SocketAddr>,
    state: Arc<LiveState>,
    cmd_rx: &mut mpsc::Receiver<CallCmd>,
    ready_tx: oneshot::Sender<Result<()>>,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    let _own_id = secret_key.public();
    let endpoint = build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0,
    )?
    .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
    .bind()
    .await
    .map_err(|e| anyhow::Error::new(e).context(tr!("binding endpoint")))?;

    if let Err(e) = bring_endpoint_online(&endpoint, relay, no_n0).await {
        let _ = ready_tx.send(Err(anyhow::Error::from(e)));
        return Ok(());
    }
    contacts::print_machine_identity(endpoint.id());
    let _ = ready_tx.send(Ok(()));

    let book = contacts::load(&contacts::contacts_path()).unwrap_or_default();
    let ringing: Arc<RwLock<Vec<Ringing>>> = Arc::new(RwLock::new(Vec::new()));
    let active: Arc<Mutex<Option<(EndpointId, ConnSlot)>>> = Arc::new(Mutex::new(None));
    let semaphore = crate::conn_semaphore(max_conns);
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    // Router for inbound.
    let ep_accept = endpoint.clone();
    let state_a = state.clone();
    let ringing_a = ringing.clone();
    let active_a = active.clone();
    let book_a = book.clone();
    let sem_a = semaphore.clone();
    let styler_a = styler;
    let ui_a = ui;
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = ep_accept.accept().await {
            let Ok(connecting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = connecting.await else {
                continue;
            };
            let peer_id = conn.remote_id();
            if active_a
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some()
            {
                conn.close(0u32.into(), b"busy");
                continue;
            }
            if phone_ring::is_known_contact(&book_a, peer_id) {
                *state_a.phase.write().await = "connected".into();
                spawn_stream_session(
                    conn,
                    peer_id,
                    default_listen,
                    default_forward,
                    &active_a,
                    &state_a,
                    sem_a.clone(),
                    false,
                    relay_only,
                    styler_a,
                    ui_a.quiet,
                    &ep_accept,
                );
            } else {
                let since_unix_ms = now_unix_ms();
                ringing_a.write().await.push(Ringing {
                    peer: peer_id,
                    conn,
                    since: Instant::now(),
                    since_unix_ms,
                });
                *state_a.phase.write().await = "ringing".into();
                publish_pending(&state_a, &ringing_a).await;
                ui_a.line(styler_a.info(&tr_fmt!(
                    "incoming call from {0} — `link-p2p call accept {0}` or `call reject`",
                    peer_id.fmt_short()
                )));
            }
        }
    });

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    None | Some(CallCmd::Shutdown) => break,
                    Some(CallCmd::Dial { to, listen, forward, to_addr }) => {
                        let listen = listen.or(default_listen);
                        let forward = forward.or(default_forward);
                        if active.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                            warn!("{}", tr!("call daemon is busy"));
                            continue;
                        }
                        *state.phase.write().await = "dialing".into();
                        ui.line(styler.info(&tr_fmt!(
                            "calling {0}… waiting for answer",
                            to
                        )));
                        let peer = match phone_ring::resolve_peer_token(&book, &to) {
                            Ok(id) => id,
                            Err(e) => {
                                warn!(error = %e, "resolve peer");
                                *state.phase.write().await = "idle".into();
                                continue;
                            }
                        };
                        let mut addrs = to_addr;
                        if let Ok(r) = contacts::resolve(&book, &to) {
                            addrs.extend(r.addrs);
                        }
                        let dial_addr = match build_dial_addr(peer, relay, &addrs) {
                            Ok(a) => a,
                            Err(e) => {
                                warn!(error = %e, "build dial addr");
                                *state.phase.write().await = "idle".into();
                                continue;
                            }
                        };
                        match endpoint.connect(dial_addr, ALPN).await {
                            Ok(conn) => {
                                *state.phase.write().await = "connected".into();
                                spawn_stream_session(
                                    conn,
                                    peer,
                                    listen,
                                    forward,
                                    &active,
                                    &state,
                                    semaphore.clone(),
                                    true,
                                    relay_only,
                                    styler,
                                    ui.quiet,
                                    &endpoint,
                                );
                                ui.line(styler.ok(&tr_fmt!("connected to {0}", to)));
                            }
                            Err(e) => {
                                warn!(error = %e, "dial failed");
                                *state.phase.write().await = "idle".into();
                                ui.line(styler.err(&tr_fmt!(
                                    "could not reach {0}: {1}",
                                    to,
                                    e
                                )));
                            }
                        }
                    }
                    Some(CallCmd::Accept { peer }) => {
                        let mut list = ringing.write().await;
                        if let Some(idx) = list.iter().position(|r| {
                            phone_ring::match_peer_token(&book, &peer, r.peer)
                        }) {
                            let r = list.remove(idx);
                            drop(list);
                            publish_pending(&state, &ringing).await;
                            *state.phase.write().await = "connected".into();
                            spawn_stream_session(
                                r.conn,
                                r.peer,
                                default_listen,
                                default_forward,
                                &active,
                                &state,
                                semaphore.clone(),
                                false,
                                relay_only,
                                styler,
                                ui.quiet,
                                &endpoint,
                            );
                        }
                    }
                    Some(CallCmd::Reject { peer }) => {
                        let mut list = ringing.write().await;
                        if let Some(idx) = list.iter().position(|r| {
                            phone_ring::match_peer_token(&book, &peer, r.peer)
                        }) {
                            let r = list.remove(idx);
                            r.conn.close(0u32.into(), b"rejected");
                            drop(list);
                            publish_pending(&state, &ringing).await;
                            if ringing.read().await.is_empty() {
                                *state.phase.write().await = "idle".into();
                            }
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let mut list = ringing.write().await;
                let before = list.len();
                list.retain(|r| {
                    if r.since.elapsed() > RING_TIMEOUT {
                        r.conn.close(0u32.into(), b"ring timeout");
                        false
                    } else {
                        true
                    }
                });
                if list.len() != before {
                    drop(list);
                    publish_pending(&state, &ringing).await;
                    if ringing.read().await.is_empty()
                        && active.lock().unwrap_or_else(|e| e.into_inner()).is_none()
                    {
                        *state.phase.write().await = "idle".into();
                    }
                }
            }
        }
    }

    accept_task.abort();
    endpoint.close().await;
    Ok(())
}

async fn publish_pending(state: &LiveState, ringing: &RwLock<Vec<Ringing>>) {
    let list = ringing.read().await;
    let calls: Vec<PendingCall> = list
        .iter()
        .map(|r| PendingCall {
            peer: r.peer.to_string(),
            since_unix_ms: r.since_unix_ms,
            direction: "in".into(),
        })
        .collect();
    *state.pending.write().await = calls;
}

#[allow(clippy::too_many_arguments)]
fn spawn_stream_session(
    conn: iroh::endpoint::Connection,
    peer: EndpointId,
    listen: Option<SocketAddr>,
    forward: Option<SocketAddr>,
    active: &Arc<Mutex<Option<(EndpointId, ConnSlot)>>>,
    state: &Arc<LiveState>,
    semaphore: Arc<tokio::sync::Semaphore>,
    we_dialed: bool,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
    endpoint: &iroh::Endpoint,
) {
    let slot = ConnSlot::new(Some(conn.clone()));
    {
        let mut g = active.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some((peer, slot.clone()));
    }
    let state_p = state.clone();
    let peer_s = peer.to_string();
    tokio::spawn(async move {
        *state_p.peers.write().await = vec![StreamPeer { id: peer_s }];
    });

    crate::spawn_path_monitor(
        conn.clone(),
        peer,
        endpoint.clone(),
        relay_only,
        styler,
        quiet,
        "call",
    );

    if let Some(target) = forward {
        let tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        crate::call::spawn_forward_accept_loop(conn.clone(), target, semaphore.clone(), tasks);
    }

    if let Some(addr) = listen {
        let slot_l = slot.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::call::run_local_listen_daemon(addr, slot_l, sem).await {
                warn!(error = %e, "local listen ended");
            }
        });
    } else if we_dialed && forward.is_none() {
        tracing::debug!("session up without local --listen");
    }

    let active_c = active.clone();
    let state_c = state.clone();
    let conn_c = conn;
    tokio::spawn(async move {
        loop {
            if conn_c.close_reason().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        *active_c.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *state_c.peers.write().await = Vec::new();
        *state_c.phase.write().await = "idle".into();
    });
}
