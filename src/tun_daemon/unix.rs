//! Unix-specific TUN daemon: spawn, UDS accept loop, peer credentials.

use super::*;
use std::fs::OpenOptions;
use std::process::{Command, Stdio};
use std::sync::Arc;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;

pub(crate) fn socket_mode(mode: RuntimeMode) -> u32 {
    if mode == RuntimeMode::System {
        0o666
    } else {
        0o600
    }
}

pub(crate) async fn spawn_daemon_unix(opts: &SpawnOpts, skeleton: bool) -> Result<PidRecord> {
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
    if let Some(ip) = opts.tun_ip6 {
        cmd.env("LINK_P2P_TUN_IP6", ip.to_string());
    }
    if !opts.allow.is_empty() {
        cmd.env("LINK_P2P_ALLOW", opts.allow.join(","));
    }
    if opts.hidden {
        cmd.env("LINK_P2P_TUN_HIDDEN", "1");
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
                    "timed out waiting for tun daemon to become ready; check {0}\n\
                     Tip: for the system service use `systemctl status link-p2p-tun.service` and `journalctl -u link-p2p-tun.service -f`.",
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
            anyhow::anyhow!(tr_fmt!(
                "TUN daemon failed to start: {0}\n\
                 See {1} (system service: `systemctl status link-p2p-tun.service` / `journalctl -u link-p2p-tun.service -e`).",
                err.trim(),
                log_path.display().to_string()
            )),
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

    // Authoritative readiness: control socket answers Status (not only the
    // TCP ready line). Mitigates TOCTOU where a child could signal OK before
    // bind, or a late pid write after a timed-out parent already cleaned up.
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


/// Skeleton control loop (no TUN). Used by unit/integration lifecycle tests.
pub(crate) async fn run_skeleton_control(
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


/// Real TUN + roster under the same lock/socket/ready contract as the skeleton.
pub(crate) async fn run_live_control_and_data(
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


pub(crate) async fn serve_ctl_until_shutdown(
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
pub(crate) async fn handle_one_connection(
    mut stream: tokio::net::UnixStream,
    hooks: Arc<crate::tun::TunHooks>,
    shutdown_tx: watch::Sender<bool>,
    require_privilege: bool,
) {
    let req = match timeout(CTL_READ_TIMEOUT, tun_ctl::read_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        _ => return, // read timeout or bad frame: drop this connection only
    };

    let privileged = resolve_ctl_privilege(require_privilege, || peer_is_privileged(&stream));
    let resp = handle_ctl_request(req, &hooks, &shutdown_tx, privileged).await;
    let _ = timeout(CTL_READ_TIMEOUT, write_response(&mut stream, &resp)).await;
}


/// Whether the peer behind `stream` may stop the daemon. Only consulted in
/// system mode (socket is world-connectable there); fails closed — an error
/// reading peer credentials is treated as unprivileged.
pub(crate) fn peer_is_privileged(stream: &tokio::net::UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) => {
            cred.uid() == 0 || cred.uid() == rustix::process::geteuid().as_raw()
        }
        Err(_) => false,
    }
}

