//! Windows-specific TUN daemon: named-pipe accept loop and admin gate.

use super::*;
use std::sync::Arc;
use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;


pub(crate) async fn run_skeleton_control(
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


pub(crate) async fn run_live_control_and_data(
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


pub(crate) async fn serve_ctl_until_shutdown(
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


pub(crate) async fn handle_one_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    hooks: Arc<crate::tun::TunHooks>,
    shutdown_tx: watch::Sender<bool>,
    require_privilege: bool,
) {
    let req = match timeout(CTL_READ_TIMEOUT, tun_ctl::read_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        _ => return,
    };

    // No `.await` between trust check and privileged handling — see
    // `win_pipe::peer_is_admin` call-site contract.
    let privileged =
        resolve_ctl_privilege(require_privilege, || crate::win_pipe::peer_is_admin(&stream));
    let resp = handle_ctl_request(req, &hooks, &shutdown_tx, privileged).await;
    let _ = timeout(CTL_READ_TIMEOUT, write_response(&mut stream, &resp)).await;
}

