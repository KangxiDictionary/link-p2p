//! Unix domain socket control plane helpers.

use super::super::*;

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
    let old = rustix::process::umask(rustix::fs::Mode::from_bits_retain(0o177));
    let bound = UnixListener::bind(path);
    rustix::process::umask(old);
    let listener = bound.with_context(|| {
        tr_fmt!("binding TUN control socket {0}", path.display().to_string())
    })?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    Ok(listener)
}

pub async fn send_shutdown(path: &Path, mode: RuntimeMode) -> Result<()> {
    send_expect_ok(path, mode, &CtlRequest::Shutdown).await
}

pub async fn send_expect_ok(path: &Path, mode: RuntimeMode, req: &CtlRequest) -> Result<()> {
    let mut stream = connect_timed(path, PROBE_CONNECT_TIMEOUT)
        .await
        .map_err(|_| tun_ctl::not_running(mode))?;
    write_request(&mut stream, req).await?;
    let resp = timeout(ready_timeout(), tun_ctl::read_response(&mut stream))
        .await
        .map_err(|_| {
            exit::coded(
                exit::TIMEOUT,
                anyhow::anyhow!(tr!("TUN control request timed out")),
            )
        })??;
    match resp {
        CtlResponse::Ok => Ok(()),
        CtlResponse::Err { code, message } => Err(exit::coded(code, anyhow::anyhow!(message))),
        other => bail!(tr_fmt!(
            "unexpected control response: {0}",
            format!("{other:?}")
        )),
    }
}
