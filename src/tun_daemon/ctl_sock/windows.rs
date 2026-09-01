//! Windows named-pipe control plane helpers.

use super::super::*;

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
