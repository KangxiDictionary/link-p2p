//! Stub control plane for non-Unix/non-Windows builds.

use super::super::*;


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

pub async fn connect_timed(_path: &Path, _limit: Duration) -> Result<()> {
    bail!(tr!("TUN daemon control socket is Unix-only in this build"))
}

pub async fn send_expect_ok(_path: &Path, mode: RuntimeMode, _req: &CtlRequest) -> Result<()> {
    Err(tun_ctl::not_running(mode))
}

pub fn bind_listener(_path: &Path, _mode: RuntimeMode) -> Result<()> {
    bail!(tr!("TUN daemon control socket is Unix-only in this build"))
}
