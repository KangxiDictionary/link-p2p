//! Stream phone daemon (standing callee).

#[cfg(unix)]
#[path = "../stream_daemon_unix.rs"]
mod imp;

#[cfg(not(unix))]
mod imp {
    use std::net::SocketAddr;
    use std::time::Duration;

    use anyhow::{bail, Result};
    use iroh::SecretKey;

    use crate::exit;
    use crate::i18n::tr;
    use crate::runtime::{TransportTune, Ui};
    use crate::style::Styler;

    pub struct UpOpts {
        pub listen: Option<SocketAddr>,
        pub forward: Option<SocketAddr>,
        pub foreground: bool,
    }

    pub fn is_worker_process() -> bool {
        false
    }

    pub async fn run_worker() -> Result<()> {
        bail!(tr!("stream call daemon worker is Unix-only in this build"))
    }

    pub async fn cmd_up(
        _opts: UpOpts,
        _identity: Option<&std::path::Path>,
        _secret_key: SecretKey,
        _relay: &[String],
        _no_n0: bool,
        _relay_only: bool,
        _keepalive: Duration,
        _idle_timeout: Duration,
        _tune: TransportTune,
        _max_conns: usize,
        _ui: Ui,
        _styler: Styler,
    ) -> Result<()> {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "stream call daemon is Unix-only in this build; use serve/connect on this platform for now"
            )),
        ))
    }

    pub async fn cmd_down(_ui: Ui, _styler: Styler) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
    pub async fn cmd_status(_ui: Ui, _styler: Styler) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
    pub async fn cmd_ring(_ui: Ui, _styler: Styler) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
    pub async fn cmd_accept(_peer: &str, _ui: Ui, _styler: Styler) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
    pub async fn cmd_reject(_peer: &str, _ui: Ui, _styler: Styler) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
    pub async fn cmd_call(
        _to: &str,
        _listen: Option<SocketAddr>,
        _forward: Option<SocketAddr>,
        _to_addr: Vec<SocketAddr>,
        _no_wait: bool,
        _identity: Option<&std::path::Path>,
        _secret_key: SecretKey,
        _relay: &[String],
        _no_n0: bool,
        _relay_only: bool,
        _keepalive: Duration,
        _idle_timeout: Duration,
        _tune: TransportTune,
        _max_conns: usize,
        _ui: Ui,
        _styler: Styler,
    ) -> Result<()> {
        bail!(tr!("stream call daemon is Unix-only in this build"))
    }
}

pub use imp::*;
