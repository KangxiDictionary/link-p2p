//! Stream phone CLI: `call up|down|ring|status|accept|reject|<peer>`.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use iroh::SecretKey;

use crate::cli::CallCommand;
use crate::exit;
use crate::i18n::tr;
use crate::runtime::{TransportTune, Ui};
use crate::stream_daemon::{self, UpOpts};
use crate::style::Styler;

pub(crate) fn parse_call_args(
    args: Vec<String>,
    listen: Option<std::net::SocketAddr>,
    forward: Option<std::net::SocketAddr>,
    to_addr: Vec<std::net::SocketAddr>,
    no_wait: bool,
    foreground: bool,
) -> Result<CallCommand> {
    let mut it = args.into_iter();
    let Some(head) = it.next() else {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "usage: call up|down|ring|status|accept <peer>|reject <peer>|<peer>"
            )),
        ));
    };
    match head.as_str() {
        "up" => {
            if it.next().is_some() {
                bail!(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("usage: call up [--listen …] [--forward …] [--foreground]")),
                ));
            }
            Ok(CallCommand::Up {
                listen,
                forward,
                foreground,
            })
        }
        "down" => Ok(CallCommand::Down),
        "status" => Ok(CallCommand::Status),
        "ring" => Ok(CallCommand::Ring),
        "accept" => {
            let Some(peer) = it.next() else {
                bail!(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("usage: call accept <peer>")),
                ));
            };
            Ok(CallCommand::Accept { peer })
        }
        "reject" => {
            let Some(peer) = it.next() else {
                bail!(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("usage: call reject <peer>")),
                ));
            };
            Ok(CallCommand::Reject { peer })
        }
        peer => {
            if it.next().is_some() {
                bail!(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!(
                        "usage: call <peer> [--listen …] [--forward …] [--to-addr …] [--no-wait]"
                    )),
                ));
            }
            Ok(CallCommand::Dial {
                to: peer.to_string(),
                listen,
                forward,
                to_addr,
                no_wait,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_call_cmd(
    command: CallCommand,
    identity: Option<&Path>,
    secret_key: SecretKey,
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
    match command {
        CallCommand::Up {
            listen,
            forward,
            foreground,
        } => {
            stream_daemon::cmd_up(
                UpOpts {
                    listen,
                    forward,
                    foreground,
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
            .await
        }
        CallCommand::Down => stream_daemon::cmd_down(ui, styler).await,
        CallCommand::Status => stream_daemon::cmd_status(ui, styler).await,
        CallCommand::Ring => stream_daemon::cmd_ring(ui, styler).await,
        CallCommand::Accept { peer } => stream_daemon::cmd_accept(&peer, ui, styler).await,
        CallCommand::Reject { peer } => stream_daemon::cmd_reject(&peer, ui, styler).await,
        CallCommand::Dial {
            to,
            listen,
            forward,
            to_addr,
            no_wait,
        } => {
            stream_daemon::cmd_call(
                &to,
                listen,
                forward,
                to_addr,
                no_wait,
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
            .await
        }
    }
}
