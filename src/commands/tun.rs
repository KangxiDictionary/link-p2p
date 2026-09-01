//! `tun` — Layer-3 mesh hub/spoke routing and daemon control.

use std::time::Duration;

use anyhow::{anyhow, Result};
use iroh::SecretKey;

use crate::cli::{OutputFormat, TunCommand};
use crate::exit;
use crate::i18n::tr;
use crate::runtime::{parse_tun_allow, resolve_peer_to, TransportTune, Ui};
use crate::style::Styler;
use crate::tun;
use crate::tun_ctl;
use crate::tun_daemon;

pub(crate) async fn run_tun(
    command: TunCommand,
    secret_key: SecretKey,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    identity_from_cli: bool,
    ephemeral: bool,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    // TUN hub accepts many peers; --max-conns only applies to stream serve.
    // `tun join` is sugar for `tun up --role spoke --to …`.
    let command = match command {
        TunCommand::Join {
            to,
            foreground,
            system,
            tun_ip,
            tun_ip6,
            mtu,
            allow,
            to_addr,
            hidden,
        } => TunCommand::Up {
            role: Some("spoke".into()),
            to: Some(to),
            foreground,
            system,
            windows_service: false,
            tun_ip,
            tun_ip6,
            mtu,
            allow,
            to_addr,
            hidden,
        },
        other => other,
    };
    let warn_max_conns = matches!(
        &command,
        TunCommand::Serve { .. } | TunCommand::Connect { .. } | TunCommand::Up { .. }
    );
    if warn_max_conns && max_conns != 1024 {
        ui.line(styler.warn(&tr!(
            "note: --max-conns is not used by TUN mode (hub accepts peers until stopped)"
        )));
    }
    match command {
        TunCommand::Up {
            role,
            to,
            foreground,
            system,
            windows_service: _,
            tun_ip,
            tun_ip6,
            mtu,
            allow,
            to_addr,
            hidden,
        } => {
            tun::validate_mtu(mtu)?;
            let runtime = tun_ctl::RuntimeMode::from_system_flag(system);
            let role = tun_daemon::resolve_up_role(role.as_deref(), to.as_deref())?;
            let allow = parse_tun_allow(allow)?;
            if hidden && role != "spoke" {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow!(tr!("`--hidden` is only valid for spoke / `tun join`")),
                ));
            }
            if hidden {
                std::env::set_var("LINK_P2P_TUN_HIDDEN", "1");
            }
            if system && !foreground {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow!(tr!(
                        "`tun up --system` requires `--foreground` (supervisor-managed services must not self-daemonize)"
                    )),
                ));
            }
            if system && !ephemeral && !identity_from_cli {
                ui.line(styler.warn(&tr!(
                    "system mode: pin identity with --identity (e.g. /etc/link-p2p/identity.key); the service account config dir may otherwise get a new key"
                )));
            }
            if foreground {
                if system {
                    let spoke_to = if role == "spoke" {
                        Some(resolve_peer_to(to, false)?.to_string())
                    } else {
                        None
                    };
                    tun_daemon::run_supervised_foreground(
                        tun_daemon::SupervisedUpOpts {
                            role,
                            to: spoke_to,
                            tun_ip,
                            tun_ip6,
                            mtu,
                            allow,
                            to_addr,
                            secret_key,
                            relays: relay.to_vec(),
                            relay_only,
                            no_n0_relays,
                            keepalive,
                            idle_timeout,
                            tune,
                        },
                        ui,
                        styler,
                    )
                    .await
                } else {
                    let spoke_to = if role == "spoke" {
                        Some(resolve_peer_to(to, false)?)
                    } else {
                        None
                    };
                    // Same opts struct as `--system`: `tun serve` /
                    // `tun connect` aliases also call `run_adhoc_foreground`.
                    tun_daemon::run_adhoc_foreground(
                        tun_daemon::SupervisedUpOpts {
                            role,
                            to: spoke_to,
                            tun_ip,
                            tun_ip6,
                            mtu,
                            allow,
                            to_addr,
                            secret_key,
                            relays: relay.to_vec(),
                            relay_only,
                            no_n0_relays,
                            keepalive,
                            idle_timeout,
                            tune,
                        },
                        ui,
                        styler,
                    )
                    .await
                }
            } else {
                let allow_str: Vec<String> = allow
                    .as_ref()
                    .map(|s| s.iter().map(|id| id.to_string()).collect())
                    .unwrap_or_default();
                tun_daemon::cmd_up_background(
                    runtime,
                    &role,
                    to.as_deref(),
                    mtu,
                    tun_ip,
                    tun_ip6,
                    &allow_str,
                    hidden,
                    &styler,
                )
                .await
            }
        }
        TunCommand::Join { .. } => unreachable!("rewritten to Up above"),
        TunCommand::Call {
            args,
            no_wait,
            system,
        } => {
            let mode = tun_ctl::RuntimeMode::from_system_flag(system);
            match args.as_slice() {
                [] => Err(exit::coded(
                    exit::USAGE,
                    anyhow!(tr!(
                        "usage: tun call <peer> | tun call accept <peer> | tun call reject <peer>"
                    )),
                )),
                [a, peer] if a == "accept" => {
                    tun_daemon::cmd_call_accept(mode, peer, &styler).await
                }
                [a, peer] if a == "reject" => {
                    tun_daemon::cmd_call_reject(mode, peer, &styler).await
                }
                [to] => tun_daemon::cmd_call(mode, to, no_wait, &styler).await,
                _ => Err(exit::coded(
                    exit::USAGE,
                    anyhow!(tr!(
                        "usage: tun call <peer> | tun call accept <peer> | tun call reject <peer>"
                    )),
                )),
            }
        }
        TunCommand::Ring { system } => {
            tun_daemon::cmd_ring(tun_ctl::RuntimeMode::from_system_flag(system)).await
        }
        TunCommand::Down { system } => {
            tun_daemon::cmd_down(tun_ctl::RuntimeMode::from_system_flag(system), &styler).await
        }
        TunCommand::Status { format, system } => {
            let fmt = match format {
                OutputFormat::Text => tun_daemon::CliFormat::Text,
                OutputFormat::Json => tun_daemon::CliFormat::Json,
            };
            tun_daemon::cmd_status(tun_ctl::RuntimeMode::from_system_flag(system), fmt).await
        }
        TunCommand::Peers { format, system } => {
            let fmt = match format {
                OutputFormat::Text => tun_daemon::CliFormat::Text,
                OutputFormat::Json => tun_daemon::CliFormat::Json,
            };
            tun_daemon::cmd_peers(tun_ctl::RuntimeMode::from_system_flag(system), fmt).await
        }
        TunCommand::Selftest { .. } => {
            unreachable!("tun selftest handled before identity load")
        }
        TunCommand::Serve {
            tun_ip,
            tun_ip6,
            mtu,
            allow,
        } => {
            // Alias of `tun up --foreground --role hub`.
            tun::validate_mtu(mtu)?;
            let allow = parse_tun_allow(allow)?;
            tun_daemon::run_adhoc_foreground(
                tun_daemon::SupervisedUpOpts {
                    role: "hub".into(),
                    to: None,
                    tun_ip,
                    tun_ip6,
                    mtu,
                    allow,
                    to_addr: Vec::new(),
                    secret_key,
                    relays: relay.to_vec(),
                    relay_only,
                    no_n0_relays,
                    keepalive,
                    idle_timeout,
                    tune,
                },
                ui,
                styler,
            )
            .await
        }
        TunCommand::Connect {
            to,
            tun_ip,
            tun_ip6,
            mtu,
            to_addr,
            allow,
            hidden,
        } => {
            // Alias of `tun up --foreground --role spoke --to …`.
            tun::validate_mtu(mtu)?;
            let to = resolve_peer_to(to, false)?;
            let allow = parse_tun_allow(allow)?;
            if hidden {
                std::env::set_var("LINK_P2P_TUN_HIDDEN", "1");
            }
            tun_daemon::run_adhoc_foreground(
                tun_daemon::SupervisedUpOpts {
                    role: "spoke".into(),
                    to: Some(to),
                    tun_ip,
                    tun_ip6,
                    mtu,
                    allow,
                    to_addr,
                    secret_key,
                    relays: relay.to_vec(),
                    relay_only,
                    no_n0_relays,
                    keepalive,
                    idle_timeout,
                    tune,
                },
                ui,
                styler,
            )
            .await
        }
        TunCommand::Service { .. } => {
            unreachable!("tun service handled before identity load")
        }
    }
}
