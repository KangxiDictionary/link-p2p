//! CLI dispatch (`real_main`) — shared by the binary entry point.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::FromArgMatches;
use iroh::SecretKey;
use tracing::{info, warn};

use crate::call;
use crate::cli::{
    localized_command, Cli, Command, ConnectMode, LogFormat, OutputFormat, TunCommand,
    TunServiceCommand,
};
use crate::commands::config::run_config;
use crate::commands::connect::run_connect;
use crate::commands::contact::run_contact;
use crate::commands::ping::run_ping;
use crate::commands::serve::run_serve;
use crate::commands::tun::run_tun;
use crate::config;
use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::path_stats;
use crate::relay_probe;
use crate::runtime::{merge_allow_list, resolve_peer_to, ServeMode, TransportTune, Ui};
use crate::selftest;
use crate::style::{apply_color_mode, ColorMode, Styler};
use crate::tun_daemon;
use crate::tun_service;
use crate::{load_or_create_secret_key, resolve_identity_path, validate_passphrase};

/// Parse argv, load identity when needed, run the selected subcommand.
pub async fn real_main(color_mode: ColorMode) -> Result<()> {
    // Dispatch shell: worker probes, clap, identity, then subcommands.
    // Definitions: `cli`; session helpers: `runtime`; stream cmds: `commands::*`.

    // Detached TUN daemon worker (spawned by tun_daemon::spawn_skeleton).
    // Not a user-facing subcommand — gated on env, ahead of clap.
    if tun_daemon::is_worker_process() {
        return tun_daemon::run_worker().await;
    }
    // Integration-test drivers (see tests/tun_daemon_spawn.rs). Not public CLI.
    if std::env::var_os("LINK_P2P_TUN_TEST_SPAWN").is_some() {
        let role = std::env::var("LINK_P2P_TUN_ROLE").unwrap_or_else(|_| "hub".into());
        tun_daemon::spawn_skeleton(&role).await?;
        return Ok(());
    }
    if std::env::var_os("LINK_P2P_TUN_TEST_DOWN").is_some() {
        return tun_daemon::request_shutdown().await;
    }

    let matches = localized_command()
        .color(color_mode.to_clap())
        .get_matches();
    let mut cli = Cli::from_arg_matches(&matches)?;

    // Completions / man are pure stdout generation — no identity file, no
    // logging, no network. Handle them before any of that machinery spins up.
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut localized_command().color(color_mode.to_clap()),
            "link-p2p",
            &mut std::io::stdout(),
        );
        return Ok(());
    }
    #[cfg(unix)]
    if matches!(cli.command, Command::Man) {
        // Lightweight man page without clap_mangen (avoids pulling edition2024
        // crates on older toolchains). Help text comes from the same localized
        // Command tree as `--help`.
        let mut cmd = localized_command().color(color_mode.to_clap());
        let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help)
            .context(tr!("rendering man page"))?;
        let help = String::from_utf8_lossy(&help);
        let mut out = String::new();
        out.push_str(".TH LINK-P2P 1\n");
        out.push_str(".SH NAME\n");
        out.push_str("link-p2p \\- minimal TCP-over-QUIC forwarder on iroh\n");
        out.push_str(".SH SYNOPSIS\n");
        out.push_str("link-p2p [OPTIONS] <COMMAND>\n");
        out.push_str(".SH DESCRIPTION\n");
        out.push_str(&about);
        out.push('\n');
        out.push_str(".SH OPTIONS\n");
        // Escape leading dots so troff does not treat help lines as macros.
        for line in help.lines() {
            if line.starts_with('.') {
                out.push('\\');
            }
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(".SH SEE ALSO\n");
        out.push_str("docs/user-guide/platforms.md, docs/architecture/performance.md, README.md\n");
        std::io::stdout()
            .write_all(out.as_bytes())
            .context(tr!("writing man page"))?;
        return Ok(());
    }

    // `help [subcommand...]`: navigate the (localized) command tree and print
    // the requested help. Borrowed match so cli.command stays usable below.
    if let Command::Help { sub } = &cli.command {
        let mut cmd = localized_command().color(color_mode.to_clap());
        let mut target = &mut cmd;
        for name in sub {
            target = match target.find_subcommand_mut(name) {
                Some(c) => c,
                None => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr_fmt!("unrecognized subcommand '{0}'", name)),
                    ));
                }
            };
        }
        target.print_help().context(tr!("printing help"))?;
        println!();
        return Ok(());
    }

    let log_format = cli.log_format;
    let ui = Ui {
        quiet: cli.quiet,
        stderr_only: false,
    };
    let tune = TransportTune {
        cc: cli.cc,
        send_window: cli.send_window,
        stream_recv_window: cli.stream_recv_window,
    };

    // Enable iroh's internal logging (RUST_LOG=iroh=debug etc). Without this
    // iroh's tracing events go nowhere, so RUST_LOG would be a no-op.
    //
    // Default filter is scoped rather than a blanket "info": iroh emits a
    // fair amount of info-level chatter internally (relay/discovery churn),
    // which would drown out our own connection-lifecycle logs. Explicit
    // RUST_LOG always wins, e.g. `RUST_LOG=iroh=trace` for the path-selection
    // debugging described in README.md. `-q`/`-v`/`-vv` only apply when
    // RUST_LOG is unset.
    let default_filter = match (cli.quiet, cli.verbose) {
        (true, _) => "link_p2p=warn,iroh=error",
        (false, 0) => "link_p2p=info,iroh=warn",
        (false, 1) => "link_p2p=debug,iroh=info",
        (false, _) => "link_p2p=trace,iroh=debug",
    };
    let fmt = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_target(true)
        // Emit span close events so timing/byte-count spans (dial, pipe) are
        // visible in the output; the default (FmtSpan::NONE) records their
        // fields but never prints them.
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        // Logs go to stderr (the Unix convention: stdout carries the
        // user-facing status lines only), so `--log-format json` output is
        // clean, jq-parseable JSON when stderr is redirected — see README.
        // Skip ANSI color codes when stderr isn't a real terminal (piped to
        // a file, `| tee`, log aggregator, etc).
        .with_ansi(std::io::stderr().is_terminal());
    match log_format {
        LogFormat::Json => fmt.json().init(),
        LogFormat::Text => fmt.init(),
    }

    let styler = apply_color_mode(color_mode);

    // Service install/uninstall must not run global identity load first — the
    // install subcommand defaults `--identity` to /etc/link-p2p/identity.key,
    // which would hit Permission denied (rc=1) before require_root() (rc=2).
    if let Command::Tun {
        command: TunCommand::Service { command },
    } = cli.command
    {
        return run_tun_service_command(command, &styler);
    }

    // Load ~/.config/link-p2p/config.toml defaults (CLI still wins / appends).
    let user_cfg = config::load_or_default(&config::config_path());
    cli.relay = config::merge_relay_urls(&cli.relay, &user_cfg);
    // Bias multi-relay dial order for every command (not just `call`).
    cli.relay = relay_probe::order_by_connect_latency(&cli.relay).await;
    cli.no_n0_relays = cli.no_n0_relays || user_cfg.relays.no_n0;
    if !cli.relay_only {
        cli.relay_only = user_cfg.relays.relay_only;
    }

    // Selftest / stats need merged --relay (selftest) but not an identity key.
    match &cli.command {
        Command::Selftest { no_echo, tun } => {
            return selftest::run_selftest(
                &cli.relay,
                selftest::SelftestOpts {
                    no_echo: *no_echo,
                    tun: *tun,
                },
                ui,
                &styler,
            )
            .await;
        }
        Command::Tun {
            command: TunCommand::Selftest { no_echo },
        } => {
            return selftest::run_selftest(
                &cli.relay,
                selftest::SelftestOpts {
                    no_echo: *no_echo,
                    tun: true,
                },
                ui,
                &styler,
            )
            .await;
        }
        Command::Stats { last, format } => {
            return print_path_stats(*last, *format, ui, &styler);
        }
        _ => {}
    }

    // Passphrase for the identity file: --identity-passphrase wins over
    // LINK_P2P_PASSPHRASE (the env var avoids the passphrase showing up in
    // `ps`/shell history). Empty values are treated as unset. Held in
    // Zeroizing so Drop clears the heap bytes (best-effort; swap may still
    // have seen them).
    let from_cli_flag = cli.identity_passphrase.is_some();
    let passphrase: Option<zeroize::Zeroizing<String>> = cli
        .identity_passphrase
        .or_else(|| std::env::var("LINK_P2P_PASSPHRASE").ok().map(zeroize::Zeroizing::new))
        .filter(|p| !p.is_empty());
    if let Some(p) = &passphrase {
        validate_passphrase(p)?;
        info!("{}", tr!("using a passphrase-protected identity key file"));
        if from_cli_flag {
            warn!(
                "{}",
                tr!(
                    "`--identity-passphrase` is visible in `ps` and shell history; prefer LINK_P2P_PASSPHRASE"
                )
            );
        }
    }
    // --ephemeral: an in-memory identity, nothing touches the filesystem.
    let identity_from_cli = cli.identity.is_some();
    let secret_key = if cli.ephemeral {
        ui.line(styler.warn(&tr!(
            "ephemeral identity: this EndpointId will not persist across restarts"
        )));
        SecretKey::generate()
    } else {
        let identity = resolve_identity_path(cli.identity)?;
        load_or_create_secret_key(&identity, passphrase.as_deref().map(|s| s.as_str()))
            .context(tr!("loading/creating persistent identity"))?
    };

    match cli.command {
        Command::Serve {
            forward,
            proxy,
            allow,
            allow_private,
        } => {
            let mode = match (forward, proxy) {
                (Some(addr), false) => ServeMode::Forward(addr),
                (None, true) => ServeMode::Proxy { allow_private },
                (Some(_), true) | (None, false) => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr!("serve requires either --forward or --proxy")),
                    ));
                }
            };
            let allow = merge_allow_list(allow);
            let allowed = allow
                .iter()
                .map(|s| {
                    s.parse().map_err(|e| {
                        exit::coded(
                            exit::USAGE,
                            anyhow::Error::new(e).context(tr_fmt!(
                                "'{0}' is not a valid EndpointId in --allow",
                                s
                            )),
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            run_serve(
                secret_key,
                mode,
                allowed,
                &cli.relay,
                cli.relay_only,
                cli.no_n0_relays,
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                tune,
                ui,
                styler,
            )
            .await
        }
        Command::Connect {
            to,
            listen,
            socks5_listen,
            #[cfg(unix)]
            stdio,
            to_addr,
        } => {
            #[cfg(unix)]
            let mode = match (listen, socks5_listen, stdio) {
                (Some(a), None, false) => ConnectMode::Listen(a),
                (None, Some(a), false) => ConnectMode::Socks5(a),
                (None, None, true) => ConnectMode::Stdio,
                _ => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr!(
                            "connect requires exactly one of --listen, --socks5-listen, or --stdio"
                        )),
                    ));
                }
            };
            #[cfg(not(unix))]
            let mode = match (listen, socks5_listen) {
                (Some(a), None) => ConnectMode::Listen(a),
                (None, Some(a)) => ConnectMode::Socks5(a),
                _ => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr!(
                            "connect requires exactly one of --listen or --socks5-listen"
                        )),
                    ));
                }
            };
            #[cfg(unix)]
            let stdio = matches!(mode, ConnectMode::Stdio);
            #[cfg(not(unix))]
            let stdio = false;
            let to = resolve_peer_to(to, stdio)?;
            let ui = Ui {
                quiet: ui.quiet,
                stderr_only: stdio,
            };
            run_connect(
                secret_key,
                &to,
                mode,
                &cli.relay,
                cli.relay_only,
                cli.no_n0_relays,
                to_addr,
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                tune,
                ui,
                styler,
            )
            .await
        }
        Command::Tun { command } => {
            run_tun(
                command,
                secret_key,
                &cli.relay,
                cli.relay_only,
                cli.no_n0_relays,
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                identity_from_cli,
                cli.ephemeral,
                tune,
                ui,
                styler,
            )
            .await
        }
        Command::Ping {
            to,
            to_addr,
            format,
        } => {
            let to = resolve_peer_to(to, false)?;
            run_ping(
                secret_key,
                &to,
                &cli.relay,
                cli.relay_only,
                cli.no_n0_relays,
                to_addr,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                tune,
                format,
                ui,
                styler,
            )
            .await
        }
        Command::Call {
            to,
            listen,
            forward,
            #[cfg(unix)]
            stdio,
            to_addr,
        } => {
            #[cfg(unix)]
            let local = match (listen, stdio) {
                (Some(a), false) => call::CallLocal::Listen(a),
                (None, true) => call::CallLocal::Stdio,
                _ => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr!(
                            "call requires exactly one of --listen or --stdio (and optional --forward)"
                        )),
                    ));
                }
            };
            #[cfg(not(unix))]
            let local = match listen {
                Some(a) => call::CallLocal::Listen(a),
                None => {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr!("call requires --listen (and optional --forward)")),
                    ));
                }
            };
            #[cfg(unix)]
            let ui = Ui {
                quiet: ui.quiet,
                stderr_only: matches!(local, call::CallLocal::Stdio),
            };
            call::run_call(
                secret_key,
                &to,
                local,
                forward,
                &cli.relay,
                cli.no_n0_relays,
                cli.relay_only,
                to_addr,
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                tune,
                ui,
                styler,
            )
            .await
        }
        Command::Contact { command } => run_contact(command, secret_key, ui, styler),
        Command::Config { command } => run_config(command, ui, styler),
        Command::Completions { .. }
        | Command::Help { .. }
        | Command::Stats { .. }
        | Command::Selftest { .. } => {
            // Completions / help / stats / selftest return before identity setup.
            unreachable!("handled before identity load")
        }
        #[cfg(unix)]
        Command::Man => {
            unreachable!("handled before identity load")
        }
    }
}

/// `tun service install/uninstall` — no global identity load (service identity
/// lives under `/etc/link-p2p/`, not the caller's config dir).
fn run_tun_service_command(command: TunServiceCommand, styler: &Styler) -> Result<()> {
    match command {
        TunServiceCommand::Install {
            role,
            to,
            identity,
            user,
        } => {
            let role = tun_daemon::resolve_up_role(role.as_deref(), to.as_deref())?;
            let spoke_to = if role == "spoke" {
                Some(resolve_peer_to(to, false)?.to_string())
            } else {
                None
            };
            let identity_fallback = if identity.is_file() {
                None
            } else {
                tun_service::sudo_caller_identity_path().or_else(|| {
                    resolve_identity_path(None)
                        .ok()
                        .filter(|p| p.is_file())
                })
            };
            tun_service::cmd_install(
                tun_service::InstallOpts {
                    role,
                    to: spoke_to,
                    identity,
                    service_user: user,
                    identity_fallback,
                },
                styler,
            )
        }
        TunServiceCommand::Uninstall => tun_service::cmd_uninstall(styler),
    }
}

fn print_path_stats(
    last: usize,
    format: OutputFormat,
    ui: Ui,
    styler: &Styler,
) -> Result<()> {
    let summary = path_stats::load_summary(Some(last))?;
    match format {
        OutputFormat::Json => {
            let path = path_stats::stats_path();
            println!(
                "{{\"file\":{file},\"total\":{total},\"direct\":{direct},\"relay\":{relay},\
\"relay_candidate\":{cand},\"unknown\":{unknown},\"direct_pct\":{pct:.1}}}",
                file = serde_json::to_string(&path.display().to_string()).unwrap_or_else(|_| "\"\"".into()),
                total = summary.total,
                direct = summary.direct,
                relay = summary.relay,
                cand = summary.relay_candidate,
                unknown = summary.unknown,
                pct = summary.direct_pct(),
            );
        }
        OutputFormat::Text => {
            ui.line(styler.banner(&tr!("link-p2p path stats")));
            ui.line(styler.dim(&tr_fmt!(
                "file: {0} (last {1} samples)",
                path_stats::stats_path().display(),
                last
            )));
            if summary.total == 0 {
                ui.line(styler.warn(&tr!(
                    "no samples yet — run `ping` or a connect/call session first"
                )));
                return Ok(());
            }
            ui.line(styler.ok(&tr_fmt!(
                "direct {0}/{1} ({2:.0}%)  relay {3}  relay+candidate {4}  unknown {5}",
                summary.direct,
                summary.total,
                summary.direct_pct(),
                summary.relay,
                summary.relay_candidate,
                summary.unknown
            )));
            // Show a few recent lines for context.
            for sample in summary.samples.iter().rev().take(5) {
                ui.line(format!(
                    "  {}  {}  {}  {}{}",
                    sample.ts,
                    sample.cmd,
                    sample.peer_short,
                    sample.path,
                    sample
                        .upgrade_ms
                        .map(|ms| format!("  upgrade_ms={ms}"))
                        .unwrap_or_default()
                ));
            }
        }
    }
    Ok(())
}
