//! link-p2p: P2P TCP/UDP bridging on iroh (QUIC).
//!
//! Primary commands:
//! - **`serve` / `connect`** — stream mode: forward TCP (or SOCKS5 proxy) over
//!   a QUIC session identified by EndpointId.
//! - **`call`** — symmetric dial (EndpointId tie-break); optional local listen
//!   and `--forward`.
//! - **`tun`** — Layer-3 mesh (hub/spoke VIP routing) with optional system
//!   service install (systemd / LaunchDaemon / Windows SCM).
//! - **`ping` / `contact` / `config`** — diagnostics and local bookkeeping.
//!
//! Identity keys live in [`identity`]; stream pipes in [`pipe`]; SOCKS5 in
//! [`socks5`]. CLI definitions in [`cli`]; shared session helpers in [`runtime`].
//!
//! NOTE ON API STABILITY: iroh's surface has moved a lot release to release
//! (NodeId → EndpointId, …). Calls match the documented 1.x API; if something
//! fails to compile, check `cargo doc -p iroh --open` before assuming the
//! overall approach is wrong.

// Unsafe is confined to audited Windows FFI modules (`win_*.rs` with
// `#![allow(unsafe_code)]`). Use `deny` (not `forbid`): crate-level `forbid`
// cannot be overridden by a module `allow`, so the Windows FFI would not
// compile. `deny` + scoped `allow` still fails the build if someone adds
// `unsafe` outside those modules — on every target, including Windows.
#![deny(unsafe_code)]

mod call;
mod cli;
mod commands;
mod config;
mod contacts;
mod exit;
mod helptext;
mod i18n;
mod identity;
mod path_kind;
mod path_stats;
mod pipe;
mod relay_probe;
mod runtime;
mod selftest;
mod socks5;
mod ssrf;
mod style;
mod tun;
mod tun_ctl;
mod tun_daemon;
mod tun_roster;
mod tun_service;
#[cfg(windows)]
mod win_eventlog;
#[cfg(windows)]
mod win_firewall;
#[cfg(windows)]
mod win_pipe;
#[cfg(windows)]
mod win_service;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!(
    "link-p2p supports Linux, macOS, and Windows only.      Please open a GitHub issue if you need another platform."
);

pub(crate) use identity::{load_or_create_secret_key, resolve_identity_path, validate_passphrase};
pub(crate) use runtime::{
    bring_endpoint_online, build_dial_addr, build_endpoint, conn_semaphore, handle_forward_stream,
    open_stream_wait, push_task, reject_relay_only_with_to_addr, spawn_path_monitor,
    spawn_reconnect_watcher, Backoff, ConnSlot, PingHandler, ServeMode, TransportTune, Ui, ALPN,
    ENDPOINT_ONLINE_STEPS, MIN_STABLE_CONN, PING_ALPN, RECONNECT_BASE, RECONNECT_MAX,
};

use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use iroh::SecretKey;
use tracing::{info, warn};

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
use crate::i18n::{tr, tr_fmt};
use crate::runtime::{merge_allow_list, resolve_peer_to};
use crate::style::{ColorMode, Styler};

fn main() {
    // Language selection + catalog load first, before any output; falls
    // back to English when the language/catalog isn't available.
    i18n::init();

    // Scan argv for --color before clap parses, so help/error output is
    // styled correctly even on the first run.
    let color_mode = style::detect_color_mode();
    let styler = style::apply_color_mode(color_mode);

    // Windows SCM must own the process main thread via
    // StartServiceCtrlDispatcher — do not nest that under #[tokio::main].
    #[cfg(windows)]
    if std::env::args_os().any(|a| a == "--windows-service") {
        if let Err(e) = win_service::run_dispatcher() {
            // SCM may have no console; also write Application Event Log.
            let msg = format!("StartServiceCtrlDispatcher / service startup failed: {e:#}");
            if let Err(log_err) = win_eventlog::error(&msg) {
                eprintln!(
                    "{}: failed to write event log: {log_err}",
                    styler.warn("warning")
                );
            }
            eprintln!("{}: {e:#}", styler.err(&tr!("error")));
            std::process::exit(exit::code_from(&e));
        }
        return;
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(real_main(color_mode));
    if let Err(e) = result {
        eprintln!("{}: {e:#}", styler.err(&tr!("error")));
        std::process::exit(exit::code_from(&e));
    }
}

async fn real_main(color_mode: ColorMode) -> Result<()> {
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

    let styler = style::apply_color_mode(color_mode);

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

// ---------------------------------------------------------------------------
// path stats + selftest helpers
// ---------------------------------------------------------------------------

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

// ping lives in commands::ping.
// ---------------------------------------------------------------------------


mod tests {
    use std::time::Duration;

    use super::{Backoff, ENDPOINT_ONLINE_STEPS};
    use crate::cli::localized_command;

    /// Every help/about text that clap derives must be overridden by
    /// `localized_command()` — otherwise the affected arg/subcommand shows
    /// untranslated English and no check catches it (the derived text is a
    /// plain string literal, not a `tr!` msgid). This walks both command
    /// trees (raw derive output vs the localized builder) and fails if any
    /// text survived unchanged, so adding an arg/subcommand without a
    /// matching mut_arg/mut_subcommand entry breaks `cargo test` instead of
    /// silently shipping English help.
    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        assert_eq!(b.next(), Duration::from_secs(1));
        assert_eq!(b.next(), Duration::from_secs(2));
        assert_eq!(b.next(), Duration::from_secs(4));
        assert_eq!(b.next(), Duration::from_secs(8));
        assert_eq!(b.next(), Duration::from_secs(16));
        // Next would be 32 -> capped at 30, and stays there.
        assert_eq!(b.next(), Duration::from_secs(30));
        assert_eq!(b.next(), Duration::from_secs(30));
        // reset() restarts from the base.
        b.reset();
        assert_eq!(b.next(), Duration::from_secs(1));
    }

    /// Handshake-then-instant-kick must not reset backoff (the bug behind
    /// thousands of redials when a relay rejects a just-opened connection).
    #[test]
    fn backoff_only_resets_after_stable_session() {
        let min = Duration::from_secs(5);
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        // Short-lived: climb 1s → 2s → 4s, never reset.
        assert_eq!(
            b.after_session(Duration::from_millis(50), min),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            b.after_session(Duration::from_millis(200), min),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            b.after_session(Duration::from_secs(4), min),
            Some(Duration::from_secs(4))
        );
        // Lived past the floor → reset; next short death starts at base again.
        assert_eq!(b.after_session(Duration::from_secs(5), min), None);
        assert_eq!(
            b.after_session(Duration::from_millis(10), min),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn endpoint_online_steps_install_relays_before_wait() {
        // Regression: wait_online-before-install_extra_relays made custom
        // --relay useless whenever n0 was unreachable (Windows lab case).
        assert_eq!(
            ENDPOINT_ONLINE_STEPS,
            &["install_extra_relays", "wait_online"]
        );
    }

    #[test]
    fn cli_help_is_fully_localized() {
        // The localized builder resolves translations via the loaded catalog,
        // so pin the language and init it before walking the tree. The shared
        // lock keeps the env mutation race-free with the i18n tests.
        //
        // Catalog is a OnceLock, so we cannot rebuild an English tree in the
        // same process. Instead require every user-facing string under zh_CN
        // to contain CJK — that catches missing .po entries even when
        // `helptext::set_help` shortens an untranslated msgid (brief ≠ full
        // English doc would otherwise make a naive assert_ne pass).
        let _guard = crate::i18n::ENV_LOCK.lock().unwrap();
        std::env::set_var("LANGUAGE", "zh_CN");
        crate::i18n::init();
        check_cmd(&localized_command(), "<root>");
        std::env::remove_var("LANGUAGE");
        std::env::set_var("LANG", "C");
        std::env::set_var("LC_ALL", "C");
        // Restore the English fallback for the rest of the test process —
        // the catalog OnceLock would otherwise keep zh_CN forever.
        crate::i18n::reset_catalog();
        crate::i18n::init();
    }

    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| {
            matches!(
                c,
                '\u{4E00}'..='\u{9FFF}' // CJK Unified Ideographs
                | '\u{3400}'..='\u{4DBF}' // Extension A
                | '\u{F900}'..='\u{FAFF}' // Compatibility Ideographs
            )
        })
    }

    fn check_cmd(loc: &clap::Command, path: &str) {
        for (tag, text) in [
            ("about", loc.get_about()),
            ("long_about", loc.get_long_about()),
            // after_help is the platform quick-start block (command examples stay
            // English by design); skip CJK check for it.
        ] {
            if let Some(t) = text {
                let s = t.to_string();
                assert!(
                    has_cjk(&s),
                    "{path}: {tag} is not localized under zh_CN:\n{s}"
                );
            }
        }

        for arg in loc.get_arguments() {
            // Hidden args (internal flags) are not user-facing help.
            if arg.is_hide_set() {
                continue;
            }
            // Built-in / structural args with no help text are skipped.
            let Some(h) = arg.get_help() else { continue };
            let id = arg.get_id();
            let hs = h.to_string();
            assert!(
                has_cjk(&hs),
                "{path}: arg --{id} short help is not localized under zh_CN:\n{hs}"
            );
            // `set_help` always attaches long_help; bare `.help()` (e.g. -V) may not.
            if let Some(lh) = arg.get_long_help() {
                let ls = lh.to_string();
                assert!(
                    has_cjk(&ls),
                    "{path}: arg --{id} long_help is not localized under zh_CN:\n{ls}"
                );
            }
        }

        for sub in loc.get_subcommands() {
            check_cmd(sub, &format!("{path} {}", sub.get_name()));
        }
    }
}
