//! link-p2p: minimal TCP-over-QUIC port forwarder built on iroh 1.0.
//!
//! Two modes:
//!   `serve`   — expose a local TCP service (e.g. 127.0.0.1:8080) to the P2P network.
//!   `connect` — dial a remote node by its EndpointId and expose it as a local TCP port.
//!
//! This is deliberately minimal: no SOCKS5, no QoS policy file, no LD_PRELOAD hook.
//! The point is to get one real, benchmarkable QUIC hop working end to end before
//! adding any of that. See README.md for how to run and benchmark it.
//!
//! NOTE ON API STABILITY: iroh 1.0 just shipped and the surface has moved a lot
//! release to release (NodeId -> EndpointId, NodeAddr -> EndpointAddr, etc).
//! The calls below match the documented 1.0 API as of this writing. If something
//! doesn't compile, it's most likely a small signature drift — check
//! `cargo doc -p iroh --open` rather than assuming the overall approach is wrong.

mod i18n;
mod socks5;
mod style;
mod tun;

use std::io::{IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use iroh::{
    endpoint::{presets, Connection, QuicTransportConfig, RecvStream, SendStream, VarInt},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::{info, warn, Instrument};

use crate::i18n::{tr, tr_fmt};
use crate::style::{ColorMode, Styler};

/// ALPN identifies this application protocol during the QUIC/TLS handshake.
/// Bump the version suffix if you make a breaking change to the framing.
const ALPN: &[u8] = b"link-p2p/tcp-forward/0";

/// ALPN for the `ping` probe (echoes a timestamp, reports RTT and path).
/// Separate from the forwarding ALPN so a ping can target a node that is
/// also serving streams — the Router accepts both. Also registered on TUN
/// nodes (see tun.rs) so `ping` works against `tun serve` too.
pub(crate) const PING_ALPN: &[u8] = b"link-p2p/ping/0";

/// How long Ctrl+C waits for in-flight forwarded streams to flush before
/// cutting them off (used by both `serve` and `connect`).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Error code sent when we abort a QUIC stream mid-transfer (one direction
/// of a pipe failed): the peer sees an immediate reset/stop instead of
/// waiting for the idle timeout to notice the dead stream.
const STREAM_ABORT_CODE: VarInt = VarInt::from_u32(1);

#[derive(Parser)]
#[command(
    name = "link-p2p",
    version,
    about = "Minimal TCP-over-QUIC forwarder on iroh",
    long_about = "link-p2p exposes a local TCP service to a P2P network (or dials one) \
                  over a direct, end-to-end encrypted QUIC connection. No TUN device, \
                  no root/admin privileges — just a persistent EndpointId and a QUIC hop.",
    after_help = "QUICK START:\n  \
                  \x20 # On the machine you want to expose (e.g. its SSH server):\n  \
                  \x20 link-p2p serve --forward 127.0.0.1:22\n  \
                  \x20 # -> prints an EndpointId, share it with the other side\n\n  \
                  \x20 # On the connecting machine:\n  \
                  \x20 link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222\n  \
                  \x20 ssh -p 2222 localhost\n\n\
                  SHELL COMPLETIONS:\n  \
                  \x20 link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish\n  \
                  \x20 link-p2p completions bash > /etc/bash_completion.d/link-p2p\n\n\
                  See README.md for self-hosted --relay setup and benchmarking against \
                  WireGuard/Tailscale."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to store/load this node's persistent secret key. If it doesn't
    /// exist yet, a new one is generated and saved there. Default: the XDG
    /// config dir, `$XDG_CONFIG_HOME/link-p2p/identity.key` (usually
    /// `~/.config/link-p2p/identity.key`); a legacy `./identity.key` in the
    /// working directory is migrated there once. Keep this stable if you
    /// want your EndpointId to stay the same across restarts.
    #[arg(long, global = true, conflicts_with = "ephemeral")]
    identity: Option<PathBuf>,

    /// Use a temporary identity that is never written to disk: the EndpointId
    /// changes every start. Conflicts with --identity.
    #[arg(long, short = 'e', global = true, conflicts_with = "identity")]
    ephemeral: bool,

    /// Use a custom relay server instead of n0's public one, e.g.
    /// http://127.0.0.1:3340 (run `iroh-relay --dev` locally). With this set,
    /// address discovery is skipped entirely: `connect` dials the peer
    /// directly through this relay, so no DNS/pkarr lookup to iroh.link is
    /// needed. Useful for self-hosted relays and for offline/local testing.
    #[arg(long, global = true)]
    relay: Option<String>,

    /// Control colored output: auto (colors on TTY only), always, or never.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Maximum number of concurrent forwarded connections. 0 means unlimited.
    /// Prevents resource exhaustion on endpoints exposed to the network.
    #[arg(long, global = true, default_value_t = 1024)]
    max_conns: usize,

    /// Log output format: text (human-readable) or json (structured, for
    /// jq/CI pipelines).
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
}

/// Log output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Expose a local TCP service to the P2P network.
    Serve {
        /// Local address to forward incoming P2P streams to, e.g. 127.0.0.1:8080
        #[arg(long, conflicts_with = "proxy")]
        forward: Option<SocketAddr>,
        /// Generic proxy mode: dial the address from each stream's header
        /// instead of a fixed --forward target. Pairs with `connect
        /// --socks5-listen`. Conflicts with --forward.
        #[arg(long, conflicts_with = "forward")]
        proxy: bool,
    },
    /// Dial a remote node and expose it as a local TCP listener.
    Connect {
        /// The remote node's EndpointId (printed by `serve` on startup)
        #[arg(long)]
        to: String,
        /// Local address to listen on, e.g. 127.0.0.1:9090
        #[arg(long, conflicts_with = "socks5_listen")]
        listen: Option<SocketAddr>,
        /// Speak SOCKS5 (no-auth, CONNECT only) on this local address; local
        /// clients can then reach any destination through the remote
        /// `serve --proxy`. Conflicts with --listen.
        #[arg(long, conflicts_with = "listen")]
        socks5_listen: Option<SocketAddr>,
    },
    /// Make two machines reachable at the IP layer over QUIC datagrams.
    ///
    /// Creates a TUN interface (needs root / CAP_NET_ADMIN) and routes the
    /// peer's virtual IP through it. Unlike `serve`/`connect`, which forward
    /// one TCP port, this bridges the whole machine: TCP, UDP and ICMP all
    /// work on the peer's virtual IP, with no per-port setup. Point-to-point
    /// only in v1 — see docs/tun-design.md.
    Tun {
        #[command(subcommand)]
        command: TunCommand,
    },
    /// Measure RTT to a remote node over the P2P network.
    Ping {
        /// The remote node's EndpointId (printed by `serve` on startup)
        #[arg(long)]
        to: String,
    },
    /// Print a shell completion script to stdout.
    ///
    /// Redirect it to wherever your shell loads completions from, e.g.
    /// `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`.
    Completions {
        /// Which shell to generate a completion script for.
        shell: Shell,
    },
    /// Print help for link-p2p or one of its subcommands.
    //
    // (implementation detail, not user-facing: this replaces clap's built-in
    // `help` subcommand, whose description is hardcoded English and cannot be
    // localized. Handled in real_main like Completions. Kept as a single-line
    // doc so no long_about is derived that would need its own translation.)
    Help {
        /// The subcommand path to print help for, e.g. `tun serve`
        #[arg(value_name = "COMMAND")]
        sub: Vec<String>,
    },
}

/// Subcommands of `link-p2p tun`.
#[derive(Subcommand)]
enum TunCommand {
    /// Exposed side: accept a peer and bridge this machine to it at the IP
    /// layer. Prints this node's virtual IP and EndpointId, then forwards all
    /// packets to the first peer that dials.
    Serve {
        /// Override this node's virtual IP (default: derived from its
        /// EndpointId, inside 172.24.0.0/16).
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        /// Upper bound for the TUN interface MTU (default 1280). The final
        /// MTU is min(this, the negotiated QUIC datagram max); values above
        /// 1280 are refused.
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
    },
    /// Dial a peer and bridge this machine to it at the IP layer.
    Connect {
        /// The remote node's EndpointId (printed by `tun serve` on startup)
        #[arg(long)]
        to: String,
        /// Override this node's virtual IP (default: derived from its
        /// EndpointId, inside 172.24.0.0/16).
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        /// Upper bound for the TUN interface MTU (default 1280). The final
        /// MTU is min(this, the negotiated QUIC datagram max); values above
        /// 1280 are refused.
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
    },
}

/// Localized `-h/--help` argument, replacing clap's built-in one (whose
/// "Print help..." text is hardcoded English and can't be localized).
/// Applied to the top command and every subcommand, alongside
/// `disable_help_flag(true)`.
fn help_arg() -> clap::Arg {
    clap::Arg::new("help")
        .short('h')
        .long("help")
        .action(clap::ArgAction::Help)
        .help(tr!("Print help"))
}

/// Localized `-V/--version` argument, same story as [`help_arg`]. Top level
/// only (subcommands don't get a version flag).
fn version_arg() -> clap::Arg {
    clap::Arg::new("version")
        .short('V')
        .long("version")
        .action(clap::ArgAction::Version)
        .help(tr!("Print version"))
}

/// The `Command` from derive, with all display strings overridden at runtime
/// so `--help` output is localized. clap derive only accepts string literals,
/// so the structure comes from derive and the text is swapped here.
fn localized_command() -> clap::Command {
    Cli::command()
        // clap's built-in `help` subcommand hardcodes English text that
        // cannot be localized; disable it and localize the derived Help
        // variant instead (see the Command::Help doc). Same for the
        // -h/--help and -V/--version flags: replaced below with our own
        // localized arguments.
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .about(tr!("Minimal TCP-over-QUIC forwarder on iroh"))
        .long_about(tr!(
            "link-p2p exposes a local TCP service to a P2P network (or dials one) over a direct, end-to-end encrypted QUIC connection. No TUN device, no root/admin privileges — just a persistent EndpointId and a QUIC hop."
        ))
        .after_help(tr!(
            "QUICK START:\n    # On the machine you want to expose (e.g. its SSH server):\n    link-p2p serve --forward 127.0.0.1:22\n    # -> prints an EndpointId, share it with the other side\n\n    # On the connecting machine:\n    link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222\n    ssh -p 2222 localhost\n\nSHELL COMPLETIONS:\n    link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish\n    link-p2p completions bash > /etc/bash_completion.d/link-p2p\n\nSee README.md for self-hosted --relay setup and benchmarking against WireGuard/Tailscale."
        ))
        .mut_arg(
            "identity",
            |a| a.help(tr!("Path to store/load this node's persistent secret key. If it doesn't exist yet, a new one is generated and saved there. Default: the XDG config dir, $XDG_CONFIG_HOME/link-p2p/identity.key (usually ~/.config/link-p2p/identity.key); a legacy ./identity.key in the working directory is migrated there once. Keep this stable if you want your EndpointId to stay the same across restarts.")),
        )
        .mut_arg(
            "ephemeral",
            |a| a.help(tr!("Use a temporary identity that is never written to disk: the EndpointId changes every start. Conflicts with --identity.")),
        )
        .mut_arg(
            "relay",
            |a| a.help(tr!("Use a custom relay server instead of n0's public one, e.g. http://127.0.0.1:3340 (run `iroh-relay --dev` locally). With this set, address discovery is skipped entirely: `connect` dials the peer directly through this relay, so no DNS/pkarr lookup to iroh.link is needed. Useful for self-hosted relays and for offline/local testing.")),
        )
        .mut_arg(
            "color",
            |a| a.help(tr!("Control colored output: auto (colors on TTY only), always, or never.")),
        )
        .mut_arg(
            "max_conns",
            |a| a.help(tr!("Maximum number of concurrent forwarded connections. 0 means unlimited. Prevents resource exhaustion on endpoints exposed to the network.")),
        )
        .mut_arg(
            "log_format",
            |a| a.help(tr!("Log output format: text (human-readable) or json (structured, for jq/CI pipelines).")),
        )
        .mut_subcommand("serve", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Expose a local TCP service to the P2P network."))
                .mut_arg(
                    "forward",
                    |a| a.help(tr!("Local address to forward incoming P2P streams to, e.g. 127.0.0.1:8080")),
                )
                .mut_arg(
                    "proxy",
                    |a| a.help(tr!("Generic proxy mode: dial the address from each stream's header instead of a fixed --forward target. Pairs with `connect --socks5-listen`.")),
                )
        })
        .mut_subcommand("connect", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Dial a remote node and expose it as a local TCP listener."))
                .mut_arg(
                    "to",
                    |a| a.help(tr!("The remote node's EndpointId (printed by `serve` on startup)")),
                )
                .mut_arg(
                    "listen",
                    |a| a.help(tr!("Local address to listen on, e.g. 127.0.0.1:9090")),
                )
                .mut_arg(
                    "socks5_listen",
                    |a| a.help(tr!("Speak SOCKS5 (no-auth, CONNECT only) on this local address; local clients can then reach any destination through the remote `serve --proxy`.")),
                )
        })
        .mut_subcommand("tun", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Make two machines reachable at the IP layer over QUIC datagrams."))
                .long_about(tr!(
                    "Make two machines reachable at the IP layer over QUIC datagrams.\n\nCreates a TUN interface (needs root / CAP_NET_ADMIN) and routes the peer's virtual IP through it. Unlike `serve`/`connect`, which forward one TCP port, this bridges the whole machine: TCP, UDP and ICMP all work on the peer's virtual IP, with no per-port setup. Point-to-point only in v1 — see docs/tun-design.md."
                ))
                .mut_subcommand("serve", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Exposed side: accept a peer and bridge this machine to it at the IP layer."))
                        .long_about(tr!(
                            "Exposed side: accept a peer and bridge this machine to it at the IP layer. Prints this node's virtual IP and EndpointId, then forwards all packets to the first peer that dials."
                        ))
                        .mut_arg(
                            "tun_ip",
                            |a| a.help(tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16).")),
                        )
                        .mut_arg(
                            "mtu",
                            |a| a.help(tr!("Upper bound for the TUN interface MTU (default 1280). The final MTU is min(this, the negotiated QUIC datagram max); values above 1280 are refused.")),
                        )
                })
                .mut_subcommand("connect", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Dial a peer and bridge this machine to it at the IP layer."))
                        .mut_arg(
                            "to",
                            |a| a.help(tr!("The remote node's EndpointId (printed by `tun serve` on startup)")),
                        )
                        .mut_arg(
                            "tun_ip",
                            |a| a.help(tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16).")),
                        )
                        .mut_arg(
                            "mtu",
                            |a| a.help(tr!("Upper bound for the TUN interface MTU (default 1280). The final MTU is min(this, the negotiated QUIC datagram max); values above 1280 are refused.")),
                        )
                })
        })
        .mut_subcommand("ping", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Measure RTT to a remote node over the P2P network."))
                .mut_arg(
                    "to",
                    |a| a.help(tr!("The remote node's EndpointId (printed by `serve` on startup)")),
                )
        })
        .mut_subcommand("completions", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Print a shell completion script to stdout."))
                .long_about(tr!(
                    "Print a shell completion script to stdout.\n\nRedirect it to wherever your shell loads completions from, e.g. `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`."
                ))
                .mut_arg(
                    "shell",
                    |a| a.help(tr!("Which shell to generate a completion script for.")),
                )
        })
        .mut_subcommand("help", |s| {
            // Our derived Help variant replaces clap's built-in one (disabled
            // above); this is the only way to localize its description.
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Print this message or the help of the given subcommand(s)"))
                .mut_arg(
                    "sub",
                    |a| a.help(tr!("Print help for the subcommand(s)")),
                )
        })
        .arg(help_arg())
        .arg(version_arg())
}

#[tokio::main]
async fn main() {
    // Language selection + catalog load first, before any output; falls
    // back to English when the language/catalog isn't available.
    i18n::init();

    // Scan argv for --color before clap parses, so help/error output is
    // styled correctly even on the first run.
    let color_mode = style::detect_color_mode();
    let styler = style::apply_color_mode(color_mode);

    if let Err(e) = real_main(color_mode).await {
        eprintln!("{}: {e:#}", styler.err(&tr!("error")));
        std::process::exit(1);
    }
}

async fn real_main(color_mode: ColorMode) -> Result<()> {
    let matches = localized_command()
        .color(color_mode.to_clap())
        .get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    // Completions are pure stdout generation — no identity file, no logging,
    // no network. Handle it before any of that machinery spins up.
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut localized_command().color(color_mode.to_clap()),
            "link-p2p",
            &mut std::io::stdout(),
        );
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
                    eprintln!("error: unrecognized subcommand '{name}'");
                    std::process::exit(2);
                }
            };
        }
        target.print_help().context(tr!("printing help"))?;
        println!();
        return Ok(());
    }

    let log_format = cli.log_format;

    // Enable iroh's internal logging (RUST_LOG=iroh=debug etc). Without this
    // iroh's tracing events go nowhere, so RUST_LOG would be a no-op.
    //
    // Default filter is scoped rather than a blanket "info": iroh emits a
    // fair amount of info-level chatter internally (relay/discovery churn),
    // which would drown out our own connection-lifecycle logs. Explicit
    // RUST_LOG always wins, e.g. `RUST_LOG=iroh=trace` for the path-selection
    // debugging described in README.md.
    let fmt = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("link_p2p=info,iroh=warn")),
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
    // --ephemeral: an in-memory identity, nothing touches the filesystem.
    let secret_key = if cli.ephemeral {
        println!(
            "{}",
            styler.warn(&tr!(
                "ephemeral identity: this EndpointId will not persist across restarts"
            ))
        );
        SecretKey::generate()
    } else {
        let identity = resolve_identity_path(cli.identity)?;
        load_or_create_secret_key(&identity).context(tr!("loading/creating persistent identity"))?
    };

    match cli.command {
        Command::Serve { forward, proxy } => {
            if !proxy && forward.is_none() {
                anyhow::bail!(tr!("serve requires either --forward or --proxy"));
            }
            run_serve(
                secret_key,
                forward,
                cli.relay.as_deref(),
                cli.max_conns,
                styler,
            )
            .await
        }
        Command::Connect {
            to,
            listen,
            socks5_listen,
        } => {
            if listen.is_none() && socks5_listen.is_none() {
                anyhow::bail!(tr!("connect requires either --listen or --socks5-listen"));
            }
            run_connect(
                secret_key,
                &to,
                listen,
                socks5_listen,
                cli.relay.as_deref(),
                cli.max_conns,
                styler,
            )
            .await
        }
        Command::Tun { command } => {
            // TUN mode is a single point-to-point session; the stream-mode
            // concurrency cap doesn't apply. Surface that instead of letting
            // the flag silently do nothing.
            if cli.max_conns != 1024 {
                println!(
                    "{}",
                    styler.warn(&tr!(
                        "note: --max-conns is not used by TUN mode (single point-to-point session)"
                    ))
                );
            }
            match command {
                TunCommand::Serve { tun_ip, mtu } => {
                    tun::validate_mtu(mtu)?;
                    tun::run_tun_serve(secret_key, tun_ip, mtu, cli.relay.as_deref(), styler).await
                }
                TunCommand::Connect { to, tun_ip, mtu } => {
                    tun::validate_mtu(mtu)?;
                    tun::run_tun_connect(secret_key, &to, tun_ip, mtu, cli.relay.as_deref(), styler)
                        .await
                }
            }
        }
        Command::Ping { to } => run_ping(secret_key, &to, cli.relay.as_deref(), styler).await,
        Command::Completions { .. } => unreachable!("handled above"),
        Command::Help { .. } => unreachable!("handled above"),
    }
}

/// Resolve the identity file path: an explicit `--identity` wins; otherwise
/// the XDG config location. A legacy `./identity.key` in the working
/// directory (pre-XDG versions kept it there) is migrated to the XDG
/// location once, so existing EndpointIds stay stable across the move.
fn resolve_identity_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let xdg = default_identity_path();
    if xdg.exists() {
        return Ok(xdg);
    }
    let legacy = PathBuf::from("identity.key");
    if !legacy.exists() {
        return Ok(xdg);
    }
    match migrate_identity(&legacy, &xdg) {
        Ok(()) => {
            info!(
                "{}",
                tr_fmt!(
                    "migrated legacy identity from {0} to {1}",
                    legacy.display(),
                    xdg.display()
                )
            );
            Ok(xdg)
        }
        Err(e) => {
            // Keep the EndpointId stable: fall back to the legacy file
            // rather than silently generating a brand-new identity.
            warn!(error = %e, "{}", tr!("identity migration failed; using the legacy file"));
            Ok(legacy)
        }
    }
}

/// The XDG config location for the identity key:
/// `$XDG_CONFIG_HOME/link-p2p/identity.key`, or `~/.config/link-p2p/...`
/// when `XDG_CONFIG_HOME` is unset. Falls back to `./identity.key` if
/// neither `XDG_CONFIG_HOME` nor `HOME` is set.
fn default_identity_path() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(base).join("link-p2p").join("identity.key");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home)
            .join(".config")
            .join("link-p2p")
            .join("identity.key");
    }
    PathBuf::from("identity.key")
}

/// Copy the legacy identity file to the XDG location (directory created as
/// needed), keeping the key material and thus the EndpointId intact.
fn migrate_identity(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating identity directory {0}", parent.display()))?;
    }
    std::fs::copy(from, to).with_context(|| {
        tr_fmt!(
            "migrating legacy identity from {0} to {1}",
            from.display(),
            to.display()
        )
    })?;
    harden_key_permissions(to)?;
    // The key material is now safely at its XDG home; drop the legacy copy
    // so the private key doesn't linger in the working directory.
    if let Err(e) = std::fs::remove_file(from) {
        warn!(error = %e, "{}", tr_fmt!(
            "could not remove the legacy identity file {0} (you can delete it manually)",
            from.display()
        ));
    }
    Ok(())
}

/// Load a persisted SecretKey from `path`, or generate + save a new one.
///
/// Storage format: 64 hex chars (32-byte ed25519 seed). iroh 1.0
/// SecretKey does not implement Display, so we hex-encode `to_bytes()`
/// ourselves instead of relying on the old Display-based round-trip.
///
/// On Unix the key file is always tightened to mode 0600 (owner-only): it's
/// a private key, and `std::fs::write` would otherwise create it with the
/// default umask-derived permissions (usually 0644, world-readable).
fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
    if let Ok(hex) = std::fs::read_to_string(path) {
        let hex = hex.trim();
        if hex.len() != 64 {
            anyhow::bail!(tr_fmt!(
                "identity file exists but has unexpected length {0} (expected 64 hex chars)",
                hex.len()
            ));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .context(tr!("identity file exists but contains non-hex characters"))?;
        }
        // Also harden pre-existing files (older versions wrote them 0644).
        harden_key_permissions(path)?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    write_key_file(path, &hex)?;
    Ok(key)
}

/// Write the key material to `path`. On Unix the file is created with mode
/// 0600 directly (no window where it's world-readable), then hardened again
/// to cover the case where the file already existed.
fn write_key_file(path: &Path, hex: &str) -> Result<()> {
    // The XDG default lives under a per-app config dir that may not exist
    // yet; create it so the very first run can persist the new key.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating identity directory {0}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))?;
    file.write_all(hex.as_bytes())
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))?;
    harden_key_permissions(path)
}

/// Ensure the key file is owner-only (0600) on Unix. No-op elsewhere.
#[cfg(unix)]
fn harden_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| tr_fmt!("setting permissions on {0}", path.display()))
}

#[cfg(not(unix))]
fn harden_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Wait up to `timeout` for the endpoint to establish a network path
/// (relay and/or direct address discovery). If it times out, the most
/// common cause is a firewall silently dropping outgoing UDP — QUIC needs
/// UDP, and many container/CI/corporate network policies only allow TCP.
///
/// Quick check: `nc -u -v -w3 8.8.8.8 53` should get a response. If it
/// hangs or is refused, UDP outbound is blocked.
async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    const ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
    time::timeout(ONLINE_TIMEOUT, endpoint.online())
        .await
        .context(tr_fmt!(
            "endpoint did not come online within {0}.\n\
             \n\
             The most likely cause: outgoing UDP is blocked by a firewall.\n\
             iroh/QUIC relies on UDP for both direct hole-punching and\n\
             relay connections. Try:\n\
               nc -u -v -w3 8.8.8.8 53    # does UDP egress work at all?\n\
               RUST_LOG=iroh=debug {1}     # see exactly where it's stuck",
            format!("{ONLINE_TIMEOUT:?}"),
            std::env::args().next().unwrap_or_else(|| "link-p2p".into())
        ))?;
    Ok(())
}

/// Build an endpoint with the given identity.
///
/// With `relay: None` this uses [`presets::N0`]: n0's public relay servers
/// plus DNS/pkarr address discovery. With `relay: Some(url)` it uses only
/// that relay (self-hosted), skipping n0's discovery entirely.
fn build_endpoint(secret_key: SecretKey, relay: Option<&str>) -> Result<iroh::endpoint::Builder> {
    let transport = transport_config()?;
    match relay {
        Some(relay_url) => {
            // Minimal sets only the mandatory crypto provider; we configure
            // everything else ourselves. Custom relay map from the given URL.
            let relay_map = RelayMap::try_from_iter([relay_url])
                .with_context(|| tr_fmt!("'{0}' is not a valid --relay URL", relay_url))?;
            Ok(Endpoint::builder(presets::Minimal)
                .secret_key(secret_key)
                .transport_config(transport)
                .relay_mode(RelayMode::Custom(relay_map)))
        }
        None => Ok(Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .transport_config(transport)),
    }
}

/// QUIC transport parameters shared by every mode.
///
/// The keepalive interval keeps NAT UDP mappings alive: they typically
/// expire after 20-30s, so a tunnel idle for longer than that would be
/// silently dropped by intermediate devices. 5s is also iroh's own default;
/// it's set here explicitly so the contract is self-documenting.
///
/// The idle timeout is relaxed from iroh's 15s default to 30s: a longer
/// window lets the peer survive brief path switches (iroh connection
/// migration) and relay hiccups without being declared dead, while still
/// detecting a genuinely gone peer within a reasonable time.
fn transport_config() -> Result<QuicTransportConfig> {
    Ok(QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_secs(5))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
        .build())
}

// ---------------------------------------------------------------------------
// serve: accept incoming P2P connections, forward each QUIC stream to a
// fixed local TCP target.
// ---------------------------------------------------------------------------

async fn run_serve(
    secret_key: SecretKey,
    forward: Option<SocketAddr>,
    relay: Option<&str>,
    max_conns: usize,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay)?
        .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
        .bind()
        .await
        .context(tr!("binding endpoint"))?;

    wait_online(&endpoint).await?;

    println!("{}", styler.banner("link-p2p serve"));
    match forward {
        Some(target) => println!(
            "  {}",
            tr_fmt!("forwarding P2P connections to: {0}", target)
        ),
        None => println!(
            "  {}",
            styler.info(&tr!(
                "proxy mode: dialing the target address from each stream's header"
            ))
        ),
    }
    println!(
        "  {}",
        styler.dim(&tr!(
            "your EndpointId (give this to peers running `connect --to`):"
        ))
    );
    println!("    {}", styler.highlight(&endpoint.id().to_string()));
    println!();
    println!("{}", styler.dim(&tr!("Press Ctrl+C to stop.")));

    // Every per-stream forwarder is our own spawned task; the router's
    // accept loop doesn't know about them, so keep the handles here for the
    // drain on shutdown.
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let handler = ForwardHandler {
        target: forward,
        // 0 = unlimited. usize::MAX keeps the acquire() call shape uniform.
        semaphore: Arc::new(Semaphore::new(if max_conns == 0 {
            usize::MAX
        } else {
            max_conns
        })),
        tasks: tasks.clone(),
    };
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, handler)
        .accept(PING_ALPN, PingHandler)
        .spawn();

    tokio::signal::ctrl_c().await?;
    println!("{}", styler.warn(&tr!("shutting down...")));
    router.shutdown().await?;
    // router.shutdown() only stops the router's own accept loop — the
    // per-stream forwarders are our tasks, so give them the same bounded
    // drain window as run_connect.
    let pending = std::mem::take(&mut *tasks.lock().unwrap());
    let drain_deadline = tokio::time::sleep(DRAIN_TIMEOUT);
    tokio::pin!(drain_deadline);
    for task in pending {
        tokio::select! {
            _ = task => {}
            _ = &mut drain_deadline => break,
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ForwardHandler {
    /// Fixed `--forward` target; `None` means `--proxy` mode where the
    /// destination comes from each stream's header.
    target: Option<SocketAddr>,
    /// Bounds the number of concurrently forwarded streams.
    semaphore: Arc<Semaphore>,
    /// Every spawned per-stream forwarder, so Ctrl+C can drain them
    /// (bounded, see DRAIN_TIMEOUT) instead of cutting them off mid-flush.
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ProtocolHandler for ForwardHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        info!(%peer, "{}", tr!("connection opened"));

        // One QUIC connection can carry many independent streams. Each stream
        // here corresponds to one TCP connection on the far side (see
        // run_connect below), so we keep accepting streams until the peer
        // closes the whole connection.
        loop {
            // Bound the number of concurrently forwarded streams. We acquire
            // the permit *before* accept_bi so a hostile peer flooding streams
            // can't make us spawn unbounded tasks/sockets: the extra streams
            // just queue up at the QUIC layer until a slot frees.
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed; shouldn't happen
            };
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    // This fires both on a clean shutdown (peer closed the
                    // connection) and on real transport errors. iroh doesn't
                    // give us a cheap way to tell those apart here, so log
                    // unconditionally rather than silently dropping real
                    // failures — a clean close is just a bit of harmless noise.
                    warn!(%peer, error = %e, "{}", tr!("connection ended"));
                    break;
                }
            };
            let target = self.target;
            let task = tokio::spawn(async move {
                // The permit lives as long as this stream does; dropping it
                // after handle_forward_stream frees the slot.
                let _permit = permit;
                if let Err(e) = handle_forward_stream(target, send, recv).await {
                    warn!(%peer, error = %e, "{}", tr!("stream error"));
                }
            });
            self.tasks.lock().unwrap().push(task);
        }

        connection.closed().await;
        info!(%peer, "{}", tr!("connection closed"));
        Ok(())
    }
}

/// Handle `link-p2p ping` probes: echo the 8-byte timestamp back over a
/// one-shot bidi stream so the caller can measure RTT. `pub(crate)` so TUN
/// nodes (tun.rs) can answer probes too.
#[derive(Debug)]
pub(crate) struct PingHandler;

impl ProtocolHandler for PingHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // connection ended
            };
            let mut ts = [0u8; 8];
            if recv.read_exact(&mut ts).await.is_err() {
                continue;
            }
            if send.write_all(&ts).await.is_err() {
                continue;
            }
            let _ = send.finish();
        }
        Ok(())
    }
}

/// Dial the target and pipe bytes between it and the given QUIC stream.
///
/// With a fixed `--forward` target, dial it directly (backwards compatible
/// with plain `connect --listen`). In `--proxy` mode (`forward: None`) read
/// the target header off the stream first — the header was written by the
/// peer's `connect --socks5-listen`.
async fn handle_forward_stream(
    forward: Option<SocketAddr>,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let target = match forward {
        Some(addr) => addr,
        None => socks5::read_target(&mut recv).await?.resolve().await?,
    };
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| tr_fmt!("connecting to {0}", target))?;
    pipe_streams(tcp, send, recv).await
}

// ---------------------------------------------------------------------------
// connect: dial a remote node once, then for every local TCP connection open
// a fresh QUIC stream on that same connection and pipe.
// ---------------------------------------------------------------------------

/// Reconnect backoff bounds: 1s, 2s, 4s, ... capped at 30s. Shared with the
/// TUN reconnect loop (tun.rs).
pub(crate) const RECONNECT_BASE: Duration = Duration::from_secs(1);
pub(crate) const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// How often a stream waiting for a reconnect re-checks the connection slot.
/// Polling beats notify-waiting here: a notification racing past the wait
/// registration would hang the waiter, a poll cannot miss. 200ms is a
/// negligible price next to the >=1s reconnect backoff.
const RECONNECT_POLL: Duration = Duration::from_millis(200);

/// The live QUIC connection slot shared between the reconnect watcher (the
/// only writer) and the per-stream forwarders (readers). `None` means "the
/// connection is down and we're reconnecting — new streams wait".
#[derive(Clone)]
struct ConnSlot(Arc<RwLock<Option<Connection>>>);

/// Open a bidi stream on the current connection, waiting through reconnect
/// windows instead of failing the local client.
///
/// - Slot empty (reconnecting): poll until the watcher replaces it.
/// - `open_bi` fails and the connection is closed: the watcher will redial;
///   wait rather than fail the stream.
/// - `open_bi` fails on a still-alive connection (e.g. stream limit): give
///   up this stream only.
async fn open_stream_wait(slot: &ConnSlot) -> Result<(SendStream, RecvStream)> {
    loop {
        let conn = slot.0.read().await.as_ref().cloned();
        let Some(conn) = conn else {
            tokio::time::sleep(RECONNECT_POLL).await;
            continue;
        };
        match conn.open_bi().await {
            Ok(pair) => return Ok(pair),
            Err(e) if conn.close_reason().is_some() => {
                warn!(error = %e, "{}", tr!("connection lost; waiting for reconnect"));
                tokio::time::sleep(RECONNECT_POLL).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Reconnect watcher: waits for the current connection to die, then re-dials
/// with exponential backoff, swapping the slot on success.
///
/// Runs for the lifetime of the process. Deliberately NOT tracked in the
/// shutdown drain (`tasks`): it never finishes on its own, and the process
/// exits right after the drain anyway.
///
/// Scope note: this reconnects the QUIC *connection*; process-level restarts
/// are the systemd unit's job (contrib/systemd), they don't mix.
fn spawn_reconnect_watcher(
    slot: &ConnSlot,
    endpoint: &Endpoint,
    dial_addr: EndpointAddr,
    peer: EndpointId,
) {
    let slot = slot.clone();
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        loop {
            // Wait for the current connection to die (none yet = dial now).
            let current = slot.0.read().await.as_ref().cloned();
            if let Some(conn) = current {
                conn.closed().await;
            }
            // Re-dial until success, backing off exponentially.
            let mut delay = RECONNECT_BASE;
            loop {
                match endpoint.connect(dial_addr.clone(), ALPN).await {
                    Ok(conn) => {
                        *slot.0.write().await = Some(conn);
                        info!(%peer, "{}", tr!("reconnected to peer"));
                        break;
                    }
                    Err(e) => {
                        warn!(%peer, error = %e, "{}", tr_fmt!(
                            "reconnect failed; retrying in {0}",
                            format!("{delay:?}")
                        ));
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, RECONNECT_MAX);
                    }
                }
            }
        }
    });
}

async fn run_connect(
    secret_key: SecretKey,
    to: &str,
    listen: Option<SocketAddr>,
    socks5_listen: Option<SocketAddr>,
    relay: Option<&str>,
    max_conns: usize,
    styler: Styler,
) -> Result<()> {
    // Exactly one of --listen / --socks5-listen was validated by the caller.
    let local_addr = socks5_listen.or(listen).expect("validated");
    let is_socks5 = socks5_listen.is_some();
    let endpoint = build_endpoint(secret_key, relay)?
        .bind()
        .await
        .context(tr!("binding endpoint"))?;
    wait_online(&endpoint).await?;

    let remote_id: EndpointId = to
        .parse()
        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId", to))?;

    let dial_addr = match relay {
        // With a custom relay we know exactly where the peer is: dial it
        // through this relay, no DNS/pkarr lookup needed.
        Some(relay_url) => {
            let relay_url = relay_url
                .parse()
                .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
            EndpointAddr::new(remote_id).with_relay_url(relay_url)
        }
        // Default path: rely on n0's address discovery (DNS/pkarr) to find
        // where the peer is.
        None => EndpointAddr::from(remote_id),
    };

    println!("{}", styler.info(&tr_fmt!("dialing {0}...", remote_id)));
    // Time the handshake. Deliberately a structured event, not a span:
    // iroh spawns long-lived internal tasks during connect() that inherit
    // the current span (tokio::spawn captures it), which would keep the span
    // open for the whole connection lifetime and never emit a close event.
    let start = std::time::Instant::now();
    let connection = endpoint
        .connect(dial_addr.clone(), ALPN)
        .await
        .context(tr!("connecting to remote endpoint"))?;
    tracing::debug!(
        peer = %remote_id,
        elapsed_ms = start.elapsed().as_millis() as u64,
        "dial completed"
    );
    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "connected. local TCP listener on {0} now forwards to the remote peer.",
            local_addr
        ))
    );

    // Seed the connection slot and start the reconnect watcher: when the
    // QUIC connection dies, it re-dials with backoff and swaps the slot.
    // The local TCP listener keeps accepting throughout — clients that
    // arrive during a reconnect wait in open_stream_wait.
    let slot = ConnSlot(Arc::new(RwLock::new(Some(connection))));
    spawn_reconnect_watcher(&slot, &endpoint, dial_addr, remote_id);

    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;

    // Same concurrency bound as serve. Here the permit is acquired *inside*
    // the spawned task so the accept loop stays responsive: excess local
    // connections queue in the kernel backlog, and only `max_conns` of them
    // are actively forwarded at any time.
    let semaphore = Arc::new(Semaphore::new(if max_conns == 0 {
        usize::MAX
    } else {
        max_conns
    }));

    // Track every spawned forwarder so Ctrl+C can drain them (bounded)
    // instead of dropping them mid-flush.
    let mut tasks = Vec::new();

    loop {
        tokio::select! {
            accepted = tcp_listener.accept() => {
                let (mut tcp_stream, client_addr) = accepted?;
                let slot = slot.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let result = async {
                        if is_socks5 {
                            // SOCKS5 mode: parse the local client's CONNECT
                            // request, then tell the remote `serve --proxy`
                            // where to dial via the stream header. The
                            // handshake happens before the permit so a client
                            // that never completes it doesn't hold a slot.
                            let target = socks5::accept_handshake(&mut tcp_stream).await?;
                            let _permit = semaphore.acquire_owned().await?;
                            let (mut send, recv) = open_stream_wait(&slot).await?;
                            socks5::write_target(&mut send, &target).await?;
                            pipe_streams(tcp_stream, send, recv).await
                        } else {
                            // Plain mode: forward to the remote serve's
                            // fixed --forward target.
                            let _permit = semaphore.acquire_owned().await?;
                            let (send, recv) = open_stream_wait(&slot).await?;
                            pipe_streams(tcp_stream, send, recv).await
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        warn!(%client_addr, error = %e, "{}", tr!("stream error"));
                    }
                }));
            }
            _ = tokio::signal::ctrl_c() => {
                // Stop accepting new local connections.
                println!("{}", styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }
    // Graceful drain: give in-flight streams a bounded window to flush their
    // last bytes before the runtime is torn down, instead of cutting them off
    // the instant the process exits. Long-running streams are cut at the
    // timeout (DRAIN_TIMEOUT).
    let drain_deadline = tokio::time::sleep(DRAIN_TIMEOUT);
    tokio::pin!(drain_deadline);
    for task in tasks {
        tokio::select! {
            _ = task => {}
            _ = &mut drain_deadline => break,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ping: measure RTT to a remote node and report the path (direct or relay).
// ---------------------------------------------------------------------------

/// `link-p2p ping`: dial with the ping ALPN, exchange an 8-byte timestamp over
/// a one-shot stream, and report RTT plus the connection's current path.
async fn run_ping(
    secret_key: SecretKey,
    to: &str,
    relay: Option<&str>,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay)?
        .bind()
        .await
        .context(tr!("binding endpoint"))?;
    wait_online(&endpoint).await?;

    let remote_id: EndpointId = to
        .parse()
        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId", to))?;

    let dial_addr = match relay {
        Some(relay_url) => {
            let relay_url = relay_url
                .parse()
                .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
            EndpointAddr::new(remote_id).with_relay_url(relay_url)
        }
        None => EndpointAddr::from(remote_id),
    };

    println!("{}", styler.info(&tr_fmt!("pinging {0}...", remote_id)));
    let connection = endpoint
        .connect(dial_addr, PING_ALPN)
        .await
        .context(tr!("connecting to remote endpoint"))?;

    let start = std::time::Instant::now();
    let (mut send, mut recv) = connection.open_bi().await?;
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    send.write_all(&ts_ms.to_be_bytes()).await?;
    send.finish()?;
    let mut echo = [0u8; 8];
    recv.read_exact(&mut echo).await?;
    let rtt_us = start.elapsed().as_micros() as u64;
    if i64::from_be_bytes(echo) != ts_ms {
        bail!(tr!("peer echoed a mismatched ping timestamp"));
    }

    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "pong from {0}: RTT {1}µs",
            remote_id.fmt_short(),
            rtt_us
        ))
    );
    // iroh 1.0.3 exposes no "current path" query on an established
    // Connection, so classify via the stats: a direct path carries UDP, a
    // relay-only path carries everything over the relay's TCP/WebSocket.
    let stats = connection.stats();
    if stats.udp_tx.datagrams + stats.udp_rx.datagrams > 0 {
        println!("  {}", styler.dim(&tr!("path: direct (UDP)")));
    } else {
        println!(
            "  {}",
            styler.dim(&tr!("path: relay (no direct UDP path yet)"))
        );
    }
    // Close gracefully instead of dropping the socket (avoids iroh's
    // ungraceful-drop error and lets the peer's session end immediately).
    endpoint.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// shared: bidirectional copy between a TCP socket and a QUIC stream pair.
// ---------------------------------------------------------------------------

async fn pipe_streams(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let span = tracing::debug_span!(
        "pipe",
        sent_bytes = tracing::field::Empty,
        recv_bytes = tracing::field::Empty
    );
    let record_span = span.clone();
    let fut = async move {
        let (mut tcp_read, mut tcp_write) = tcp.into_split();

        let client_to_remote = async {
            let n = copy(&mut tcp_read, &mut send).await?;
            // Signal "no more data" on the QUIC send side so the peer's
            // tokio::io::copy on its end returns instead of hanging forever.
            send.finish().context(tr!("finishing send stream"))?;
            Ok::<_, anyhow::Error>(n)
        };
        let remote_to_client = async {
            let r = copy(&mut recv, &mut tcp_write).await;
            // The stream side is done (EOF or error): signal EOF to the local TCP
            // peer explicitly. Relying on the write half being dropped at function
            // exit would delay the FIN until *both* directions finish, which
            // never happens when the peer keeps the connection open.
            let _ = tcp_write.shutdown().await;
            r
        };

        // Run both directions concurrently. A half-closed TCP connection (client
        // stops writing but still reads, or vice versa) is common and shouldn't be
        // treated as an error on its own, so a *clean* completion of one direction
        // must not cancel the other. An *error* in either direction, however,
        // should abort the whole pipe promptly rather than waiting for the other
        // side to give up on its own.
        let mut client_to_remote = Box::pin(client_to_remote);
        let mut remote_to_client = Box::pin(remote_to_client);
        let (mut res_client, mut res_remote) = (None, None);
        while res_client.is_none() || res_remote.is_none() {
            tokio::select! {
                r = &mut client_to_remote, if res_client.is_none() => {
                    res_client = Some(r);
                    if res_client.as_ref().unwrap().is_err() { break; }
                }
                r = &mut remote_to_client, if res_remote.is_none() => {
                    res_remote = Some(r);
                    if res_remote.as_ref().unwrap().is_err() { break; }
                }
            }
        }
        // The futures above hold `&mut` borrows of send/recv; drop them to
        // release the borrows before the error path touches those streams.
        drop(client_to_remote);
        drop(remote_to_client);
        match (res_client, res_remote) {
            (Some(a), Some(b)) => {
                let sent = a?;
                let recvd = b?;
                record_span.record("sent_bytes", sent);
                record_span.record("recv_bytes", recvd);
                Ok(())
            }
            // One direction errored; the other was cancelled by the select! drop.
            // Tell the peer explicitly instead of letting the stream half just
            // drop: a RESET/STOP propagates immediately, whereas a silently
            // dropped stream only becomes visible to the peer once the idle
            // timeout fires (which is the point of task 1's keepalive work —
            // the reset makes abnormal teardown cheap). Best-effort: if the
            // stream is already closed, there's nothing to signal.
            (Some(a), None) => {
                // client→remote copy failed (send side broke): stop reading
                // from the peer so it doesn't keep pushing data into a dead pipe.
                let _ = recv.stop(STREAM_ABORT_CODE);
                a.map(|_| ())
            }
            (None, Some(b)) => {
                // remote→client copy failed (recv side broke): reset our send
                // half so the peer's read fails immediately instead of hanging.
                let _ = send.reset(STREAM_ABORT_CODE);
                b.map(|_| ())
            }
            (None, None) => unreachable!("loop exits only when both complete or one errors"),
        }
    };
    fut.instrument(span).await
}

async fn copy<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(reader, writer)
        .await
        .context(tr!("copying stream data"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every help/about text that clap derives must be overridden by
    /// `localized_command()` — otherwise the affected arg/subcommand shows
    /// untranslated English and no check catches it (the derived text is a
    /// plain string literal, not a `tr!` msgid). This walks both command
    /// trees (raw derive output vs the localized builder) and fails if any
    /// text survived unchanged, so adding an arg/subcommand without a
    /// matching mut_arg/mut_subcommand entry breaks `cargo test` instead of
    /// silently shipping English help.
    #[test]
    fn cli_help_is_fully_localized() {
        // The localized builder resolves translations via the loaded catalog,
        // so pin the language and init it before comparing the trees. The
        // shared lock keeps the env mutation race-free with the i18n tests.
        let _guard = crate::i18n::ENV_LOCK.lock().unwrap();
        std::env::set_var("LANGUAGE", "zh_CN");
        crate::i18n::init();
        std::env::remove_var("LANGUAGE");
        check_cmd(&Cli::command(), &localized_command(), "<root>");
    }

    fn check_cmd(raw: &clap::Command, loc: &clap::Command, path: &str) {
        // Command-level texts. Only texts present in the raw tree are checked
        // (localized must not drop or fail to translate them).
        for (tag, r, l) in [
            ("about", raw.get_about(), loc.get_about()),
            ("long_about", raw.get_long_about(), loc.get_long_about()),
            ("after_help", raw.get_after_help(), loc.get_after_help()),
        ] {
            if let Some(r) = r {
                let l = l.unwrap_or_else(|| panic!("{path}: {tag} missing in localized tree"));
                assert_ne!(
                    r.to_string(),
                    l.to_string(),
                    "{path}: {tag} was not localized"
                );
            }
        }

        // Per-argument help, matched by arg id. A pair that can't be matched
        // (e.g. the built-in help subcommand's "subcommand" arg vs our
        // derived "sub") is skipped — the check that matters is: same id in
        // both trees => help must have been translated.
        for arg in raw.get_arguments() {
            let Some(rh) = arg.get_help() else { continue };
            let Some(l) = loc.get_arguments().find(|a| a.get_id() == arg.get_id()) else {
                continue;
            };
            let lh = l.get_help().unwrap_or_else(|| {
                panic!(
                    "{path}: arg {} lost its help in the localized tree",
                    arg.get_id()
                )
            });
            assert_ne!(
                rh.to_string(),
                lh.to_string(),
                "{path}: arg --{} help was not localized",
                arg.get_id()
            );
        }

        // Recurse into subcommands, matched by name.
        for sub in raw.get_subcommands() {
            let Some(l) = loc
                .get_subcommands()
                .find(|s| s.get_name() == sub.get_name())
            else {
                continue;
            };
            check_cmd(sub, l, &format!("{path} {}", sub.get_name()));
        }
    }
}
