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

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::{info, warn, Instrument};
use zeroize::Zeroize;

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

    /// Passphrase protecting the identity key file. When set, the key is
    /// stored encrypted (Argon2id + XChaCha20-Poly1305) instead of plaintext
    /// hex, so a disk/backup leak doesn't expose the key. Prefer the
    /// LINK_P2P_PASSPHRASE environment variable over passing it inline — the
    /// flag value is visible in `ps` and shell history. Conflicts with
    /// --ephemeral.
    #[arg(long, global = true, conflicts_with = "ephemeral")]
    identity_passphrase: Option<String>,

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

    /// QUIC keepalive interval in seconds (default 5). Keeps NAT UDP
    /// mappings alive; the typical home-router mapping expires after
    /// 20-30s of idle. Raise it on high-latency links, lower it where
    /// NAT timeouts are aggressive.
    #[arg(long, global = true, default_value_t = 5)]
    keepalive: u64,

    /// QUIC max idle timeout in seconds (default 30). After this long
    /// without traffic the peer is declared dead and the connection
    /// re-dialed. Raise it for lossy / high-latency links so a brief
    /// outage doesn't tear the connection down.
    #[arg(long, global = true, default_value_t = 30)]
    idle_timeout: u64,
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
        /// Only accept P2P connections from these EndpointIds (repeatable).
        /// Default: accept anyone who knows this node's EndpointId. Strongly
        /// recommended when the node is reachable from untrusted networks.
        #[arg(long)]
        allow: Vec<String>,
        /// In proxy mode, allow forwarding to private/loopback/link-local
        /// addresses (blocked by default to prevent SSRF — a malicious peer
        /// could otherwise make this node reach into your LAN or cloud
        /// metadata endpoints such as 169.254.169.254).
        #[arg(long)]
        allow_private: bool,
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
        /// Direct address hint(s) for the peer (repeatable), e.g. its public
        /// ip:port or a LAN address. Dialed directly, skipping discovery —
        /// use it when you exchanged addresses out-of-band and want no
        /// DNS/pkarr lookup (also faster reconnects). May be combined with
        /// --relay, which then stays as the fallback path.
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
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
        /// Direct address hint(s) for the peer (repeatable) — see `connect
        /// --to-addr`. Dialed directly, skipping discovery.
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
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
        /// Direct address hint(s) for the peer (repeatable) — see `connect
        /// --to-addr`. Dialed directly, skipping discovery.
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
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
            "identity_passphrase",
            |a| a.help(tr!("Passphrase protecting the identity key file. When set, the key is stored encrypted (Argon2id + XChaCha20-Poly1305) instead of plaintext hex, so a disk/backup leak doesn't expose the key. Prefer the LINK_P2P_PASSPHRASE environment variable over passing it inline — the flag value is visible in `ps` and shell history. Conflicts with --ephemeral.")),
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
        .mut_arg(
            "keepalive",
            |a| a.help(tr!("QUIC keepalive interval in seconds (default 5). Keeps NAT UDP mappings alive; the typical home-router mapping expires after 20-30s of idle. Raise it on high-latency links, lower it where NAT timeouts are aggressive.")),
        )
        .mut_arg(
            "idle_timeout",
            |a| a.help(tr!("QUIC max idle timeout in seconds (default 30). After this long without traffic the peer is declared dead and the connection re-dialed. Raise it for lossy / high-latency links so a brief outage doesn't tear the connection down.")),
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
                .mut_arg(
                    "allow",
                    |a| a.help(tr!("Only accept P2P connections from these EndpointIds (repeatable). Default: accept anyone who knows this node's EndpointId. Strongly recommended when the node is reachable from untrusted networks.")),
                )
                .mut_arg(
                    "allow_private",
                    |a| a.help(tr!("In proxy mode, allow forwarding to private/loopback/link-local addresses (blocked by default to prevent SSRF — a malicious peer could otherwise make this node reach into your LAN or cloud metadata endpoints such as 169.254.169.254).")),
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
                .mut_arg(
                    "to_addr",
                    |a| a.help(tr!("Direct address hint(s) for the peer (repeatable), e.g. its public ip:port or a LAN address. Dialed directly, skipping discovery — use it when you exchanged addresses out-of-band and want no DNS/pkarr lookup (also faster reconnects). May be combined with --relay, which then stays as the fallback path.")),
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
                        .mut_arg(
                            "to_addr",
                            |a| a.help(tr!("Direct address hint(s) for the peer (repeatable) — see `connect --to-addr`. Dialed directly, skipping discovery.")),
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
                .mut_arg(
                    "to_addr",
                    |a| a.help(tr!("Direct address hint(s) for the peer (repeatable) — see `connect --to-addr`. Dialed directly, skipping discovery.")),
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
    // Passphrase for the identity file: --identity-passphrase wins over
    // LINK_P2P_PASSPHRASE (the env var avoids the passphrase showing up in
    // `ps`/shell history). Empty values are treated as unset.
    let passphrase = cli
        .identity_passphrase
        .or_else(|| std::env::var("LINK_P2P_PASSPHRASE").ok())
        .filter(|p| !p.is_empty());
    if passphrase.is_some() {
        info!("{}", tr!("using a passphrase-protected identity key file"));
    }
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
        load_or_create_secret_key(&identity, passphrase.as_deref())
            .context(tr!("loading/creating persistent identity"))?
    };

    match cli.command {
        Command::Serve {
            forward,
            proxy,
            allow,
            allow_private,
        } => {
            if !proxy && forward.is_none() {
                anyhow::bail!(tr!("serve requires either --forward or --proxy"));
            }
            // Parse the --allow whitelist up front so a typo'd EndpointId
            // fails before we bind and wait for the network.
            let allowed = allow
                .iter()
                .map(|s| {
                    s.parse()
                        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId in --allow", s))
                })
                .collect::<Result<Vec<_>>>()?;
            run_serve(
                secret_key,
                forward,
                proxy,
                allowed,
                allow_private,
                cli.relay.as_deref(),
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                styler,
            )
            .await
        }
        Command::Connect {
            to,
            listen,
            socks5_listen,
            to_addr,
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
                to_addr,
                cli.max_conns,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
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
                    tun::run_tun_serve(
                        secret_key,
                        tun_ip,
                        mtu,
                        cli.relay.as_deref(),
                        Duration::from_secs(cli.keepalive),
                        Duration::from_secs(cli.idle_timeout),
                        styler,
                    )
                    .await
                }
                TunCommand::Connect {
                    to,
                    tun_ip,
                    mtu,
                    to_addr,
                } => {
                    tun::validate_mtu(mtu)?;
                    tun::run_tun_connect(
                        secret_key,
                        &to,
                        tun_ip,
                        mtu,
                        cli.relay.as_deref(),
                        to_addr,
                        Duration::from_secs(cli.keepalive),
                        Duration::from_secs(cli.idle_timeout),
                        styler,
                    )
                    .await
                }
            }
        }
        Command::Ping { to, to_addr } => {
            run_ping(
                secret_key,
                &to,
                cli.relay.as_deref(),
                to_addr,
                Duration::from_secs(cli.keepalive),
                Duration::from_secs(cli.idle_timeout),
                styler,
            )
            .await
        }
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
/// File magic + version for passphrase-encrypted identity keys.
/// Layout: magic | salt(16) | nonce(24) | ciphertext(64 hex chars + 16 tag).
/// The plaintext format is exactly 64 hex chars (0-9a-f) and `l` is not a hex
/// digit, so a plaintext file can never collide with this prefix.
const KEY_FILE_MAGIC: &[u8] = b"linkp2p-k1";
const KEY_FILE_SALT_LEN: usize = 16;
const KEY_FILE_NONCE_LEN: usize = 24;
const KEY_FILE_TAG_LEN: usize = 16;
const KEY_FILE_OVERHEAD: usize =
    KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN + KEY_FILE_NONCE_LEN + KEY_FILE_TAG_LEN;

/// Whether `data` looks like a passphrase-encrypted key file (vs legacy
/// plaintext hex).
fn is_encrypted_key(data: &[u8]) -> bool {
    data.starts_with(KEY_FILE_MAGIC)
}

/// Argon2id key derivation from the passphrase + per-file salt.
/// OWASP-recommended interactive-login parameters (19 MiB, t=2, p=1); the
/// salt is random per file, so the derived key is fresh on every write.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::password_hash::SaltString;
    use argon2::{Algorithm, Argon2, Params, Version};

    let salt_str = SaltString::encode_b64(salt)
        .map_err(|_| anyhow::anyhow!(tr!("encoding the passphrase salt")))?;
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|_| anyhow::anyhow!(tr!("invalid Argon2 parameters")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut dk = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_str.as_str().as_bytes(), &mut dk)
        .map_err(|_| anyhow::anyhow!(tr!("deriving key from passphrase")))?;
    Ok(dk)
}

/// Encrypt a 64-char hex key into the on-disk format (magic + salt + nonce +
/// ciphertext). XChaCha20-Poly1305 with the file magic as AAD, so a header
/// can't be swapped between files. The derived key is zeroized on return.
fn encrypt_key_hex(hex: &str, passphrase: &str) -> Result<Vec<u8>> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

    let mut salt = [0u8; KEY_FILE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; KEY_FILE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut dk = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&dk).into());
    let ciphertext = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: hex.as_bytes(),
                aad: KEY_FILE_MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!(tr!("encrypting identity file failed")))?;
    dk.zeroize();

    let mut out = Vec::with_capacity(KEY_FILE_OVERHEAD + hex.len());
    out.extend_from_slice(KEY_FILE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a key file written by [`encrypt_key_hex`], returning the 64-char
/// hex. A wrong passphrase or any tampering fails the AEAD tag check and
/// errors here.
fn decrypt_key_hex(data: &[u8], passphrase: &str) -> Result<String> {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

    if !is_encrypted_key(data) {
        bail!(tr!("identity file is not passphrase-encrypted"));
    }
    let salt = &data[KEY_FILE_MAGIC.len()..KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN];
    let nonce = &data[KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN
        ..KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN + KEY_FILE_NONCE_LEN];
    let ciphertext = &data[KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN + KEY_FILE_NONCE_LEN..];

    let mut dk = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new((&dk).into());
    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: KEY_FILE_MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!(tr!("incorrect passphrase or corrupted identity file")))?;
    dk.zeroize();
    // Plaintext is the 64-char hex; ownership moves out, caller zeroizes.
    String::from_utf8(plaintext).context(tr!("decrypted identity file is not valid UTF-8"))
}

/// Parse a 64-char hex identity blob into a [`SecretKey`], hardening the
/// file permissions along the way (covers pre-existing plaintext files).
fn secret_key_from_hex(hex: &str, path: &Path) -> Result<SecretKey> {
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
    harden_key_permissions(path)?;
    let key = SecretKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

/// Load a persisted SecretKey from `path`, or generate + save a new one.
///
/// With a passphrase the file is stored encrypted (Argon2id + XChaCha20-
/// Poly1305); without one, plaintext hex (legacy behaviour, 0600 on Unix).
/// A legacy plaintext file loaded *with* a passphrase is transparently
/// re-encrypted on disk (best-effort — if that write fails the key still
/// loads, it just stays plaintext).
///
/// Storage format: 64 hex chars (32-byte ed25519 seed). iroh 1.0
/// SecretKey does not implement Display, so we hex-encode `to_bytes()`
/// ourselves instead of relying on the old Display-based round-trip.
fn load_or_create_secret_key(path: &Path, passphrase: Option<&str>) -> Result<SecretKey> {
    if let Ok(data) = std::fs::read(path) {
        let result = if is_encrypted_key(&data) {
            // Passphrase-encrypted file: the passphrase is mandatory.
            let pass = passphrase.context(tr!(
                "identity file is passphrase-encrypted but no passphrase was provided (use --identity-passphrase or LINK_P2P_PASSPHRASE)"
            ))?;
            let mut hex = decrypt_key_hex(&data, pass).context(tr!("decrypting identity file"))?;
            let key = secret_key_from_hex(&hex, path);
            hex.zeroize();
            key
        } else {
            // Legacy plaintext hex (the only other format that exists).
            let mut hex = String::from_utf8(data)
                .context(tr!("identity file is neither plaintext hex nor encrypted"))?;
            // A passphrase on a plaintext file means "encrypt it now": load
            // the key, then rewrite the file encrypted (best-effort).
            if let Some(pass) = passphrase {
                match write_key_file_encrypted(path, hex.trim(), pass) {
                    Ok(()) => info!(
                        "{}",
                        tr!("re-encrypting the legacy plaintext identity file with the provided passphrase")
                    ),
                    Err(e) => warn!(
                        error = %e,
                        "{}",
                        tr!("could not encrypt the legacy identity file; it stays plaintext on disk")
                    ),
                }
            }
            let key = secret_key_from_hex(&hex, path);
            hex.zeroize();
            key
        };
        return result;
    }
    // No file yet: generate, then persist in the requested format.
    let key = SecretKey::generate();
    let mut hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let written = match passphrase {
        Some(pass) => write_key_file_encrypted(path, &hex, pass),
        None => write_key_file(path, &hex),
    };
    hex.zeroize();
    written?;
    Ok(key)
}

/// Open (create/truncate) the identity file with owner-only permissions on
/// Unix — no window where the key material is world-readable.
fn open_key_file_for_write(path: &Path) -> Result<std::fs::File> {
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
    opts.open(path)
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))
}

/// Write the key material to `path` as plaintext hex (legacy format). On
/// Unix the file is created with mode 0600 directly, then hardened again
/// to cover the case where the file already existed.
fn write_key_file(path: &Path, hex: &str) -> Result<()> {
    let mut file = open_key_file_for_write(path)?;
    file.write_all(hex.as_bytes())
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))?;
    harden_key_permissions(path)
}

/// Write the key material to `path` passphrase-encrypted. Same 0600
/// discipline as [`write_key_file`]; the on-disk bytes are magic + salt +
/// nonce + ciphertext, so a disk/backup leak without the passphrase yields
/// nothing.
fn write_key_file_encrypted(path: &Path, hex: &str, passphrase: &str) -> Result<()> {
    let encrypted = encrypt_key_hex(hex, passphrase)?;
    let mut file = open_key_file_for_write(path)?;
    let written = file.write_all(&encrypted);
    drop(file);
    if let Err(e) = written {
        return Err(e).with_context(|| {
            tr_fmt!(
                "writing passphrase-encrypted identity to {0}",
                path.display()
            )
        });
    }
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
/// that relay (self-hosted), skipping n0's discovery entirely — which also
/// means nothing about this node is published to iroh.link.
fn build_endpoint(
    secret_key: SecretKey,
    relay: Option<&str>,
    keepalive: Duration,
    idle_timeout: Duration,
) -> Result<iroh::endpoint::Builder> {
    let transport = transport_config(keepalive, idle_timeout)?;
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

/// Build the [`EndpointAddr`] used to dial a peer: the peer's EndpointId,
/// optionally pinned down by a custom relay URL and/or out-of-band direct
/// address hints (`--to-addr`).
///
/// Order of preference is up to iroh: the direct IP hints are tried first
/// when reachable; the relay (if given) and discovery (if no relay is given)
/// act as fallbacks for NAT traversal. Passing only direct hints and no
/// relay means no DNS/pkarr lookup happens at all — the peer is dialed
/// straight through the given addresses.
fn build_dial_addr(
    peer_id: EndpointId,
    relay: Option<&str>,
    to_addr: &[SocketAddr],
) -> Result<EndpointAddr> {
    let mut addr = match relay {
        Some(relay_url) => {
            let relay_url = relay_url
                .parse()
                .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
            EndpointAddr::new(peer_id).with_relay_url(relay_url)
        }
        // Default path: rely on n0's address discovery (DNS/pkarr) to find
        // where the peer is — unless direct hints below already say where.
        None => EndpointAddr::from(peer_id),
    };
    for a in to_addr {
        addr = addr.with_ip_addr(*a);
    }
    Ok(addr)
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
///
/// Both are CLI-tunable (`--keepalive`, `--idle-timeout`) because the right
/// value depends on the network: aggressive home-router NATs want a shorter
/// keepalive, high-latency or lossy links want a longer idle timeout.
fn transport_config(keepalive: Duration, idle_timeout: Duration) -> Result<QuicTransportConfig> {
    Ok(QuicTransportConfig::builder()
        .keep_alive_interval(keepalive)
        .max_idle_timeout(Some(idle_timeout.try_into()?))
        .build())
}

// ---------------------------------------------------------------------------
// serve: accept incoming P2P connections, forward each QUIC stream to a
// fixed local TCP target.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // CLI entry point; explicit config beats a grab-bag struct
async fn run_serve(
    secret_key: SecretKey,
    forward: Option<SocketAddr>,
    proxy: bool,
    allowed: Vec<EndpointId>,
    allow_private: bool,
    relay: Option<&str>,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout)?
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
    // The whitelist is an important security property; surface it in the
    // banner instead of hiding it in --help.
    if !allowed.is_empty() {
        println!(
            "  {}",
            styler.info(&tr_fmt!(
                "only accepting connections from {0} allowed peer(s)",
                allowed.len()
            ))
        );
    }
    if proxy && !allow_private {
        println!(
            "  {}",
            styler.warn(&tr!(
                "proxy targets in private/loopback ranges are blocked (use --allow-private to permit)"
            ))
        );
    }
    println!(
        "  {}",
        styler.dim(&tr!(
            "your EndpointId (give this to peers running `connect --to`):"
        ))
    );
    let ep_hex = endpoint.id().to_string();
    println!("    {}", styler.highlight(&ep_hex));
    println!("ENDPOINT_ID={ep_hex}");
    println!();
    println!("{}", styler.dim(&tr!("Press Ctrl+C to stop.")));

    // Every per-stream forwarder is our own spawned task; the router's
    // accept loop doesn't know about them, so keep the handles here for the
    // drain on shutdown.
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let handler = ForwardHandler {
        target: forward,
        proxy,
        allow_private,
        allowed: if allowed.is_empty() {
            None
        } else {
            Some(Arc::new(allowed.into_iter().collect()))
        },
        // 0 = unlimited. usize::MAX keeps the acquire() call shape uniform.
        semaphore: Arc::new(Semaphore::new(if max_conns == 0 {
            usize::MAX
        } else {
            max_conns
        })),
        // A second, independent cap on *connections* (not streams): an idle
        // connection costs memory + an accept task even without any stream,
        // so bound how many such connections a flood of dials can open.
        conn_semaphore: Arc::new(Semaphore::new(if max_conns == 0 {
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

/// Reject a connection with a QUIC close frame instead of silently dropping
/// it, so the peer sees a decisive error rather than a timeout. Best-effort:
/// if the connection is already dead, there's nothing to close.
fn reject_connection(connection: &Connection, peer: EndpointId) {
    warn!(%peer, "{}", tr!("rejecting connection: peer is not in the --allow list"));
    connection.close(VarInt::from_u32(0), b"peer not allowed");
}

#[derive(Debug)]
struct ForwardHandler {
    /// Fixed `--forward` target; `None` means `--proxy` mode where the
    /// destination comes from each stream's header.
    target: Option<SocketAddr>,
    /// True when running in `--proxy` mode (target comes from the header).
    proxy: bool,
    /// In proxy mode, allow targets in private/loopback/link-local ranges
    /// (blocked by default — SSRF guard, see check_proxy_target).
    allow_private: bool,
    /// Peer whitelist: `None` accepts anyone (`serve` without `--allow`),
    /// `Some(set)` rejects every connection whose EndpointId is not in it.
    allowed: Option<Arc<HashSet<EndpointId>>>,
    /// Bounds the number of concurrently forwarded streams.
    semaphore: Arc<Semaphore>,
    /// Bounds the number of concurrently *open connections* (idle ones
    /// included), independent of the stream cap.
    conn_semaphore: Arc<Semaphore>,
    /// Every spawned per-stream forwarder, so Ctrl+C can drain them
    /// (bounded, see DRAIN_TIMEOUT) instead of cutting them off mid-flush.
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ProtocolHandler for ForwardHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        info!(%peer, "{}", tr!("connection opened"));

        // Authorization: with `--allow`, only whitelisted peers get past this
        // point. iroh's QUIC handshake already authenticated the peer's key
        // (remote_id is its public identity), so this is a real check, not a
        // claim. Close the connection so the peer learns immediately.
        if let Some(allowed) = &self.allowed {
            if !allowed.contains(&peer) {
                reject_connection(&connection, peer);
                return Ok(());
            }
        }

        // Bound concurrent *connections* (not just streams): a flood of idle
        // dials would otherwise each hold an accept task + connection state
        // forever. Acquired before the accept loop; released when the whole
        // connection ends.
        let _conn_permit = match self.conn_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // semaphore closed; shouldn't happen
        };

        // One QUIC connection can carry many independent streams. Each stream
        // here corresponds to one TCP connection on the far side (see
        // run_connect below), so we keep accepting streams until the peer
        // closes the whole connection.
        spawn_path_stats_logger(connection.clone(), peer);
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
            let proxy = self.proxy;
            let allow_private = self.allow_private;
            let task = tokio::spawn(async move {
                // The permit lives as long as this stream does; dropping it
                // after handle_forward_stream frees the slot.
                let _permit = permit;
                if let Err(e) =
                    handle_forward_stream(target, proxy, allow_private, send, recv).await
                {
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
/// with plain `connect --listen`). In `--proxy` mode (`proxy: true`) read
/// the target header off the stream first — the header was written by the
/// peer's `connect --socks5-listen`.
async fn handle_forward_stream(
    forward: Option<SocketAddr>,
    proxy: bool,
    allow_private: bool,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let target = match forward {
        Some(addr) => addr,
        None => {
            if !proxy {
                unreachable!("called without a target and not in proxy mode");
            }
            let target = socks5::read_target(&mut recv).await?.resolve().await?;
            check_proxy_target(target, allow_private)?;
            target
        }
    };
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| tr_fmt!("connecting to {0}", target))?;
    pipe_streams(tcp, send, recv).await
}

/// SSRF guard for `--proxy` mode: a remote peer must not be able to make
/// this node reach into private networks (the whole point of the guard —
/// 169.254.169.254 cloud metadata, LAN services, loopback). The check runs
/// on the *resolved* address so domain names can't smuggle a private IP in.
/// `--allow-private` lifts it for trusted setups.
fn check_proxy_target(target: SocketAddr, allow_private: bool) -> Result<()> {
    if !allow_private && is_blocked_target(target) {
        bail!(tr_fmt!(
            "target {0} is in a private/loopback/link-local range; blocked in proxy mode (use --allow-private to permit)",
            target
        ));
    }
    Ok(())
}

/// Whether an address is in a range a proxy must not dial by default:
/// loopback, private (RFC 1918), link-local, unspecified, multicast and
/// broadcast for IPv4; loopback, unspecified, multicast, ULA and link-local
/// for IPv6.
fn is_blocked_target(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Log the connection's path quality every 30s until it closes, so a
/// long-running tunnel is diagnosable without waiting for a failure: UDP
/// datagram counters that grow mean a direct path is carrying traffic;
/// flat UDP + growing relay means everything is going through the relay;
/// lost_packets/bytes is the connection-level loss. Debug level — this is
/// an observability aid, not something to spam by default.
fn spawn_path_stats_logger(connection: Connection, peer: EndpointId) {
    tokio::spawn(async move {
        let mut tick = time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let s = connection.stats();
                    tracing::debug!(%peer,
                        udp_tx = s.udp_tx.datagrams,
                        udp_rx = s.udp_rx.datagrams,
                        lost_packets = s.lost_packets,
                        lost_bytes = s.lost_bytes,
                        "path stats (growing udp_tx/rx means the direct path is in use)"
                    );
                }
                _ = connection.closed() => break,
            }
        }
    });
}

// ---------------------------------------------------------------------------
// connect: dial a remote node once, then for every local TCP connection open
// a fresh QUIC stream on that same connection and pipe.
// ---------------------------------------------------------------------------

/// Reconnect backoff bounds: 1s, 2s, 4s, ... capped at 30s. Shared with the
/// TUN reconnect loop (tun.rs).
pub(crate) const RECONNECT_BASE: Duration = Duration::from_secs(1);
pub(crate) const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Exponential backoff with a cap, shared by the stream-mode reconnect
/// watcher and the TUN reconnect loop. `next()` returns the delay for the
/// *next* attempt and then advances (1s, 2s, 4s, ... capped); `reset()`
/// restarts after a successful connect.
pub(crate) struct Backoff {
    next_delay: Duration,
    base: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        Self {
            next_delay: base,
            base,
            max,
        }
    }

    pub(crate) fn next(&mut self) -> Duration {
        let d = self.next_delay;
        self.next_delay = std::cmp::min(self.next_delay * 2, self.max);
        d
    }

    pub(crate) fn reset(&mut self) {
        self.next_delay = self.base;
    }
}

/// The live QUIC connection slot shared between the reconnect watcher (the
/// only writer) and the per-stream forwarders (readers). `None` means "the
/// connection is down and we're reconnecting — new streams wait".
///
/// A `watch` channel (not a lock + poll): waiters are woken the moment the
/// watcher swaps in the new connection, so a client that arrives during a
/// reconnect window is served with zero polling delay instead of up to
/// RECONNECT_POLL of stale sleep. `watch::Sender::send` requires the value
/// to be cloneable; `Connection` is cheap to clone (an Arc inside).
#[derive(Clone)]
struct ConnSlot(Arc<watch::Sender<Option<Connection>>>);

impl ConnSlot {
    fn new(initial: Option<Connection>) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self(Arc::new(tx))
    }

    fn replace(&self, conn: Option<Connection>) {
        // send() returns Err only when all receivers are dropped — at that
        // point nobody is waiting for a reconnect anyway.
        let _ = self.0.send(conn);
    }
}

/// Open a bidi stream on the current connection, waiting through reconnect
/// windows instead of failing the local client.
///
/// - Slot empty (reconnecting): wait on the watch channel — the watcher's
///   `replace(Some(..))` wakes us the instant the new connection lands.
/// - `open_bi` fails and the connection is closed: same wait — the watcher
///   will redial and swap the slot.
/// - `open_bi` fails on a still-alive connection (e.g. stream limit): give
///   up this stream only.
async fn open_stream_wait(slot: &ConnSlot) -> Result<(SendStream, RecvStream)> {
    loop {
        // A fresh receiver per attempt: starts at the current value, so if
        // a connection is already present we never wait at all.
        let mut rx = slot.0.subscribe();
        let conn = (*rx.borrow_and_update()).clone();
        let Some(conn) = conn else {
            // Reconnecting: wait for the watcher to swap in a connection.
            // Err means the sender was dropped (process shutting down) — bail.
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            continue;
        };
        match conn.open_bi().await {
            Ok(pair) => return Ok(pair),
            Err(e) if conn.close_reason().is_some() => {
                warn!(error = %e, "{}", tr!("connection lost; waiting for reconnect"));
                // The current value is a dead connection; wait until the
                // watcher replaces it (changed() fires only on a write, so
                // this can't spin).
                rx.changed()
                    .await
                    .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
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
        let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX);
        loop {
            // Wait for the current connection to die (none yet = dial now).
            let current = (*slot.0.subscribe().borrow_and_update()).clone();
            if let Some(conn) = current {
                conn.closed().await;
            }
            // Re-dial until success, backing off exponentially.
            loop {
                match endpoint.connect(dial_addr.clone(), ALPN).await {
                    Ok(conn) => {
                        slot.replace(Some(conn));
                        info!(%peer, "{}", tr!("reconnected to peer"));
                        backoff.reset();
                        break;
                    }
                    Err(e) => {
                        let delay = backoff.next();
                        warn!(%peer, error = %e, "{}", tr_fmt!(
                            "reconnect failed; retrying in {0}",
                            format!("{delay:?}")
                        ));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)] // CLI entry point; explicit config beats a grab-bag struct
async fn run_connect(
    secret_key: SecretKey,
    to: &str,
    listen: Option<SocketAddr>,
    socks5_listen: Option<SocketAddr>,
    relay: Option<&str>,
    to_addr: Vec<SocketAddr>,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    styler: Styler,
) -> Result<()> {
    // Exactly one of --listen / --socks5-listen was validated by the caller.
    let local_addr = socks5_listen.or(listen).expect("validated");
    let is_socks5 = socks5_listen.is_some();
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout)?
        .bind()
        .await
        .context(tr!("binding endpoint"))?;
    wait_online(&endpoint).await?;

    let remote_id: EndpointId = to
        .parse()
        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId", to))?;

    let dial_addr = build_dial_addr(remote_id, relay, &to_addr)?;
    if !to_addr.is_empty() {
        println!(
            "  {}",
            styler.dim(&tr_fmt!(
                "dialing the peer's direct address hint(s): {0}",
                to_addr
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        );
    }

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

    // Seed the connection slot and start the reconnect watcher: when the
    // QUIC connection dies, it re-dials with backoff and swaps the slot.
    // The local TCP listener keeps accepting throughout — clients that
    // arrive during a reconnect wait in open_stream_wait.
    let slot = ConnSlot::new(Some(connection.clone()));
    spawn_reconnect_watcher(&slot, &endpoint, dial_addr, remote_id);
    // Same path-quality observability as the serve side.
    spawn_path_stats_logger(connection, remote_id);

    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;
    // The "connected" banner comes only after the listener is actually up —
    // printing it before bind would claim success for a port that's taken.
    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "connected. local TCP listener on {0} now forwards to the remote peer.",
            local_addr
        ))
    );

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
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout)?
        .bind()
        .await
        .context(tr!("binding endpoint"))?;
    wait_online(&endpoint).await?;

    let remote_id: EndpointId = to
        .parse()
        .with_context(|| tr_fmt!("'{0}' is not a valid EndpointId", to))?;

    let dial_addr = build_dial_addr(remote_id, relay, &to_addr)?;

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

    /// SSRF guard: private, loopback and link-local targets are blocked;
    /// public addresses pass.
    #[test]
    fn proxy_target_ssrf_guard() {
        use std::net::Ipv6Addr;
        // Blocked: loopback, RFC 1918, link-local, unspecified, multicast.
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4("10.1.2.3".parse().unwrap()),
            IpAddr::V4("172.16.0.1".parse().unwrap()),
            IpAddr::V4("172.31.255.255".parse().unwrap()),
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            IpAddr::V4("169.254.169.254".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4("224.0.0.1".parse().unwrap()),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fd12:3456::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
        ] {
            assert!(
                is_blocked_target(SocketAddr::new(ip, 80)),
                "{ip} should be blocked"
            );
        }
        // Allowed: public addresses.
        for ip in [
            IpAddr::V4("8.8.8.8".parse().unwrap()),
            IpAddr::V4("203.0.113.7".parse().unwrap()),
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            assert!(
                !is_blocked_target(SocketAddr::new(ip, 80)),
                "{ip} should pass"
            );
        }
        // The guard itself: a blocked target errors, a public one doesn't.
        assert!(check_proxy_target("127.0.0.1:80".parse().unwrap(), false).is_err());
        assert!(check_proxy_target("10.0.0.1:80".parse().unwrap(), false).is_err());
        assert!(check_proxy_target("8.8.8.8:80".parse().unwrap(), false).is_ok());
        // --allow-private lifts the block.
        assert!(check_proxy_target("127.0.0.1:80".parse().unwrap(), true).is_ok());
    }

    /// Passphrase encryption: round-trip, wrong passphrase, tampering, and
    /// non-confusability with plaintext hex.
    #[test]
    fn key_encryption_round_trip() {
        let hex = "abcdef0123456789".repeat(4); // 64 hex chars
        let encrypted = encrypt_key_hex(&hex, "hunter2").unwrap();
        assert!(is_encrypted_key(&encrypted));
        assert_eq!(encrypted.len(), KEY_FILE_OVERHEAD + 64);
        assert_eq!(decrypt_key_hex(&encrypted, "hunter2").unwrap(), hex);
    }

    #[test]
    fn key_encryption_rejects_wrong_passphrase() {
        let hex = "0123456789abcdef".repeat(4);
        let encrypted = encrypt_key_hex(&hex, "right").unwrap();
        assert!(decrypt_key_hex(&encrypted, "wrong").is_err());
    }

    #[test]
    fn key_encryption_rejects_tampered_ciphertext() {
        let hex = "0123456789abcdef".repeat(4);
        let mut encrypted = encrypt_key_hex(&hex, "hunter2").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01; // flip one ciphertext byte -> AEAD tag fails
        assert!(decrypt_key_hex(&encrypted, "hunter2").is_err());
        // Tampering with the header (salt/nonce) also fails, and swapping a
        // header between files is blocked by the AAD (magic is the AAD).
        encrypted[KEY_FILE_MAGIC.len()] ^= 0x01;
        assert!(decrypt_key_hex(&encrypted, "hunter2").is_err());
    }

    #[test]
    fn plaintext_hex_is_not_confusable_with_encrypted() {
        // 'l' (magic's first byte) is not a hex digit, so a legacy 64-char
        // plaintext file can never look encrypted.
        let plain = "0123456789abcdef".repeat(4);
        assert!(!is_encrypted_key(plain.as_bytes()));
        assert!(!is_encrypted_key(b""));
        assert!(!is_encrypted_key(b"linkp2p-k0")); // wrong version byte
    }

    #[test]
    fn identity_file_passphrase_round_trip_on_disk() {
        let dir = std::env::temp_dir().join(format!("link-p2p-keytest-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("identity.key");
        let _ = std::fs::remove_file(&path);

        // Create with a passphrase: file lands encrypted, key round-trips.
        let key1 = load_or_create_secret_key(&path, Some("s3cret")).unwrap();
        assert!(is_encrypted_key(&std::fs::read(&path).unwrap()));
        let key2 = load_or_create_secret_key(&path, Some("s3cret")).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        // Wrong passphrase and missing passphrase both fail loudly.
        assert!(load_or_create_secret_key(&path, Some("nope")).is_err());
        assert!(load_or_create_secret_key(&path, None).is_err());

        // Legacy upgrade: overwrite with plaintext hex, load with a
        // passphrase -> same key, file becomes encrypted.
        let hex: String = key1.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, &hex).unwrap();
        let key3 = load_or_create_secret_key(&path, Some("newpass")).unwrap();
        assert_eq!(key1.to_bytes(), key3.to_bytes());
        assert!(is_encrypted_key(&std::fs::read(&path).unwrap()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

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
