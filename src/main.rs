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

mod call;
mod config;
mod contacts;
mod exit;
mod helptext;
mod i18n;
mod path_kind;
mod pipe;
mod relay_probe;
mod socks5;
mod ssrf;
mod style;
mod tun;
mod tun_roster;

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use iroh::{
    endpoint::{presets, Connection, QuicTransportConfig, RecvStream, SendStream, VarInt},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
};
use noq_proto::congestion::{Bbr3Config, CubicConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::i18n::{tr, tr_fmt};
use crate::ssrf::check_proxy_target;
use crate::style::{ColorMode, Styler};

/// ALPN identifies this application protocol during the QUIC/TLS handshake.
/// `/1` requires a 4-byte [`pipe::STREAM_HELLO`] on every fixed-forward stream
/// so `open_bi()` becomes visible on the wire (QUIC has no stream-open frame).
/// Mismatch must fail handshake — do not route `/0` and `/1` together.
const ALPN: &[u8] = b"link-p2p/tcp-forward/1";

/// ALPN for the `ping` probe (echoes a timestamp, reports RTT and path).
/// Separate from the forwarding ALPN so a ping can target a node that is
/// also serving streams — the Router accepts both. Also registered on TUN
/// nodes (see tun.rs) so `ping` works against `tun serve` too.
pub(crate) const PING_ALPN: &[u8] = b"link-p2p/ping/0";

#[derive(Parser)]
#[command(
    name = "link-p2p",
    version,
    about = "Minimal TCP-over-QUIC forwarder on iroh",
    long_about = "link-p2p exposes a local TCP service to a P2P network (or dials one) \
                  over a direct, end-to-end encrypted QUIC connection. No TUN device, \
                  no root/admin privileges — just a persistent EndpointId and a QUIC hop.",
    after_help = "See README.md and docs/windows.md (Windows) or docs/unix.md (Unix)."
)]
#[allow(clippy::struct_excessive_bools)]
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

    /// Custom relay URL(s), repeatable. Replaces n0's default map when set
    /// (skips n0 DNS/pkarr). Pass several for failover, e.g. a self-hosted
    /// relay first then an n0 URL as backup. **Does not disable hole-punch** —
    /// use `--relay-only` for a true relay-only baseline. Also
    /// `LINK_P2P_RELAY` (comma-separated; flag wins / appends).
    #[arg(long, global = true, env = "LINK_P2P_RELAY", value_delimiter = ',', action = ArgAction::Append)]
    relay: Vec<String>,

    /// Disable IP transports so traffic stays on relay (no hole-punch / LAN
    /// direct). Both sides of a session must set this for a reliable
    /// relay-only baseline. Conflicts with `--to-addr` (direct hints). Also
    /// `LINK_P2P_RELAY_ONLY=1`.
    #[arg(long, global = true, env = "LINK_P2P_RELAY_ONLY", default_value_t = false)]
    relay_only: bool,

    /// When `--relay` is set, do **not** keep n0's public relays / discovery
    /// (replace the map entirely). Default is to **merge** custom relays into
    /// n0 so self-hosted + public failover both work. Also `LINK_P2P_NO_N0_RELAYS`.
    #[arg(long = "no-n0-relays", global = true, env = "LINK_P2P_NO_N0_RELAYS", default_value_t = false)]
    no_n0_relays: bool,

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

    /// Quiet user-facing banners (errors still print). Independent of
    /// `RUST_LOG` / `-v`.
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// Increase user-facing / tracing detail (`-v`, `-vv`). Ignored when
    /// `RUST_LOG` is set.
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    verbose: u8,

    /// QUIC congestion controller: `cubic` (default) or `bbr3`. Also
    /// `LINK_P2P_CC`. Experimental — see docs/performance.md.
    #[arg(long, global = true, env = "LINK_P2P_CC", value_enum)]
    cc: Option<CongestionControl>,

    /// QUIC connection send window in bytes. Also `LINK_P2P_SEND_WINDOW`.
    #[arg(long, global = true, env = "LINK_P2P_SEND_WINDOW")]
    send_window: Option<u64>,

    /// QUIC per-stream receive window in bytes. Also
    /// `LINK_P2P_STREAM_RECV_WINDOW`.
    #[arg(long, global = true, env = "LINK_P2P_STREAM_RECV_WINDOW")]
    stream_recv_window: Option<u64>,

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
enum ContactCommand {
    /// Add or update a contact.
    Add {
        /// Local nickname.
        name: String,
        /// EndpointId hex or short code.
        id: String,
    },
    /// Remove a contact.
    Remove {
        name: String,
    },
    /// List contacts.
    List,
    /// Print this node's short code (and EndpointId).
    Code,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Write a default `config.toml` (refuses to overwrite unless `--force`).
    Init {
        /// Replace an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Print the resolved config file path.
    Path,
}

/// Machine-oriented output for status commands (`ping`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// QUIC congestion controller selection (maps to noq-proto factories).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum CongestionControl {
    Cubic,
    Bbr3,
}

/// Tunables applied on top of iroh/noq transport defaults.
#[derive(Clone, Debug, Default)]
pub(crate) struct TransportTune {
    cc: Option<CongestionControl>,
    send_window: Option<u64>,
    stream_recv_window: Option<u64>,
}

/// User-facing status lines: respect `-q` and keep stdout clean in `--stdio`.
#[derive(Clone, Copy)]
pub(crate) struct Ui {
    pub(crate) quiet: bool,
    pub(crate) stderr_only: bool,
}

impl Ui {
    pub(crate) fn line(self, s: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        if self.stderr_only {
            eprintln!("{}", s.as_ref());
        } else {
            println!("{}", s.as_ref());
        }
    }
}

/// Shared `--max-conns` → semaphore mapping (`0` = unlimited).
pub(crate) fn conn_semaphore(max_conns: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(if max_conns == 0 {
        usize::MAX
    } else {
        max_conns
    }))
}

/// Push a JoinHandle into a shared task list, surviving a poisoned mutex.
pub(crate) fn push_task(tasks: &Mutex<Vec<JoinHandle<()>>>, task: JoinHandle<()>) {
    match tasks.lock() {
        Ok(mut g) => g.push(task),
        Err(poisoned) => poisoned.into_inner().push(task),
    }
}

/// Serve mode — exactly one of fixed forward or proxy. Encoded as an enum so
/// "neither / both" cannot be represented after CLI validation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ServeMode {
    Forward(SocketAddr),
    Proxy { allow_private: bool },
}

/// Connect local side — listen, SOCKS5, or (Unix) stdio.
#[derive(Clone, Copy, Debug)]
enum ConnectMode {
    Listen(SocketAddr),
    Socks5(SocketAddr),
    #[cfg(unix)]
    Stdio,
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
        /// The remote node's EndpointId (printed by `serve` on startup).
        /// On Unix, `-` reads one line from stdin. Also `LINK_P2P_TO`.
        #[arg(long, env = "LINK_P2P_TO")]
        to: Option<String>,
        /// Local address to listen on, e.g. 127.0.0.1:9090
        #[arg(long, conflicts_with = "socks5_listen")]
        listen: Option<SocketAddr>,
        /// Speak SOCKS5 (no-auth, CONNECT only) on this local address; local
        /// clients can then reach any destination through the remote
        /// `serve --proxy`. Conflicts with --listen
        #[arg(long, conflicts_with = "listen")]
        socks5_listen: Option<SocketAddr>,
        /// Pipe stdin/stdout to one QUIC stream (ssh ProxyCommand / rsync -e).
        /// Unix only. Status banners go to stderr. Conflicts with --listen /
        /// --socks5-listen and with `--to -` (stdin is the data path).
        #[cfg(unix)]
        #[arg(long, conflicts_with_all = ["listen", "socks5_listen"])]
        stdio: bool,
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
    /// Creates a TUN interface (needs root / CAP_NET_ADMIN, or Administrator
    /// and wintun.dll on Windows) and routes `172.24.0.0/16` through it.
    /// Unlike `serve`/`connect`, which forward one TCP port, this bridges the
    /// whole machine: TCP, UDP and ICMP on mesh virtual IPs, with no per-port
    /// setup. Hub coordinates the roster; spokes prefer direct links — see
    /// docs/tun-design.md.
    Tun {
        #[command(subcommand)]
        command: TunCommand,
    },
    /// Measure RTT to a remote node over the P2P network.
    Ping {
        /// The remote node's EndpointId (printed by `serve` on startup).
        /// Use `-` to read one line from stdin. Also `LINK_P2P_TO`.
        #[arg(long, env = "LINK_P2P_TO")]
        to: Option<String>,
        /// Direct address hint(s) for the peer (repeatable) — see `connect
        /// --to-addr`. Dialed directly, skipping discovery.
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
        /// Output format: text (default) or json (for jq).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Symmetric call: both sides publish and dial (EndpointId tie-break).
    ///
    /// Resolves a contact name, EndpointId, or short code. Merges config.toml
    /// relays with n0 by default. Pair with the same flags on both peers.
    Call {
        /// Contact name, EndpointId, or short code.
        to: String,
        /// Local TCP listen address (forwards to the peer).
        #[arg(long, conflicts_with = "stdio")]
        listen: Option<SocketAddr>,
        /// Local TCP target for streams the peer opens to us.
        #[arg(long)]
        forward: Option<SocketAddr>,
        /// Pipe stdin/stdout (Unix). Conflicts with --listen.
        #[cfg(unix)]
        #[arg(long, conflicts_with = "listen")]
        stdio: bool,
        /// Direct address hint(s) (repeatable).
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
    },
    /// Manage the local contacts book (names → EndpointId).
    Contact {
        #[command(subcommand)]
        command: ContactCommand,
    },
    /// Read or write `~/.config/link-p2p/config.toml` defaults.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Print a shell completion script to stdout.
    ///
    /// Redirect it to wherever your shell loads completions from, e.g.
    /// `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`
    /// or `link-p2p completions powershell` on Windows.
    Completions {
        /// Which shell to generate a completion script for.
        shell: Shell,
    },
    /// Print a man page (troff) for link-p2p to stdout. Unix builds only.
    #[cfg(unix)]
    Man,
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
    /// Exposed side: coordination hub for a virtual IP mesh. Accepts many
    /// concurrent peers, broadcasts the VIP↔EndpointId roster, bridges this
    /// machine to each, and forwards when spokes have no direct path.
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
        /// Only accept TUN mesh connections from these EndpointIds
        /// (repeatable). Default: anyone who knows this hub's EndpointId.
        /// Also `LINK_P2P_ALLOW` (comma-separated).
        #[arg(long)]
        allow: Vec<String>,
    },
    /// Dial a hub (`tun serve`), join the mesh, and try direct peer links.
    Connect {
        /// The remote node's EndpointId (printed by `tun serve` on startup).
        /// Use `-` to read one line from stdin. Also `LINK_P2P_TO`.
        #[arg(long, env = "LINK_P2P_TO")]
        to: Option<String>,
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
        /// Only accept inbound direct mesh links from these EndpointIds
        /// (repeatable). Hub dial is always attempted; this gates peer↔peer
        /// accepts and outbound dials. Also `LINK_P2P_ALLOW`.
        #[arg(long)]
        allow: Vec<String>,
    },
}

/// Localized `-h/--help` argument, replacing clap's built-in one (whose
/// "Print help..." text is hardcoded English and can't be localized).
/// Applied to the top command and every subcommand, alongside
/// `disable_help_flag(true)`.
///
/// clap's `ArgAction::Help` already chooses short vs long help from whether
/// the user typed `-h` or `--help`.
fn help_arg() -> clap::Arg {
    clap::Arg::new("help")
        .short('h')
        .long("help")
        .action(clap::ArgAction::Help)
        .help(tr!("Print help"))
        .long_help(tr!(
            "Print help. `-h` lists commands and examples; `--help` shows full option details."
        ))
        .hide_short_help(true)
}

/// Localized `-V/--version` argument, same story as [`help_arg`]. Top level
/// only (subcommands don't get a version flag).
fn version_arg() -> clap::Arg {
    clap::Arg::new("version")
        .short('V')
        .long("version")
        .action(clap::ArgAction::Version)
        .help(tr!("Print version"))
        .hide_short_help(true)
}

/// The `Command` from derive, with all display strings overridden at runtime
/// so `--help` output is localized. clap derive only accepts string literals,
/// so the structure comes from derive and the text is swapped here.
/// Platform-specific quick start appended to `--help`.
#[cfg(unix)]
fn platform_after_help() -> &'static str {
    "QUICK START:\n    link-p2p serve --forward 127.0.0.1:22\n    link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222\n\nUNIX-ONLY:\n    connect --stdio, --to -, link-p2p man\n\nCOMPLETIONS:\n    link-p2p completions fish|bash|zsh > …\n\nSee docs/unix.md and README.md."
}

#[cfg(windows)]
fn platform_after_help() -> &'static str {
    "QUICK START:\n    link-p2p serve --forward 127.0.0.1:3389\n    link-p2p connect --to <EndpointId> --listen 127.0.0.1:13389\n\nCOMPLETIONS:\n    link-p2p completions powershell | Out-File $PROFILE\\link-p2p.ps1\n\nTUN mode needs Administrator + wintun.dll beside the binary. See docs/windows.md and README.md."
}

#[cfg(not(any(unix, windows)))]
fn platform_after_help() -> &'static str {
    "See README.md. TUN mode supports Linux, macOS, and Windows."
}

#[cfg(unix)]
fn peer_to_help() -> String {
    tr!("The remote node's EndpointId (printed by `serve` on startup). Use `-` to read one line from stdin. Also `LINK_P2P_TO`.")
}

#[cfg(not(unix))]
fn peer_to_help() -> String {
    tr!("The remote node's EndpointId (printed by `serve` on startup). Also `LINK_P2P_TO`.")
}

fn localized_command() -> clap::Command {
    let cmd = Cli::command()
        // clap's built-in `help` subcommand hardcodes English text that
        // cannot be localized; disable it and localize the derived Help
        // variant instead (see the Command::Help doc). Same for the
        // -h/--help and -V/--version flags: replaced below with our own
        // localized arguments.
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        // wrap_help: detect terminal width; cap so ultra-wide terminals stay readable.
        // Indentation of wrapped option text is preserved by clap.
        .max_term_width(100)
        .about(tr!("Minimal TCP-over-QUIC forwarder on iroh"))
        .long_about(helptext::hard_wrap_help(&tr!(
            "link-p2p exposes a local TCP service to a P2P network (or dials one) over a direct, end-to-end encrypted QUIC connection. No TUN device, no root/admin privileges — just a persistent EndpointId and a QUIC hop."
        )))
        .after_help(i18n::lookup(platform_after_help()))
        .mut_arg(
            "identity",
            |a| helptext::set_help(a, &tr!("Path to store/load this node's persistent secret key. If it doesn't exist yet, a new one is generated and saved there. Default: the XDG config dir, $XDG_CONFIG_HOME/link-p2p/identity.key (usually ~/.config/link-p2p/identity.key); a legacy ./identity.key in the working directory is migrated there once. Keep this stable if you want your EndpointId to stay the same across restarts.")),
        )
        .mut_arg(
            "ephemeral",
            |a| helptext::set_help(a, &tr!("Use a temporary identity that is never written to disk: the EndpointId changes every start. Conflicts with --identity.")),
        )
        .mut_arg(
            "identity_passphrase",
            |a| helptext::set_help(a, &tr!("Passphrase protecting the identity key file. When set, the key is stored encrypted (Argon2id + XChaCha20-Poly1305) instead of plaintext hex, so a disk/backup leak doesn't expose the key. Prefer the LINK_P2P_PASSPHRASE environment variable over passing it inline — the flag value is visible in `ps` and shell history. Conflicts with --ephemeral.")),
        )
        .mut_arg(
            "relay",
            |a| helptext::set_help(a, &tr!("Custom relay URL(s), repeatable. Merged with n0 by default (keeps discovery); use --no-n0-relays to replace. Does NOT disable hole-punch — use --relay-only for a true relay-only baseline. Also LINK_P2P_RELAY (comma-separated) and config.toml.")),
        )
        .mut_arg(
            "relay_only",
            |a| helptext::set_help(a, &tr!("Disable IP transports (no hole-punch / LAN direct); traffic stays on relay. Set on both peers for a reliable baseline. Conflicts with --to-addr. Also LINK_P2P_RELAY_ONLY.")),
        )
        .mut_arg(
            "no_n0_relays",
            |a| helptext::set_help(a, &tr!("With --relay, use only the listed relays (no n0 public relays / discovery). Default merges custom relays into n0. Also LINK_P2P_NO_N0_RELAYS and config.toml relays.no_n0.")),
        )
        .mut_arg(
            "color",
            |a| helptext::set_help(a, &tr!("Control colored output: auto (colors on TTY only), always, or never.")),
        )
        .mut_arg(
            "max_conns",
            |a| helptext::set_help(a, &tr!("Maximum number of concurrent forwarded connections. 0 means unlimited. Prevents resource exhaustion on endpoints exposed to the network.")),
        )
        .mut_arg(
            "log_format",
            |a| helptext::set_help(a, &tr!("Log output format: text (human-readable) or json (structured, for jq/CI pipelines).")),
        )
        .mut_arg(
            "quiet",
            |a| helptext::set_help(a, &tr!("Quiet user-facing banners (errors still print). Independent of RUST_LOG / -v.")),
        )
        .mut_arg(
            "verbose",
            |a| helptext::set_help(a, &tr!("Increase tracing detail (-v, -vv). Ignored when RUST_LOG is set.")),
        )
        .mut_arg(
            "cc",
            |a| helptext::set_help(a, &tr!("QUIC congestion controller: cubic (default) or bbr3. Also LINK_P2P_CC. See docs/performance.md.")),
        )
        .mut_arg(
            "send_window",
            |a| helptext::set_help(a, &tr!("QUIC connection send window in bytes. Also LINK_P2P_SEND_WINDOW.")),
        )
        .mut_arg(
            "stream_recv_window",
            |a| helptext::set_help(a, &tr!("QUIC per-stream receive window in bytes. Also LINK_P2P_STREAM_RECV_WINDOW.")),
        )
        .mut_arg(
            "keepalive",
            |a| helptext::set_help(a, &tr!("QUIC keepalive interval in seconds (default 5). Keeps NAT UDP mappings alive; the typical home-router mapping expires after 20-30s of idle. Raise it on high-latency links, lower it where NAT timeouts are aggressive.")),
        )
        .mut_arg(
            "idle_timeout",
            |a| helptext::set_help(a, &tr!("QUIC max idle timeout in seconds (default 30). After this long without traffic the peer is declared dead and the connection re-dialed. Raise it for lossy / high-latency links so a brief outage doesn't tear the connection down.")),
        )
        .mut_subcommand("serve", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Expose a local TCP service to the P2P network."))
                .mut_arg(
                    "forward",
                    |a| helptext::set_help(a, &tr!("Local address to forward incoming P2P streams to, e.g. 127.0.0.1:8080")),
                )
                .mut_arg(
                    "proxy",
                    |a| helptext::set_help(a, &tr!("Generic proxy mode: dial the address from each stream's header instead of a fixed --forward target. Pairs with `connect --socks5-listen`.")),
                )
                .mut_arg(
                    "allow",
                    |a| helptext::set_help(a, &tr!("Only accept P2P connections from these EndpointIds (repeatable). Default: accept anyone who knows this node's EndpointId. Strongly recommended when the node is reachable from untrusted networks.")),
                )
                .mut_arg(
                    "allow_private",
                    |a| helptext::set_help(a, &tr!("In proxy mode, allow forwarding to private/loopback/link-local addresses (blocked by default to prevent SSRF — a malicious peer could otherwise make this node reach into your LAN or cloud metadata endpoints such as 169.254.169.254).")),
                )
        })
        .mut_subcommand("connect", |s| {
            let s = s
                .disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Dial a remote node and expose it as a local TCP listener."))
                .mut_arg("to", |a| helptext::set_help(a, &peer_to_help()))
                .mut_arg(
                    "listen",
                    |a| helptext::set_help(a, &tr!("Local address to listen on, e.g. 127.0.0.1:9090")),
                )
                .mut_arg(
                    "socks5_listen",
                    |a| helptext::set_help(a, &tr!("Speak SOCKS5 (no-auth, CONNECT only) on this local address; local clients can then reach any destination through the remote `serve --proxy`.")),
                );
            #[cfg(unix)]
            let s = s.mut_arg(
                "stdio",
                |a| helptext::set_help(a, &tr!(
                    "Pipe stdin/stdout to one QUIC stream (ssh ProxyCommand / rsync -e). Status banners go to stderr."
                )),
            );
            s.mut_arg(
                "to_addr",
                |a| helptext::set_help(a, &tr!(
                    "Direct address hint(s) for the peer (repeatable), e.g. its public ip:port or a LAN address. Dialed directly, skipping discovery — use it when you exchanged addresses out-of-band and want no DNS/pkarr lookup (also faster reconnects). May be combined with --relay, which then stays as the fallback path."
                )),
            )
        })
        .mut_subcommand("tun", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Make machines reachable at the IP layer over QUIC datagrams (mesh with hub coordination)."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Make machines reachable at the IP layer over QUIC datagrams.\n\nCreates a TUN interface (needs root / CAP_NET_ADMIN on Linux and macOS, or Administrator + wintun.dll on Windows). `tun serve` is the coordination hub (roster + fallback forward); `tun connect` dials it, learns the VIP↔EndpointId roster, and tries direct spoke↔spoke links (hub forward remains the fallback). Prefer `--cc bbr3` on lossy paths. Virtual IPs are IPv4 only — see docs/tun-design.md."
                )))
                .mut_subcommand("serve", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Hub: roster + fallback forward for the virtual IP mesh."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Hub: accept many concurrent peers, broadcast the VIP↔EndpointId roster, bridge this machine to each at the IP layer, and forward traffic when spokes have no direct path. Prints this node's virtual IP and EndpointId."
                        )))
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16).")),
                        )
                        .mut_arg(
                            "mtu",
                            |a| helptext::set_help(a, &tr!("Upper bound for the TUN interface MTU (default 1280). The final MTU is min(this, the negotiated QUIC datagram max); values above 1280 are refused.")),
                        )
                        .mut_arg(
                            "allow",
                            |a| helptext::set_help(a, &tr!("Only accept TUN mesh connections from these EndpointIds (repeatable). Default: accept anyone who knows this hub's EndpointId. Also LINK_P2P_ALLOW.")),
                        )
                })
                .mut_subcommand("connect", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Dial a hub, join the mesh, and try direct peer links."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Dial a `tun serve` hub, install 172.24.0.0/16 on the TUN, receive the mesh roster, and attempt direct links to other spokes (packets prefer direct; otherwise via hub)."
                        )))
                        .mut_arg(
                            "to",
                            |a| helptext::set_help(a, &peer_to_help()),
                        )
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16).")),
                        )
                        .mut_arg(
                            "mtu",
                            |a| helptext::set_help(a, &tr!("Upper bound for the TUN interface MTU (default 1280). The final MTU is min(this, the negotiated QUIC datagram max); values above 1280 are refused.")),
                        )
                        .mut_arg(
                            "to_addr",
                            |a| helptext::set_help(a, &tr!("Direct address hint(s) for the peer (repeatable) — see `connect --to-addr`. Dialed directly, skipping discovery.")),
                        )
                        .mut_arg(
                            "allow",
                            |a| helptext::set_help(a, &tr!("Only accept inbound direct mesh links from these EndpointIds (repeatable); also gates outbound peer dials. Hub dial is always attempted. Also LINK_P2P_ALLOW.")),
                        )
                })
        })
        .mut_subcommand("ping", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Measure RTT to a remote node over the P2P network."))
                .mut_arg(
                    "to",
                    |a| helptext::set_help(a, &peer_to_help()),
                )
                .mut_arg(
                    "to_addr",
                    |a| helptext::set_help(a, &tr!("Direct address hint(s) for the peer (repeatable) — see `connect --to-addr`. Dialed directly, skipping discovery.")),
                )
                .mut_arg(
                    "format",
                    |a| helptext::set_help(a, &tr!("Output format: text (default) or json (for jq).")),
                )
        })
        .mut_subcommand("call", |s| {
            let s = s
                .disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Symmetric call: both peers publish and dial (tie-break by EndpointId)."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Phone-like session: both sides run `call` with the same peer token (contact name, EndpointId, or short code). The peer with the smaller EndpointId dials; the other waits. Use --listen and/or --forward on both ends. Relays from config.toml merge with n0 unless --no-n0-relays."
                )))
                .mut_arg("to", |a| {
                    helptext::set_help(
                        a,
                        &tr!("Contact name, EndpointId, or short code from `contact code`."),
                    )
                })
                .mut_arg("listen", |a| {
                    helptext::set_help(
                        a,
                        &tr!("Local TCP address to listen on; connections are forwarded to the peer."),
                    )
                })
                .mut_arg("forward", |a| {
                    helptext::set_help(
                        a,
                        &tr!("Local TCP target for streams the peer opens to us (optional)."),
                    )
                })
                .mut_arg("to_addr", |a| {
                    helptext::set_help(
                        a,
                        &tr!("Direct address hint(s) for the peer (repeatable)."),
                    )
                });
            #[cfg(unix)]
            let s = s.mut_arg("stdio", |a| {
                helptext::set_help(
                    a,
                    &tr!("Pipe stdin/stdout to one stream (Unix). Conflicts with --listen."),
                )
            });
            s
        })
        .mut_subcommand("contact", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Manage the local contacts book (names → EndpointId)."))
                .mut_subcommand("add", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Add or update a contact."))
                        .mut_arg("name", |a| helptext::set_help(a, &tr!("Local nickname.")))
                        .mut_arg(
                            "id",
                            |a| helptext::set_help(a, &tr!("EndpointId hex or short code.")),
                        )
                })
                .mut_subcommand("remove", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Remove a contact."))
                        .mut_arg("name", |a| helptext::set_help(a, &tr!("Local nickname.")))
                })
                .mut_subcommand("list", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("List contacts."))
                })
                .mut_subcommand("code", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Print this node's short code (and EndpointId)."))
                })
        })
        .mut_subcommand("config", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Read or write ~/.config/link-p2p/config.toml defaults."))
                .mut_subcommand("init", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!(
                            "Write a default config.toml (refuses to overwrite unless --force)."
                        ))
                        .mut_arg(
                            "force",
                            |a| helptext::set_help(a, &tr!("Replace an existing config file.")),
                        )
                })
                .mut_subcommand("path", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Print the resolved config file path."))
                })
        })
        .mut_subcommand("completions", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Print a shell completion script to stdout."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Print a shell completion script to stdout.\n\nRedirect it to wherever your shell loads completions from, e.g. `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`."
                )))
                .mut_arg(
                    "shell",
                    |a| helptext::set_help(a, &tr!("Which shell to generate a completion script for.")),
                )
        })
        ;
    #[cfg(unix)]
    let cmd = cmd.mut_subcommand("man", |s| {
        s.disable_help_flag(true)
            .arg(help_arg())
            .about(tr!("Print a man page (troff) for link-p2p to stdout."))
    });
    cmd.mut_subcommand("help", |s| {
            // Our derived Help variant replaces clap's built-in one (disabled
            // above); this is the only way to localize its description.
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Print this message or the help of the given subcommand(s)"))
                .mut_arg(
                    "sub",
                    |a| helptext::set_help(a, &tr!("Print help for the subcommand(s)")),
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
        std::process::exit(exit::code_from(&e));
    }
}

async fn real_main(color_mode: ColorMode) -> Result<()> {
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
        out.push_str("docs/unix.md, docs/performance.md, README.md\n");
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
    // Load ~/.config/link-p2p/config.toml defaults (CLI still wins / appends).
    let user_cfg = config::load_or_default(&config::config_path());
    cli.relay = config::merge_relay_urls(&cli.relay, &user_cfg);
    // Bias multi-relay dial order for every command (not just `call`).
    cli.relay = relay_probe::order_by_connect_latency(&cli.relay).await;
    cli.no_n0_relays = cli.no_n0_relays || user_cfg.relays.no_n0;
    if !cli.relay_only {
        cli.relay_only = user_cfg.relays.relay_only;
    }
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
        ui.line(styler.warn(&tr!(
            "ephemeral identity: this EndpointId will not persist across restarts"
        )));
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
            // TUN hub accepts many peers; --max-conns only applies to stream serve.
            if cli.max_conns != 1024 {
                ui.line(styler.warn(&tr!(
                    "note: --max-conns is not used by TUN mode (hub accepts peers until stopped)"
                )));
            }
            match command {
                TunCommand::Serve {
                    tun_ip,
                    mtu,
                    allow,
                } => {
                    tun::validate_mtu(mtu)?;
                    let allow = parse_tun_allow(allow)?;
                    tun::run_tun_serve(
                        secret_key,
                        tun_ip,
                        mtu,
                        &cli.relay,
                        cli.relay_only,
                        cli.no_n0_relays,
                        Duration::from_secs(cli.keepalive),
                        Duration::from_secs(cli.idle_timeout),
                        tune,
                        allow,
                        ui,
                        styler,
                    )
                    .await
                }
                TunCommand::Connect {
                    to,
                    tun_ip,
                    mtu,
                    to_addr,
                    allow,
                } => {
                    tun::validate_mtu(mtu)?;
                    let to = resolve_peer_to(to, false)?;
                    let allow = parse_tun_allow(allow)?;
                    tun::run_tun_connect(
                        secret_key,
                        &to,
                        tun_ip,
                        mtu,
                        &cli.relay,
                        cli.relay_only,
                        cli.no_n0_relays,
                        to_addr,
                        Duration::from_secs(cli.keepalive),
                        Duration::from_secs(cli.idle_timeout),
                        tune,
                        allow,
                        ui,
                        styler,
                    )
                    .await
                }
            }
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
        Command::Contact { command } => match command {
            ContactCommand::Add { name, id } => {
                let path = contacts::contacts_path();
                let mut book = contacts::load(&path)?;
                let eid = contacts::parse_endpoint_token(&id)?;
                book.contacts.insert(
                    name.clone(),
                    contacts::Contact {
                        id: eid.to_string(),
                        relays: Vec::new(),
                        addrs: Vec::new(),
                    },
                );
                contacts::save(&path, &book)?;
                ui.line(styler.ok(&tr_fmt!(
                    "saved contact {0} → {1}",
                    name,
                    eid.fmt_short()
                )));
                Ok(())
            }
            ContactCommand::Remove { name } => {
                let path = contacts::contacts_path();
                let mut book = contacts::load(&path)?;
                if book.contacts.remove(&name).is_none() {
                    bail!(tr_fmt!("no contact named '{0}'", name));
                }
                contacts::save(&path, &book)?;
                ui.line(styler.ok(&tr_fmt!("removed contact {0}", name)));
                Ok(())
            }
            ContactCommand::List => {
                let book = contacts::load(&contacts::contacts_path())?;
                if book.contacts.is_empty() {
                    ui.line(styler.dim(&tr!("no contacts yet — use `contact add` or pair a short code")));
                } else {
                    // Machine-readable TSV for scripts (`name\tid`), like
                    // `contact code` / `ping --format json`: always stdout,
                    // not via `ui.line` — quiet must not suppress data output.
                    for (name, c) in &book.contacts {
                        println!("{name}\t{}", c.id);
                    }
                }
                Ok(())
            }
            ContactCommand::Code => {
                // Machine-readable identity lines for scripts / pairing —
                // always stdout, even under `-q` (same rule as ENDPOINT_ID=).
                let id = secret_key.public();
                println!("ENDPOINT_ID={id}");
                println!("SHORT_CODE={}", contacts::encode_short_code(id));
                Ok(())
            }
        },
        Command::Config { command } => match command {
            ConfigCommand::Path => {
                // Machine-readable path for scripts — always stdout.
                println!("{}", config::config_path().display());
                Ok(())
            }
            ConfigCommand::Init { force } => {
                let path = config::config_path();
                if path.exists() && !force {
                    return Err(exit::coded(
                        exit::USAGE,
                        anyhow::anyhow!(tr_fmt!(
                            "config already exists at {0} (use --force to overwrite)",
                            path.display()
                        )),
                    ));
                }
                let cfg = config::UserConfig::default();
                config::save(&path, &cfg)?;
                ui.line(styler.ok(&tr_fmt!("wrote {0}", path.display())));
                Ok(())
            }
        },
        Command::Completions { .. } | Command::Help { .. } => {
            // Completions / help return before identity setup.
            Err(anyhow::anyhow!(
                "internal: meta-command should have returned earlier"
            ))
        }
        #[cfg(unix)]
        Command::Man => {
            Err(anyhow::anyhow!(
                "internal: meta-command should have returned earlier"
            ))
        }
    }
}

/// Resolve `--to` / `LINK_P2P_TO`, including `-` = read EndpointId from stdin.
/// Incompatible with `--stdio` (stdin is the data path).
fn resolve_peer_to(to: Option<String>, stdio: bool) -> Result<String> {
    let raw = to
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("missing peer EndpointId (--to or LINK_P2P_TO)")),
            )
        })?;
    if raw == "-" {
        #[cfg(not(unix))]
        {
            let _ = stdio;
            return Err(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!("--to - (read EndpointId from stdin) is only available on Unix builds")),
            ));
        }
        #[cfg(unix)]
        {
            if stdio {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("--to - cannot be combined with --stdio (stdin conflict)")),
                ));
            }
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context(tr!("reading EndpointId from stdin"))?;
            let id = line.trim();
            if id.is_empty() {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr!("empty EndpointId on stdin")),
                ));
            }
            if let Some(rest) = id.strip_prefix("ENDPOINT_ID=") {
                return Ok(rest.trim().to_string());
            }
            return Ok(id.to_string());
        }
    }
    Ok(raw)
}

/// CLI `--allow` wins; otherwise parse comma-separated `LINK_P2P_ALLOW`.
fn merge_allow_list(cli: Vec<String>) -> Vec<String> {
    if !cli.is_empty() {
        return cli;
    }
    match std::env::var("LINK_P2P_ALLOW") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse TUN `--allow` / `LINK_P2P_ALLOW` into a set; `None` means open.
fn parse_tun_allow(cli: Vec<String>) -> Result<Option<HashSet<EndpointId>>> {
    let allow = merge_allow_list(cli);
    if allow.is_empty() {
        return Ok(None);
    }
    let mut set = HashSet::new();
    for s in &allow {
        let id: EndpointId = s.parse().map_err(|e| {
            exit::coded(
                exit::USAGE,
                anyhow::Error::new(e).context(tr_fmt!(
                    "'{0}' is not a valid EndpointId in --allow",
                    s
                )),
            )
        })?;
        set.insert(id);
    }
    Ok(Some(set))
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
///
/// The KDF salt input is the PHC "B64" encoding of the on-disk salt bytes
/// (same as argon2 0.5 `SaltString::encode_b64`), so existing encrypted
/// identity files keep decrypting after the 0.6 upgrade.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::password_hash::phc::Salt;
    use argon2::{Algorithm, Argon2, Params, Version};

    let salt_b64 = Salt::new(salt)
        .map_err(|_| anyhow::anyhow!(tr!("encoding the passphrase salt")))?
        .to_salt_string();
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|_| anyhow::anyhow!(tr!("invalid Argon2 parameters")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut dk = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_b64.as_bytes(), &mut dk)
        .map_err(|_| anyhow::anyhow!(tr!("deriving key from passphrase")))?;
    Ok(dk)
}

/// Encrypt a 64-char hex key into the on-disk format (magic + salt + nonce +
/// ciphertext). XChaCha20-Poly1305 with the file magic as AAD, so a header
/// can't be swapped between files. The derived key is zeroized on return.
fn encrypt_key_hex(hex: &str, passphrase: &str) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

    let mut salt = [0u8; KEY_FILE_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|_| anyhow::anyhow!(tr!("gathering entropy for identity salt")))?;
    let mut nonce_bytes = [0u8; KEY_FILE_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!(tr!("gathering entropy for identity nonce")))?;

    let mut dk = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(dk));
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
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
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a key file written by [`encrypt_key_hex`], returning the 64-char
/// hex. A wrong passphrase or any tampering fails the AEAD tag check and
/// errors here.
fn decrypt_key_hex(data: &[u8], passphrase: &str) -> Result<String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

    if !is_encrypted_key(data) {
        bail!(tr!("identity file is not passphrase-encrypted"));
    }
    let salt = &data[KEY_FILE_MAGIC.len()..KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN];
    let nonce_off = KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN;
    let nonce_bytes: [u8; KEY_FILE_NONCE_LEN] = data[nonce_off..nonce_off + KEY_FILE_NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!(tr!("identity file is truncated")))?;
    let ciphertext = &data[nonce_off + KEY_FILE_NONCE_LEN..];

    let mut dk = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(dk));
    let nonce = XNonce::from(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            &nonce,
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
pub(crate) async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    const ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
    match time::timeout(ONLINE_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_elapsed) => Err(exit::coded(
            exit::TIMEOUT,
            anyhow::anyhow!(tr_fmt!(
                "endpoint did not come online within {0}.\n\
                 \n\
                 The most likely cause: outgoing UDP is blocked by a firewall.\n\
                 iroh/QUIC relies on UDP for both direct hole-punching and\n\
                 relay connections. Try:\n\
                   nc -u -v -w3 8.8.8.8 53    # does UDP egress work at all?\n\
                   RUST_LOG=iroh=debug {1}     # see exactly where it's stuck",
                format!("{ONLINE_TIMEOUT:?}"),
                std::env::args().next().unwrap_or_else(|| "link-p2p".into())
            )),
        )),
    }
}

/// Build an endpoint with the given identity.
///
/// Build an endpoint.
///
/// - `relay` empty → [`presets::N0`] (public relays + discovery).
/// - `relay` non-empty and `no_n0_relays` → [`presets::Minimal`] + custom map only.
/// - `relay` non-empty and not `no_n0_relays` → N0 base (keeps discovery); call
///   [`install_extra_relays`] after `bind` to add the custom URLs.
///
/// `relay_only` clears IP transports (true relay-only baseline).
pub(crate) fn build_endpoint(
    secret_key: SecretKey,
    relay: &[String],
    keepalive: Duration,
    idle_timeout: Duration,
    tune: &TransportTune,
    relay_only: bool,
    no_n0_relays: bool,
) -> Result<iroh::endpoint::Builder> {
    let transport = transport_config(keepalive, idle_timeout, tune)?;
    let builder = if relay.is_empty() {
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .transport_config(transport)
    } else if no_n0_relays {
        let relay_map = RelayMap::try_from_iter(relay.iter().map(|s| s.as_str()))
            .with_context(|| {
                tr_fmt!(
                    "invalid --relay URL in list: {0}",
                    relay.join(", ")
                )
            })?;
        Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .transport_config(transport)
            .relay_mode(RelayMode::Custom(relay_map))
    } else {
        // Keep n0 discovery + public relays; extras via install_extra_relays.
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .transport_config(transport)
    };
    if relay_only {
        Ok(builder
            .clear_ip_transports()
            .addr_filter(iroh::address_lookup::AddrFilter::relay_only()))
    } else {
        Ok(builder)
    }
}

/// Insert custom relay URLs into a live endpoint that was built with n0 base.
pub(crate) async fn install_extra_relays(
    endpoint: &Endpoint,
    relay: &[String],
    no_n0_relays: bool,
) -> Result<()> {
    if no_n0_relays || relay.is_empty() {
        return Ok(());
    }
    for raw in relay {
        let url: iroh::RelayUrl = raw
            .parse()
            .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", raw))?;
        let cfg = std::sync::Arc::new(iroh::RelayConfig::from(url.clone()));
        endpoint.insert_relay(url, cfg).await;
    }
    Ok(())
}

pub(crate) fn reject_relay_only_with_to_addr(relay_only: bool, to_addr: &[SocketAddr]) -> Result<()> {
    if relay_only && !to_addr.is_empty() {
        return Err(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "--relay-only cannot be combined with --to-addr (direct IP hints)"
            )),
        ));
    }
    Ok(())
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
pub(crate) fn build_dial_addr(
    peer_id: EndpointId,
    relay: &[String],
    to_addr: &[SocketAddr],
) -> Result<EndpointAddr> {
    let mut addr = EndpointAddr::from(peer_id);
    for relay_url in relay {
        let relay_url = relay_url
            .parse()
            .with_context(|| tr_fmt!("'{0}' is not a valid RelayUrl", relay_url))?;
        addr = addr.with_relay_url(relay_url);
    }
    // With no custom relays, dial by EndpointId alone and let n0 discovery
    // (or --to-addr hints below) supply reachability.
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
fn transport_config(
    keepalive: Duration,
    idle_timeout: Duration,
    tune: &TransportTune,
) -> Result<QuicTransportConfig> {
    let mut b = QuicTransportConfig::builder()
        .keep_alive_interval(keepalive)
        .max_idle_timeout(Some(idle_timeout.try_into()?));
    // Defaults are CUBIC + ~100Mbps/100ms windows (noq). Override only when
    // the operator asked — see docs/performance.md and the transport matrix.
    match tune.cc {
        Some(CongestionControl::Cubic) => {
            b = b.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        Some(CongestionControl::Bbr3) => {
            b = b.congestion_controller_factory(Arc::new(Bbr3Config::default()));
        }
        None => {}
    }
    if let Some(w) = tune.send_window {
        b = b.send_window(w);
    }
    if let Some(w) = tune.stream_recv_window {
        b = b.stream_receive_window(VarInt::from_u64(w).map_err(|_| {
            anyhow::anyhow!(tr!("--stream-recv-window / LINK_P2P_STREAM_RECV_WINDOW out of range"))
        })?);
    }
    Ok(b.build())
}

// ---------------------------------------------------------------------------
// serve: accept incoming P2P connections, forward each QUIC stream to a
// fixed local TCP target.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // CLI entry point; explicit config beats a grab-bag struct
async fn run_serve(
    secret_key: SecretKey,
    mode: ServeMode,
    allowed: Vec<EndpointId>,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune, relay_only, no_n0_relays)?
        .alpns(vec![ALPN.to_vec(), PING_ALPN.to_vec()])
        .bind()
        .await
        .context(tr!("binding endpoint"))?;

    wait_online(&endpoint).await?;
    install_extra_relays(&endpoint, relay, no_n0_relays).await?;

    ui.line(styler.banner("link-p2p serve"));
    match mode {
        ServeMode::Forward(target) => ui.line(format!(
            "  {}",
            tr_fmt!("forwarding P2P connections to: {0}", target)
        )),
        ServeMode::Proxy { allow_private } => {
            ui.line(format!(
                "  {}",
                styler.info(&tr!(
                    "proxy mode: dialing the target address from each stream's header"
                ))
            ));
            if !allow_private {
                ui.line(format!(
                    "  {}",
                    styler.warn(&tr!(
                        "proxy targets in private/loopback ranges are blocked (use --allow-private to permit)"
                    ))
                ));
            }
        }
    }
    // The whitelist is an important security property; surface it in the
    // banner instead of hiding it in --help.
    if !allowed.is_empty() {
        ui.line(format!(
            "  {}",
            styler.info(&tr_fmt!(
                "only accepting connections from {0} allowed peer(s)",
                allowed.len()
            ))
        ));
    }
    ui.line(format!(
        "  {}",
        styler.dim(&tr!(
            "your EndpointId (give this to peers running `connect --to`):"
        ))
    ));
    let ep_hex = endpoint.id().to_string();
    ui.line(format!("    {}", styler.highlight(&ep_hex)));
    // Machine-readable for scripts / e2e — always stdout, even under `-q`.
    println!("ENDPOINT_ID={ep_hex}");
    ui.line("");
    ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));

    // Every per-stream forwarder is our own spawned task; the router's
    // accept loop doesn't know about them, so keep the handles here for the
    // drain on shutdown.
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let handler = ForwardHandler {
        mode,
        allowed: if allowed.is_empty() {
            None
        } else {
            Some(Arc::new(allowed.into_iter().collect()))
        },
        // 0 = unlimited. usize::MAX keeps the acquire() call shape uniform.
        semaphore: conn_semaphore(max_conns),
        // A second, independent cap on *connections* (not streams): an idle
        // connection costs memory + an accept task even without any stream,
        // so bound how many such connections a flood of dials can open.
        conn_semaphore: conn_semaphore(max_conns),
        tasks: tasks.clone(),
        endpoint: endpoint.clone(),
        relay_only,
        styler,
        quiet: ui.quiet,
    };
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, handler)
        .accept(PING_ALPN, PingHandler)
        .spawn();

    tokio::signal::ctrl_c().await?;
    ui.line(styler.warn(&tr!("shutting down...")));
    router.shutdown().await?;
    // router.shutdown() only stops the router's own accept loop — the
    // per-stream forwarders are our tasks, so give them the same bounded
    // drain window as run_connect.
    let pending = std::mem::take(&mut *tasks.lock().unwrap_or_else(|e| e.into_inner()));
    pipe::drain_tasks(pending).await;
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
    mode: ServeMode,
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
    endpoint: Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
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
        tracing::debug!(%peer, "waiting for connection permit");
        let _conn_permit = match self.conn_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // semaphore closed; shouldn't happen
        };
        tracing::debug!(%peer, "connection permit acquired, entering accept_bi loop");

        // One QUIC connection can carry many independent streams. Each stream
        // here corresponds to one TCP connection on the far side (see
        // run_connect below), so we keep accepting streams until the peer
        // closes the whole connection.
        spawn_path_monitor(
            connection.clone(),
            peer,
            self.endpoint.clone(),
            self.relay_only,
            self.styler,
            self.quiet,
        );
        loop {
            // Bound the number of concurrently forwarded streams. We acquire
            // the permit *before* accept_bi so a hostile peer flooding streams
            // can't make us spawn unbounded tasks/sockets: the extra streams
            // just queue up at the QUIC layer until a slot frees.
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed; shouldn't happen
            };
            tracing::debug!(%peer, "waiting for bidi stream (accept_bi)");
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => {
                    tracing::debug!(%peer, "bidi stream accepted");
                    pair
                }
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
            let mode = self.mode;
            let task = tokio::spawn(async move {
                // The permit lives as long as this stream does; dropping it
                // after handle_forward_stream frees the slot.
                let _permit = permit;
                if let Err(e) = handle_forward_stream(mode, send, recv).await {
                    warn!(%peer, error = %e, "{}", tr!("stream error"));
                }
            });
            push_task(&self.tasks, task);
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
pub(crate) async fn handle_forward_stream(
    mode: ServeMode,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let target = match mode {
        ServeMode::Forward(addr) => {
            // Fixed-forward: consume STREAM_HELLO before dialing so accept_bi
            // completes as soon as the connect side opens the stream — not
            // when the local TCP client eventually writes (or FIN)s.
            pipe::read_stream_hello(&mut recv).await?;
            addr
        }
        ServeMode::Proxy { allow_private } => {
            // Proxy already has an on-wire header (`write_target` / read_target).
            let target = socks5::read_target(&mut recv).await?.resolve().await?;
            check_proxy_target(target, allow_private)?;
            target
        }
    };
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| tr_fmt!("connecting to {0}", target))?;
    tracing::debug!("DBG forward: connected to {target}, starting pipe_streams");
    pipe::pipe_streams(tcp, send, recv).await
}

/// Path / throughput monitor for a live session.
///
/// - Every 30s: debug-log path kind + Quinn counters (path from
///   [`Connection::paths`], not `udp_tx/rx` heuristics).
/// - While not on a direct path and not `--relay-only`: every ~45s call
///   [`Endpoint::network_change`] so magicsock re-STUNs / retries hole-punch
///   (home NAT mappings drift; a single settle at connect is not enough).
/// - If traffic is active but stuck under a low ceiling while still on relay,
///   warn once that public relays rate-limit (self-host / wait for direct).
pub(crate) fn spawn_path_monitor(
    connection: Connection,
    peer: EndpointId,
    endpoint: Endpoint,
    relay_only: bool,
    styler: Styler,
    quiet: bool,
) -> tokio::task::JoinHandle<()> {
    /// Sample window for path stats + slow-relay detection.
    const STATS_SECS: u64 = 30;
    /// How often to nudge magicsock while still on relay (and not relay-permanent).
    const UPGRADE_SECS: u64 = 45;
    /// After this many pure-relay (no IP candidate) samples, slow upgrades.
    const RELAY_PERM_STREAK: u8 = 4;
    /// Backed-off upgrade interval for peers that never show a direct candidate.
    const UPGRADE_SECS_PERMANENT: u64 = 300;
    /// Sustained under this (with real traffic) → treat as relay-shaped ceiling.
    const RELAY_SLOW_BPS: u64 = 128 * 1024;
    /// Ignore idle windows (keepalive alone).
    const ACTIVE_MIN_BPS: u64 = 2 * 1024;

    tokio::spawn(async move {
        let mut stats_tick = time::interval(Duration::from_secs(STATS_SECS));
        stats_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut next_upgrade = tokio::time::Instant::now() + Duration::from_secs(UPGRADE_SECS);
        // Skip the immediate first stats tick.
        stats_tick.tick().await;

        let mut prev_bytes = {
            let s = connection.stats();
            s.udp_tx.bytes.saturating_add(s.udp_rx.bytes)
        };
        let mut slow_relay_streak: u8 = 0;
        let mut no_ip_candidate_streak: u8 = 0;
        let mut warned_relay_limit = false;
        let mut warned_relay_permanent = false;
        let mut was_direct = path_kind::path_kind(&connection).is_direct();

        loop {
            let upgrade_delay = if no_ip_candidate_streak >= RELAY_PERM_STREAK {
                Duration::from_secs(UPGRADE_SECS_PERMANENT)
            } else {
                Duration::from_secs(UPGRADE_SECS)
            };
            tokio::select! {
                _ = stats_tick.tick() => {
                    let s = connection.stats();
                    let kind = path_kind::path_kind(&connection);
                    let bytes = s.udp_tx.bytes.saturating_add(s.udp_rx.bytes);
                    let delta = bytes.saturating_sub(prev_bytes);
                    prev_bytes = bytes;
                    let bps = delta / STATS_SECS;

                    tracing::debug!(
                        %peer,
                        path = kind.as_str(),
                        paths = connection.paths().len(),
                        bps,
                        udp_tx = s.udp_tx.datagrams,
                        udp_rx = s.udp_rx.datagrams,
                        lost_packets = s.lost_packets,
                        lost_bytes = s.lost_bytes,
                        "path stats (path= from iroh paths(); udp_* are Quinn layer counters)"
                    );

                    let now_direct = kind.is_direct();
                    if now_direct && !was_direct {
                        info!(%peer, "{}", tr!("path upgraded to direct (IP)"));
                        if !quiet {
                            eprintln!(
                                "{}",
                                styler.ok(&tr!("path upgraded to direct (IP)"))
                            );
                        }
                        warned_relay_limit = false;
                        warned_relay_permanent = false;
                        slow_relay_streak = 0;
                        no_ip_candidate_streak = 0;
                    }
                    was_direct = now_direct;

                    match kind {
                        path_kind::PathKind::Relay => {
                            no_ip_candidate_streak =
                                no_ip_candidate_streak.saturating_add(1);
                        }
                        path_kind::PathKind::Direct
                        | path_kind::PathKind::RelayWithDirectCandidate => {
                            no_ip_candidate_streak = 0;
                        }
                        path_kind::PathKind::Unknown => {}
                    }
                    if !warned_relay_permanent
                        && no_ip_candidate_streak >= RELAY_PERM_STREAK
                    {
                        warned_relay_permanent = true;
                        let msg = tr!(
                            "no direct IP candidate observed — treating peer as relay-permanent (slowing hole-punch retries). CGNAT without global IPv6 often needs a self-hosted --relay"
                        );
                        tracing::warn!(%peer, "{}", msg);
                        if !quiet {
                            eprintln!("{}", styler.warn(&msg));
                        }
                    }

                    if !now_direct && (ACTIVE_MIN_BPS..RELAY_SLOW_BPS).contains(&bps) {
                        slow_relay_streak = slow_relay_streak.saturating_add(1);
                    } else {
                        slow_relay_streak = 0;
                    }
                    if !warned_relay_limit && slow_relay_streak >= 2 {
                        warned_relay_limit = true;
                        let kbps = bps / 1024;
                        let msg = tr_fmt!(
                            "low throughput while on relay (~{0} KB/s) — public relays rate-limit; self-host with --relay (and raise iroh-relay client limits) or wait for direct. See docs/performance.md",
                            kbps
                        );
                        tracing::warn!(%peer, path = kind.as_str(), bps, "{}", msg);
                        if !quiet {
                            eprintln!("{}", styler.warn(&msg));
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_upgrade), if !relay_only => {
                    next_upgrade = tokio::time::Instant::now() + upgrade_delay;
                    // Experiment gates (env, temporary):
                    // - LINK_P2P_NO_PATH_NUDGE=1  → never call network_change
                    // - LINK_P2P_FORCE_PATH_NUDGE=1 → nudge even when already
                    //   direct (stress CID churn / Tailscale re-probe)
                    let force = std::env::var_os("LINK_P2P_FORCE_PATH_NUDGE").is_some();
                    let disable = std::env::var_os("LINK_P2P_NO_PATH_NUDGE").is_some();
                    let should_nudge =
                        !disable && (force || !path_kind::path_kind(&connection).is_direct());
                    if should_nudge {
                        tracing::debug!(
                            %peer,
                            secs = upgrade_delay.as_secs(),
                            force,
                            "nudging magicsock (network_change) for path upgrade retry"
                        );
                        endpoint.network_change().await;
                    } else if disable {
                        tracing::debug!(
                            %peer,
                            "skipping path nudge (LINK_P2P_NO_PATH_NUDGE set)"
                        );
                    }
                }
                _ = connection.closed() => break,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// connect: dial a remote node once, then for every local TCP connection open
// a fresh QUIC stream on that same connection and pipe.
// ---------------------------------------------------------------------------

/// Reconnect backoff bounds: 1s, 2s, 4s, ... capped at 30s. Shared with the
/// TUN reconnect loop (tun.rs).
pub(crate) const RECONNECT_BASE: Duration = Duration::from_secs(1);
pub(crate) const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// A connection must stay up at least this long before a successful dial
/// counts as "stable" for backoff purposes. Handshake-then-instant-kick
/// (relay identity conflict, brief path flaps) must *not* reset backoff —
/// otherwise the watcher redials in a tight loop with no sleep.
pub(crate) const MIN_STABLE_CONN: Duration = Duration::from_secs(5);

/// Exponential backoff with a cap, shared by the stream-mode reconnect
/// watcher and the TUN reconnect loop. `next()` returns the delay for the
/// *next* attempt and then advances (1s, 2s, 4s, ... capped); `reset()`
/// restarts from the base — call it only after a *stable* session, not
/// merely after `connect()` returns `Ok`.
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

    /// After a live session ends: reset if it was stable, otherwise advance
    /// and return the sleep before the next dial. `None` = redial immediately.
    pub(crate) fn after_session(
        &mut self,
        lived: Duration,
        min_stable: Duration,
    ) -> Option<Duration> {
        if lived >= min_stable {
            self.reset();
            None
        } else {
            Some(self.next())
        }
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
pub(crate) struct ConnSlot(Arc<watch::Sender<Option<Connection>>>);

impl ConnSlot {
    pub(crate) fn new(initial: Option<Connection>) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self(Arc::new(tx))
    }

    pub(crate) fn replace(&self, conn: Option<Connection>) {
        // send() returns Err only when all receivers are dropped — at that
        // point nobody is waiting for a reconnect anyway.
        let _ = self.0.send(conn);
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<Connection>> {
        self.0.subscribe()
    }

    pub(crate) fn borrow(&self) -> Option<Connection> {
        self.0.borrow().clone()
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
/// - `open_bi` hangs past `open_timeout`: log [`Connection::stats`] /
///   `close_reason` / `paths`, close **only this connection** (not the
///   endpoint), clear the slot, and wait for a redial. Callers that dial
///   must run [`spawn_reconnect_watcher`] (or equivalent) or this waits
///   forever after a hang.
pub(crate) async fn open_stream_wait(slot: &ConnSlot) -> Result<(SendStream, RecvStream)> {
    open_stream_wait_deadline(slot, Duration::from_secs(5)).await
}

/// Like [`open_stream_wait`], but with an explicit `open_bi` deadline.
pub(crate) async fn open_stream_wait_deadline(
    slot: &ConnSlot,
    open_timeout: Duration,
) -> Result<(SendStream, RecvStream)> {
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
        match time::timeout(open_timeout, conn.open_bi()).await {
            Ok(Ok(pair)) => return Ok(pair),
            Ok(Err(e)) if conn.close_reason().is_some() => {
                warn!(error = %e, "{}", tr!("connection lost; waiting for reconnect"));
                // The current value is a dead connection; wait until the
                // watcher replaces it (changed() fires only on a write, so
                // this can't spin).
                rx.changed()
                    .await
                    .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                log_open_bi_timeout(&conn);
                // Force the reconnect watcher (or peer) to install a fresh
                // connection. Do NOT close the Endpoint — only this conn.
                conn.close(0u32.into(), b"open_bi timeout");
                slot.replace(None);
                warn!("{}", tr!("open_bi timed out; waiting for reconnect"));
                rx.changed()
                    .await
                    .map_err(|_| anyhow::anyhow!(tr!("connection slot closed")))?;
            }
        }
    }
}

fn log_open_bi_timeout(conn: &Connection) {
    let stats = conn.stats();
    let close = conn.close_reason();
    let kind = path_kind::path_kind(conn);
    warn!(
        close = ?close,
        path = kind.as_str(),
        paths = conn.paths().len(),
        udp_tx = stats.udp_tx.bytes,
        udp_rx = stats.udp_rx.bytes,
        lost_packets = stats.lost_packets,
        "{}",
        tr!("open_bi timed out (connection still open; see stats/paths)")
    );
}

/// Reconnect watcher: waits for the current connection to die, then re-dials
/// with exponential backoff, swapping the slot on success.
///
/// Backoff resets only when a session lived at least [`MIN_STABLE_CONN`].
/// A handshake that succeeds and then dies in milliseconds (relay kick,
/// path flap) keeps climbing the backoff and sleeps before the next dial —
/// otherwise `connect()` success alone would reset to zero delay and spin.
///
/// Runs for the lifetime of the process. Deliberately NOT tracked in the
/// shutdown drain (`tasks`): it never finishes on its own, and the process
/// exits right after the drain anyway.
///
/// Scope note: this reconnects the QUIC *connection*; process-level restarts
/// are the systemd unit's job (contrib/systemd), they don't mix.
pub(crate) fn spawn_reconnect_watcher(
    slot: &ConnSlot,
    endpoint: &Endpoint,
    dial_addr: EndpointAddr,
    peer: EndpointId,
) {
    let slot = slot.clone();
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX);
        // Pre-existing slot connection (installed by `run_connect` before we
        // spawn) is treated as already stable so its first natural death
        // after a long transfer is not mistaken for a short-lived flap.
        let mut connected_at = if slot.0.borrow().is_some() {
            // Pre-existing connection is treated as already past the stability
            // floor so its first natural death after a long transfer is not
            // mistaken for a short-lived flap.
            Some(
                std::time::Instant::now()
                    .checked_sub(MIN_STABLE_CONN)
                    .expect("MIN_STABLE_CONN fits in Instant clock"),
            )
        } else {
            None
        };
        loop {
            let current = (*slot.0.subscribe().borrow_and_update()).clone();
            if let Some(conn) = current {
                conn.closed().await;
                slot.replace(None);
                let lived = connected_at
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO);
                connected_at = None;
                if let Some(delay) = backoff.after_session(lived, MIN_STABLE_CONN) {
                    warn!(
                        %peer,
                        lived_ms = lived.as_millis() as u64,
                        "{}",
                        tr_fmt!(
                            "connection died quickly; backing off {0} before redial",
                            format!("{delay:?}")
                        )
                    );
                    tokio::time::sleep(delay).await;
                }
            }

            match endpoint.connect(dial_addr.clone(), ALPN).await {
                Ok(conn) => {
                    connected_at = Some(std::time::Instant::now());
                    slot.replace(Some(conn));
                    info!(%peer, "{}", tr!("reconnected to peer"));
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
    });
}

#[allow(clippy::too_many_arguments)] // CLI entry point; explicit config beats a grab-bag struct
async fn run_connect(
    secret_key: SecretKey,
    to: &str,
    mode: ConnectMode,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    max_conns: usize,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    reject_relay_only_with_to_addr(relay_only, &to_addr)?;
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune, relay_only, no_n0_relays)?
        .bind()
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("binding endpoint"))))?;
    wait_online(&endpoint).await?;
    install_extra_relays(&endpoint, relay, no_n0_relays).await?;

    let remote_id: EndpointId = to.parse().map_err(|e| {
        exit::coded(
            exit::USAGE,
            anyhow::Error::new(e).context(tr_fmt!("'{0}' is not a valid EndpointId", to)),
        )
    })?;

    let dial_addr = build_dial_addr(remote_id, relay, &to_addr)?;
    if !to_addr.is_empty() {
        ui.line(styler.dim(&tr_fmt!(
            "dialing the peer's direct address hint(s): {0}",
            to_addr
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    ui.line(styler.info(&tr_fmt!("dialing {0}...", remote_id)));
    let start = std::time::Instant::now();
    let connection = endpoint
        .connect(dial_addr.clone(), ALPN)
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("connecting to remote endpoint"))))?;
    tracing::debug!(
        peer = %remote_id,
        elapsed_ms = start.elapsed().as_millis() as u64,
        "dial completed"
    );

    #[cfg(unix)]
    if matches!(mode, ConnectMode::Stdio) {
        ui.line(styler.ok(&tr!("connected. piping stdin/stdout to the remote peer.")));
        let (mut send, recv) = connection
            .open_bi()
            .await
            .context(tr!("opening stream"))?;
        // Same hello as --listen: serve --forward must see a STREAM frame
        // before accept_bi returns (stdio may stay silent until the remote
        // banner arrives — classic download-first hang without this).
        pipe::write_stream_hello(&mut send).await?;
        let result = pipe::pipe_stdio(send, recv).await;
        endpoint.close().await;
        return result;
    }

    let (local_addr, is_socks5) = match mode {
        ConnectMode::Listen(a) => (a, false),
        ConnectMode::Socks5(a) => (a, true),
        #[cfg(unix)]
        ConnectMode::Stdio => {
            // Stdio returns above after open_bi; this arm is unreachable by
            // construction. Keep a typed error instead of panic.
            return Err(anyhow::anyhow!(
                "internal: ConnectMode::Stdio should have returned earlier"
            ));
        }
    };

    let slot = ConnSlot::new(Some(connection.clone()));
    spawn_reconnect_watcher(&slot, &endpoint, dial_addr, remote_id);
    spawn_path_monitor(
        connection,
        remote_id,
        endpoint.clone(),
        relay_only,
        styler,
        ui.quiet,
    );

    let tcp_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| tr_fmt!("binding local listener on {0}", local_addr))?;
    ui.line(styler.ok(&tr_fmt!(
        "connected. local TCP listener on {0} now forwards to the remote peer.",
        local_addr
    )));

    let semaphore = conn_semaphore(max_conns);

    let mut tasks = Vec::new();

    loop {
        tokio::select! {
            accepted = tcp_listener.accept() => {
                let (mut tcp_stream, client_addr) = accepted?;
                // Without this, a healthy QUIC session with nobody dialing the
                // local listen port looks identical to a "stuck" serve from
                // the far side (keepalive alone never opens a bidi stream).
                tracing::debug!(%client_addr, %local_addr, "local TCP client accepted");
                let slot = slot.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let result = async {
                        if is_socks5 {
                            let target = socks5::accept_handshake(&mut tcp_stream).await?;
                            let _permit = semaphore.acquire_owned().await?;
                            tracing::debug!(%client_addr, "opening QUIC stream for local client");
                            let (mut send, recv) = open_stream_wait(&slot).await?;
                            socks5::write_target(&mut send, &target).await?;
                            pipe::pipe_streams(tcp_stream, send, recv).await
                        } else {
                            let _permit = semaphore.acquire_owned().await?;
                            tracing::debug!(%client_addr, "opening QUIC stream for local client");
                            let (mut send, recv) = open_stream_wait(&slot).await?;
                            // Announce the stream on the wire immediately
                            // (QUIC has no open-stream control frame).
                            pipe::write_stream_hello(&mut send).await?;
                            pipe::pipe_streams(tcp_stream, send, recv).await
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        warn!(%client_addr, error = %e, "{}", tr!("stream error"));
                    }
                }));
            }
            _ = tokio::signal::ctrl_c() => {
                ui.line(styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }

    pipe::drain_tasks(tasks).await;
    endpoint.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// ping: measure RTT to a remote node and report the path (direct or relay).
// ---------------------------------------------------------------------------

/// One ping exchange: open a bi stream, write an 8-byte timestamp, read echo.
async fn ping_exchange(connection: &iroh::endpoint::Connection) -> Result<u64> {
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
    Ok(rtt_us)
}

fn path_kind_human(kind: path_kind::PathKind) -> String {
    match kind {
        path_kind::PathKind::Direct => tr!("path: direct (IP)"),
        path_kind::PathKind::Relay => tr!("path: relay"),
        path_kind::PathKind::RelayWithDirectCandidate => {
            tr!("path: relay (direct IP candidate open, not selected)")
        }
        path_kind::PathKind::Unknown => tr!("path: unknown"),
    }
}

/// `link-p2p ping`: dial with the ping ALPN, exchange timestamps over one-shot
/// streams, and report RTT plus path.
///
/// Magicsock often finishes the handshake on relay first and upgrades to
/// direct in the background. Measuring RTT *before* that upgrade (then
/// labeling the path after `settle_path_kind`) produced contradictory
/// "direct but 600ms+" readings. We therefore report **both**:
/// - **initial**: RTT + path snapshot right after connect (often still relay)
/// - **settled**: wait up to 2s for a direct upgrade, then measure again
///
/// JSON keeps `rtt_us` / `path` as the settled values (the ones to trust for
/// "how good is the path now?") and adds `initial_*` for diagnosis.
async fn run_ping(
    secret_key: SecretKey,
    to: &str,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: TransportTune,
    format: OutputFormat,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    reject_relay_only_with_to_addr(relay_only, &to_addr)?;
    let endpoint = build_endpoint(secret_key, relay, keepalive, idle_timeout, &tune, relay_only, no_n0_relays)?
        .bind()
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("binding endpoint"))))?;
    wait_online(&endpoint).await?;
    install_extra_relays(&endpoint, relay, no_n0_relays).await?;

    let remote_id: EndpointId = to.parse().map_err(|e| {
        exit::coded(
            exit::USAGE,
            anyhow::Error::new(e).context(tr_fmt!("'{0}' is not a valid EndpointId", to)),
        )
    })?;

    let dial_addr = build_dial_addr(remote_id, relay, &to_addr)?;

    if format == OutputFormat::Text {
        ui.line(styler.info(&tr_fmt!("pinging {0}...", remote_id)));
    }
    let connection = endpoint
        .connect(dial_addr, PING_ALPN)
        .await
        .map_err(|e| exit::coded(exit::CONNECT, anyhow::Error::new(e).context(tr!("connecting to remote endpoint"))))?;

    // Snapshot + measure immediately (handshake path — often still relay).
    let initial_kind = path_kind::path_kind(&connection);
    let initial_rtt_us = ping_exchange(&connection).await?;

    // Wait for magicsock relay→direct upgrade when IP transports are enabled.
    // With --relay-only there is nothing to wait for.
    let settle_budget = if relay_only {
        Duration::ZERO
    } else {
        Duration::from_secs(2)
    };
    let settled_kind = path_kind::settle_path_kind(&connection, settle_budget).await;
    let settled_rtt_us = ping_exchange(&connection).await?;

    let stats = connection.stats();
    let initial_path = initial_kind.as_str();
    let settled_path = settled_kind.as_str();

    match format {
        OutputFormat::Json => {
            // Always stdout — machine output for jq, even under -q.
            // `rtt_us` / `path` are settled (trust these); `initial_*` diagnose
            // the post-handshake race.
            println!(
                "{{\"peer\":\"{peer}\",\"rtt_us\":{rtt},\"path\":\"{path}\",\
\"initial_rtt_us\":{init_rtt},\"initial_path\":\"{init_path}\",\
\"settled_rtt_us\":{rtt},\"settled_path\":\"{path}\"}}",
                peer = remote_id,
                rtt = settled_rtt_us,
                path = settled_path,
                init_rtt = initial_rtt_us,
                init_path = initial_path,
            );
        }
        OutputFormat::Text => {
            ui.line(styler.ok(&tr_fmt!(
                "pong from {0}",
                remote_id.fmt_short()
            )));
            ui.line(styler.dim(&tr_fmt!(
                "initial: RTT {0}µs, {1}",
                initial_rtt_us,
                path_kind_human(initial_kind)
            )));
            ui.line(styler.dim(&tr_fmt!(
                "settled: RTT {0}µs, {1}",
                settled_rtt_us,
                path_kind_human(settled_kind)
            )));
            tracing::debug!(
                initial_path = initial_path,
                settled_path = settled_path,
                initial_rtt_us,
                settled_rtt_us,
                udp_tx = stats.udp_tx.datagrams,
                udp_rx = stats.udp_rx.datagrams,
                "ping path from iroh paths(); udp_* are not used for classification"
            );
        }
    }
    endpoint.close().await;
    Ok(())
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
        check_cmd(&Cli::command(), &localized_command(), "<root>");
        std::env::remove_var("LANGUAGE");
        std::env::set_var("LANG", "C");
        std::env::set_var("LC_ALL", "C");
        crate::i18n::init();
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
            // `--help` uses long_help when present; it must also be translated.
            if let Some(llh) = l.get_long_help() {
                assert_ne!(
                    rh.to_string(),
                    llh.to_string(),
                    "{path}: arg --{} long_help was not localized",
                    arg.get_id()
                );
            }
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
