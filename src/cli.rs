//! Clap CLI surface: global flags, subcommands, and localized help text.
//!
//! Extracted from `main` so command dispatch does not share a multi-thousand-line
//! file with endpoint/runtime helpers.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::engine::{ArgValueCompleter, PathCompleter};
use clap_complete::Shell;
use zeroize::Zeroizing;

use crate::contacts;
use crate::helptext;
use crate::i18n::{self, tr};
use crate::style::ColorMode;
use crate::tun_service;

/// Contact / peer-token completer for `--to` and related args (dynamic shells).
fn peer_completer() -> ArgValueCompleter {
    ArgValueCompleter::new(contacts::complete_peer_tokens)
}

fn tun_call_completer() -> ArgValueCompleter {
    ArgValueCompleter::new(contacts::complete_tun_call_args)
}

fn identity_path_completer() -> ArgValueCompleter {
    ArgValueCompleter::new(PathCompleter::file())
}

fn parse_passphrase(s: &str) -> Result<Zeroizing<String>, std::convert::Infallible> {
    Ok(Zeroizing::new(s.to_owned()))
}

#[derive(Parser)]
#[command(
    name = "link-p2p",
    version,
    about = "Minimal TCP-over-QUIC forwarder on iroh",
    long_about = "link-p2p exposes a local TCP service to a P2P network (or dials one) \
                  over a direct, end-to-end encrypted QUIC connection. No TUN device, \
                  no root/admin privileges — just a persistent EndpointId and a QUIC hop.",
    after_help = "See README.md and docs/user-guide/platforms.md."
)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// Path to store/load this node's persistent secret key. If it doesn't
    /// exist yet, a new one is generated and saved there. Default: the XDG
    /// config dir, `$XDG_CONFIG_HOME/link-p2p/identity.key` (usually
    /// `~/.config/link-p2p/identity.key`); a legacy `./identity.key` in the
    /// working directory is migrated there once. Keep this stable if you
    /// want your EndpointId to stay the same across restarts.
    #[arg(
        long,
        global = true,
        conflicts_with = "ephemeral",
        value_hint = ValueHint::FilePath,
        add = identity_path_completer()
    )]
    pub(crate) identity: Option<PathBuf>,

    /// Use a temporary identity that is never written to disk: the EndpointId
    /// changes every start. Conflicts with --identity.
    #[arg(long, short = 'e', global = true, conflicts_with = "identity")]
    pub(crate) ephemeral: bool,

    /// Passphrase protecting the identity key file. When set, the key is
    /// stored encrypted (Argon2id + XChaCha20-Poly1305) instead of plaintext
    /// hex, so a disk/backup leak doesn't expose the key. Prefer the
    /// LINK_P2P_PASSPHRASE environment variable over passing it inline — the
    /// flag value is visible in `ps` and shell history. Conflicts with
    /// --ephemeral.
    ///
    /// Stored in [`Zeroizing`] so Drop clears the heap bytes (best-effort).
    #[arg(
        long,
        global = true,
        conflicts_with = "ephemeral",
        value_parser = parse_passphrase
    )]
    pub(crate) identity_passphrase: Option<Zeroizing<String>>,

    /// Custom relay URL(s), repeatable. Replaces n0's default map when set
    /// (skips n0 DNS/pkarr). Pass several for failover, e.g. a self-hosted
    /// relay first then an n0 URL as backup. **Does not disable hole-punch** —
    /// use `--relay-only` for a true relay-only baseline. Also
    /// `LINK_P2P_RELAY` (comma-separated; flag wins / appends).
    #[arg(long, global = true, env = "LINK_P2P_RELAY", value_delimiter = ',', action = ArgAction::Append)]
    pub(crate) relay: Vec<String>,

    /// Disable IP transports so traffic stays on relay (no hole-punch / LAN
    /// direct). Both sides of a session must set this for a reliable
    /// relay-only baseline. Conflicts with `--to-addr` (direct hints). Also
    /// `LINK_P2P_RELAY_ONLY=1`.
    #[arg(long, global = true, env = "LINK_P2P_RELAY_ONLY", default_value_t = false)]
    pub(crate) relay_only: bool,

    /// When `--relay` is set, do **not** keep n0's public relays / discovery
    /// (replace the map entirely). Default is to **merge** custom relays into
    /// n0 so self-hosted + public failover both work. Also `LINK_P2P_NO_N0_RELAYS`.
    #[arg(long = "no-n0-relays", global = true, env = "LINK_P2P_NO_N0_RELAYS", default_value_t = false)]
    pub(crate) no_n0_relays: bool,

    /// Control colored output: auto (colors on TTY only), always, or never.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub(crate) color: ColorMode,

    /// Maximum number of concurrent forwarded connections. 0 means unlimited.
    /// Prevents resource exhaustion on endpoints exposed to the network.
    #[arg(long, global = true, default_value_t = 1024)]
    pub(crate) max_conns: usize,

    /// Log output format: text (human-readable) or json (structured, for
    /// jq/CI pipelines).
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    pub(crate) log_format: LogFormat,

    /// Quiet user-facing banners (errors still print). Independent of
    /// `RUST_LOG` / `-v`.
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    pub(crate) quiet: bool,

    /// Increase user-facing / tracing detail (`-v`, `-vv`). Ignored when
    /// `RUST_LOG` is set.
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,

    /// QUIC congestion controller: `cubic` (default) or `bbr3`. Also
    /// `LINK_P2P_CC`. Experimental — see docs/architecture/performance.md.
    #[arg(long, global = true, env = "LINK_P2P_CC", value_enum)]
    pub(crate) cc: Option<CongestionControl>,

    /// QUIC connection send window in bytes. Also `LINK_P2P_SEND_WINDOW`.
    #[arg(long, global = true, env = "LINK_P2P_SEND_WINDOW")]
    pub(crate) send_window: Option<u64>,

    /// QUIC per-stream receive window in bytes. Also
    /// `LINK_P2P_STREAM_RECV_WINDOW`.
    #[arg(long, global = true, env = "LINK_P2P_STREAM_RECV_WINDOW")]
    pub(crate) stream_recv_window: Option<u64>,

    /// QUIC keepalive interval in seconds (default 5). Keeps NAT UDP
    /// mappings alive; the typical home-router mapping expires after
    /// 20-30s of idle. Raise it on high-latency links, lower it where
    /// NAT timeouts are aggressive.
    #[arg(long, global = true, default_value_t = 5)]
    pub(crate) keepalive: u64,

    /// QUIC max idle timeout in seconds (default 30). After this long
    /// without traffic the peer is declared dead and the connection
    /// re-dialed. Raise it for lossy / high-latency links so a brief
    /// outage doesn't tear the connection down.
    #[arg(long, global = true, default_value_t = 30)]
    pub(crate) idle_timeout: u64,
}

/// Log output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
pub(crate) enum ContactCommand {
    /// Add or update a contact.
    Add {
        /// Local nickname.
        name: String,
        /// EndpointId hex or short code.
        id: String,
    },
    /// Remove a contact.
    Remove {
        #[arg(add = peer_completer())]
        name: String,
    },
    /// List contacts.
    List,
    /// Print this node's short code (and EndpointId).
    Code,
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommand {
    /// Write a default `config.toml` (refuses to overwrite unless `--force`).
    Init {
        /// Replace an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Print the resolved config file path.
    Path,
}

/// Parsed `link-p2p call …` action (after trailing-arg parse).
#[derive(Debug, Clone)]
pub(crate) enum CallCommand {
    Up {
        listen: Option<SocketAddr>,
        forward: Option<SocketAddr>,
        foreground: bool,
    },
    Down,
    Status,
    Ring,
    Accept {
        peer: String,
    },
    Reject {
        peer: String,
    },
    Dial {
        to: String,
        listen: Option<SocketAddr>,
        forward: Option<SocketAddr>,
        to_addr: Vec<SocketAddr>,
        no_wait: bool,
    },
}

/// Machine-oriented output for status commands (`ping`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

/// QUIC congestion controller selection (maps to noq-proto factories).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum CongestionControl {
    Cubic,
    Bbr3,
}

pub(crate) enum ConnectMode {
    Listen(SocketAddr),
    Socks5(SocketAddr),
    #[cfg(unix)]
    Stdio,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
        #[arg(long, add = peer_completer())]
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
        #[arg(long, env = "LINK_P2P_TO", add = peer_completer())]
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
    /// and wintun.dll on Windows) and routes `172.24.0.0/16` plus
    /// `fd24:ac18::/64` through it.
    /// Unlike `serve`/`connect`, which forward one TCP port, this bridges the
    /// whole machine: TCP, UDP and ICMP on mesh virtual IPs, with no per-port
    /// setup. Outer transport is QUIC datagrams. Hub coordinates the roster;
    /// spokes prefer direct links — see docs/subsystems/tun.md.
    Tun {
        #[command(subcommand)]
        command: TunCommand,
    },
    /// Measure RTT to a remote node over the P2P network.
    Ping {
        /// The remote node's EndpointId (printed by `serve` on startup).
        /// Use `-` to read one line from stdin. Also `LINK_P2P_TO`.
        #[arg(long, env = "LINK_P2P_TO", add = peer_completer())]
        to: Option<String>,
        /// Direct address hint(s) for the peer (repeatable) — see `connect
        /// --to-addr`. Dialed directly, skipping discovery.
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
        /// Output format: text (default) or json (for jq).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Phone-mode stream call: standing callee daemon + dial / ring / accept.
    ///
    /// Examples: `call up --listen 127.0.0.1:2222`, `call alice --listen …`,
    /// `call ring`, `call accept <peer>`, `call down`. Known contacts
    /// auto-accept; strangers ring until accept/reject/timeout.
    Call {
        /// `up` | `down` | `ring` | `status` | `accept <peer>` | `reject <peer>` | `<peer>` to dial.
        #[arg(trailing_var_arg = true, allow_hyphen_values = false)]
        args: Vec<String>,
        /// Local TCP listen address (forwards to the peer).
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Local TCP target for streams the peer opens to us.
        #[arg(long)]
        forward: Option<SocketAddr>,
        /// Direct address hint(s) for dial (repeatable).
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
        /// Return after enqueueing a dial (no short status poll).
        #[arg(long)]
        no_wait: bool,
        /// With `call up`: run in the foreground (do not daemonize).
        #[arg(long)]
        foreground: bool,
    },
    /// Show local path history (direct vs relay) from `ping` / sessions.
    Stats {
        /// How many recent samples to include (default 100).
        #[arg(long, default_value_t = 100)]
        last: usize,
        /// Output format: text (default) or json.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Host diagnostics: relay TCP probe + loopback echo (no identity needed).
    ///
    /// Prefer this before first `serve`/`connect`/`call`. Use `--tun` for
    /// TUN-oriented extras (same as `tun selftest`).
    Selftest {
        /// Skip the loopback TCP echo drain.
        #[arg(long)]
        no_echo: bool,
        /// Also run TUN checks (wintun.dll path, system identity dir).
        #[arg(long)]
        tun: bool,
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
    /// Print a static shell completion script to stdout (AOT).
    ///
    /// Prefer the dynamic installer (`COMPLETE=bash link-p2p`, etc.) so contact
    /// names stay live. Redirect AOT scripts when packaging:
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
pub(crate) enum TunCommand {
    /// Start the TUN mesh (background daemon, or `--foreground` like serve/connect).
    Up {
        /// `hub`, `spoke`, or `phone`. Default: `spoke` if `--to` is set, otherwise `hub`.
        #[arg(long, value_parser = ["hub", "spoke", "phone"])]
        role: Option<String>,
        /// Hub EndpointId when role is spoke (also implies `--role spoke` if role omitted).
        #[arg(long, env = "LINK_P2P_TO", add = peer_completer())]
        to: Option<String>,
        /// Run in the foreground (same as `tun serve` / `tun connect`). Do not daemonize.
        #[arg(long)]
        foreground: bool,
        /// System-service paths (e.g. `/run/link-p2p/tun.sock`). Requires `--foreground`.
        #[arg(long)]
        system: bool,
        /// Internal: running under Windows SCM (set only in the registered service command line).
        #[arg(long, hide = true)]
        windows_service: bool,
        /// Override this node's virtual IP (default: derived from its
        /// EndpointId, inside 172.24.0.0/16). Omit to auto-pick a free address.
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        /// Override this node's IPv6 VIP (default: derived in fd24:ac18::/64).
        /// Omit to auto-pick a free address.
        #[arg(long)]
        tun_ip6: Option<std::net::Ipv6Addr>,
        /// Upper bound for the TUN interface MTU (default 1280). The final
        /// MTU is min(this, the negotiated QUIC datagram max); values above
        /// 1280 are refused.
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        /// Only accept TUN mesh connections from these EndpointIds
        /// (repeatable). Default: anyone who knows this hub's EndpointId.
        /// Also `LINK_P2P_ALLOW` (comma-separated).
        #[arg(long, add = peer_completer())]
        allow: Vec<String>,
        /// Direct address hint(s) for the hub (spoke / foreground only).
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
        /// Spoke: join the hub mesh without appearing on other spokes' rosters.
        #[arg(long)]
        hidden: bool,
    },
    /// Join a hub mesh (alias for `tun up --to <hub>`).
    Join {
        /// Hub EndpointId / contact / short code.
        #[arg(add = peer_completer())]
        to: String,
        #[arg(long)]
        foreground: bool,
        #[arg(long)]
        system: bool,
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        #[arg(long)]
        tun_ip6: Option<std::net::Ipv6Addr>,
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        #[arg(long, add = peer_completer())]
        allow: Vec<String>,
        #[arg(long = "to-addr")]
        to_addr: Vec<SocketAddr>,
        /// Omit yourself from other spokes' roster (hub still knows you).
        #[arg(long)]
        hidden: bool,
    },
    /// Phone-mode: dial a peer, or `accept` / `reject` a ringing call.
    ///
    /// Examples: `tun call alice`, `tun call accept <id>`, `tun call reject <id>`.
    Call {
        /// ` <peer> ` | `accept <peer>` | `reject <peer>`
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = false,
            add = tun_call_completer()
        )]
        args: Vec<String>,
        /// Return after enqueueing the dial (no short status poll).
        #[arg(long)]
        no_wait: bool,
        #[arg(long)]
        system: bool,
    },
    /// List pending inbound phone-mode calls.
    Ring {
        #[arg(long)]
        system: bool,
    },
    /// Stop the background TUN daemon (idempotent if already stopped).
    Down {
        /// Talk to the system-service daemon (fixed runtime paths).
        #[arg(long)]
        system: bool,
    },
    /// Show daemon role / VIP / path / uptime.
    Status {
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Query the system-service daemon (fixed runtime paths).
        #[arg(long)]
        system: bool,
    },
    /// List mesh peers known to the local daemon.
    Peers {
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Query the system-service daemon (fixed runtime paths).
        #[arg(long)]
        system: bool,
    },
    /// Local diagnostics that do not need python/nc: relay TCP probes, identity
    /// path, Windows wintun.dll placement, and a loopback TCP echo drain.
    Selftest {
        /// Skip the loopback echo drain (relay/wintun checks only).
        #[arg(long)]
        no_echo: bool,
    },
    /// Exposed side: coordination hub for a virtual IP mesh. Accepts many
    /// concurrent peers, broadcasts the VIP↔EndpointId roster, bridges this
    /// machine to each, and forwards when spokes have no direct path.
    Serve {
        /// Override this node's virtual IP (default: derived from its
        /// EndpointId, inside 172.24.0.0/16).
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        #[arg(long)]
        tun_ip6: Option<std::net::Ipv6Addr>,
        /// Upper bound for the TUN interface MTU (default 1280). The final
        /// MTU is min(this, the negotiated QUIC datagram max); values above
        /// 1280 are refused.
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        /// Only accept TUN mesh connections from these EndpointIds
        /// (repeatable). Default: anyone who knows this hub's EndpointId.
        /// Also `LINK_P2P_ALLOW` (comma-separated).
        #[arg(long, add = peer_completer())]
        allow: Vec<String>,
    },
    /// Dial a hub (`tun serve`), join the mesh, and try direct peer links.
    Connect {
        /// The remote node's EndpointId (printed by `tun serve` on startup).
        /// Use `-` to read one line from stdin. Also `LINK_P2P_TO`.
        #[arg(long, env = "LINK_P2P_TO", add = peer_completer())]
        to: Option<String>,
        /// Override this node's virtual IP (default: derived from its
        /// EndpointId, inside 172.24.0.0/16).
        #[arg(long)]
        tun_ip: Option<Ipv4Addr>,
        #[arg(long)]
        tun_ip6: Option<std::net::Ipv6Addr>,
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
        #[arg(long, add = peer_completer())]
        allow: Vec<String>,
        /// Omit yourself from other spokes' roster (hub still knows you).
        #[arg(long)]
        hidden: bool,
    },
    /// Install or remove a system service (Linux: systemd; macOS: LaunchDaemon).
    Service {
        #[command(subcommand)]
        command: TunServiceCommand,
    },
}

/// `tun service` subcommands.
#[derive(Subcommand, Clone)]
pub(crate) enum TunServiceCommand {
    /// Write the platform service definition and enable it.
    Install {
        /// `hub` or `spoke`. Default: spoke if `--to` is set, otherwise hub.
        #[arg(long, value_parser = ["hub", "spoke"])]
        role: Option<String>,
        /// Hub EndpointId when role is spoke.
        #[arg(long, env = "LINK_P2P_TO", add = peer_completer())]
        to: Option<String>,
        /// Identity key path for the service (stable EndpointId).
        #[arg(
            long,
            default_value = tun_service::DEFAULT_IDENTITY_PATH,
            value_hint = ValueHint::FilePath,
            add = identity_path_completer()
        )]
        identity: PathBuf,
        /// Unix account the Linux systemd service runs as (ignored on macOS — runs as root).
        #[arg(long, default_value = tun_service::DEFAULT_SERVICE_USER)]
        user: String,
    },
    /// Disable and remove the service unit (keeps `/etc/link-p2p/identity.key`).
    Uninstall,
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
    "QUICK START (same verbs; stream phone vs TUN phone):\n\
    \x20   link-p2p call up --listen 127.0.0.1:2222 --forward 127.0.0.1:22\n\
    \x20   link-p2p call <peer> --listen 127.0.0.1:2222 --forward 127.0.0.1:22\n\
    \x20   link-p2p tun call <peer>   # whole-machine VIP (needs root)\n\
    \x20   link-p2p contact add alice <peer EndpointId>\n\
    \x20   link-p2p selftest\n\
\n\
ALTERNATE (explicit roles):\n\
    \x20   link-p2p serve --forward 127.0.0.1:22\n\
    \x20   link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222\n\
\n\
UNIX-ONLY:\n\
    \x20   connect --stdio, --to -, link-p2p man\n\
\n\
COMPLETIONS:\n\
    \x20   source <(COMPLETE=bash link-p2p)   # or fish/zsh; see docs\n\
    \x20   link-p2p completions fish|bash|zsh > …   # static AOT fallback\n\
\n\
See docs/user-guide/platforms.md and README.md."
}

#[cfg(windows)]
fn platform_after_help() -> &'static str {
    "QUICK START (same verbs; stream phone vs TUN phone):\n\
    \x20   link-p2p call up --listen 127.0.0.1:13389 --forward 127.0.0.1:3389\n\
    \x20   link-p2p call <peer> --listen 127.0.0.1:13389 --forward 127.0.0.1:3389\n\
    \x20   link-p2p tun call <peer>\n\
    \x20   link-p2p contact add alice <peer EndpointId>\n\
    \x20   link-p2p selftest\n\
\n\
ALTERNATE (explicit roles):\n\
    \x20   link-p2p serve --forward 127.0.0.1:3389\n\
    \x20   link-p2p connect --to <EndpointId> --listen 127.0.0.1:13389\n\
\n\
COMPLETIONS:\n\
    \x20   $env:COMPLETE='powershell'; link-p2p | Out-String | Invoke-Expression\n\
    \x20   link-p2p completions powershell   # static AOT fallback\n\
\n\
TUN mode needs Administrator + wintun.dll beside the binary. See docs/user-guide/platforms.md and README.md."
}

#[cfg(not(any(unix, windows)))]
fn platform_after_help() -> &'static str {
    "See README.md. TUN mode supports Linux, macOS, and Windows."
}

#[cfg(unix)]
fn peer_to_help() -> String {
    tr!("Contact name, EndpointId, or short code. Use `-` to read one line from stdin. Also `LINK_P2P_TO`.")
}

#[cfg(not(unix))]
fn peer_to_help() -> String {
    tr!("Contact name, EndpointId, or short code. Also `LINK_P2P_TO`.")
}

pub(crate) fn localized_command() -> clap::Command {
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
            |a| helptext::set_help(a, &tr!("QUIC congestion controller: cubic (default) or bbr3. Also LINK_P2P_CC. See docs/architecture/performance.md.")),
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
                    "Make machines reachable at the IP layer over QUIC datagrams.\n\nCreates a TUN interface (needs root / CAP_NET_ADMIN on Linux and macOS, or Administrator + wintun.dll on Windows). Preferred day-to-day commands: `tun call` (1:1 phone), `tun join <hub>` (mesh channel), `tun status` / `tun peers` / `tun down`. Also `tun up --role phone|hub|spoke`. Foreground aliases: `tun serve` / `tun connect`. Prefer `--cc bbr3` on lossy paths. Dual-stack VIPs: 172.24.0.0/16 and fd24:ac18::/64 (omit --tun-ip/--tun-ip6 to auto-pick on collision) — see docs/subsystems/tun.md."
                )))
                .mut_subcommand("up", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Start the TUN mesh daemon (or run foreground with --foreground)."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Start the TUN mesh.\n\nWithout `--foreground`, spawns a background daemon and returns after it is ready (Unix today; on Windows use `--foreground`). With `--foreground`, blocks like `tun serve` / `tun connect` (same code paths).\n\nRole defaults: if `--to` is set, role is `spoke`; otherwise `hub`. Roles: `hub`, `spoke`, `phone`. Do not pass `--role hub`/`phone` together with `--to`. `--role spoke` requires `--to <hub>`.\n\nAlready-running daemon → usage error (exit 2). Ready timeout → exit 4 (check tun.log). Init failure reported by the child → exit 3."
                        )))
                        .mut_arg(
                            "role",
                            |a| helptext::set_help(a, &tr!("`hub`, `spoke`, or `phone`. Default: spoke if `--to` is set, otherwise hub.")),
                        )
                        .mut_arg(
                            "to",
                            |a| helptext::set_help(a, &peer_to_help()),
                        )
                        .mut_arg(
                            "foreground",
                            |a| helptext::set_help(a, &tr!("Run in the foreground instead of daemonizing (alias of `tun serve` / `tun connect`).")),
                        )
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Use system-service paths (e.g. `/run/link-p2p/tun.sock`). Requires `--foreground`; pin identity with `--identity`.")),
                        )
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "tun_ip6",
                            |a| helptext::set_help(a, &tr!("Override this node's IPv6 VIP (default: derived in fd24:ac18::/64). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "mtu",
                            |a| helptext::set_help(a, &tr!("Upper bound for the TUN interface MTU (default 1280). The final MTU is min(this, the negotiated QUIC datagram max); values above 1280 are refused.")),
                        )
                        .mut_arg(
                            "allow",
                            |a| helptext::set_help(a, &tr!("Only accept TUN mesh connections from these EndpointIds (repeatable). Default: accept anyone who knows this hub's EndpointId. Also LINK_P2P_ALLOW.")),
                        )
                        .mut_arg(
                            "to_addr",
                            |a| helptext::set_help(a, &tr!("Direct address hint(s) for the hub (foreground spoke only) — see `connect --to-addr`.")),
                        )
                        .mut_arg(
                            "hidden",
                            |a| helptext::set_help(a, &tr!("Spoke only: join without appearing on other spokes' rosters (hub still knows you).")),
                        )
                })
                .mut_subcommand("join", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Join a hub mesh channel (alias for `tun up --to <hub>`)."))
                        .mut_arg("to", |a| helptext::set_help(a, &peer_to_help()))
                        .mut_arg(
                            "hidden",
                            |a| helptext::set_help(a, &tr!("Join without appearing on other spokes' rosters (hub still knows you).")),
                        )
                        .mut_arg(
                            "foreground",
                            |a| helptext::set_help(a, &tr!("Run in the foreground instead of daemonizing.")),
                        )
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "tun_ip6",
                            |a| helptext::set_help(a, &tr!("Override this node's IPv6 VIP (default: derived in fd24:ac18::/64). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Use system-service paths. Requires `--foreground`.")),
                        )
                })
                .mut_subcommand("call", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Phone-mode TUN call: dial a peer, or accept/reject a ringing call."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "1:1 TUN calls via the local daemon (remote-control).\n\n`tun call <contact|id>` — start phone daemon if needed, dial, short-poll status.\n`tun call accept <peer>` / `tun call reject <peer>` — decide a ringing stranger call.\nKnown contacts auto-accept; unknowns ring until accept/reject/timeout.\nSee also `tun ring` and daemon logs (`tun.log`)."
                        )))
                        .mut_arg(
                            "args",
                            |a| helptext::set_help(a, &tr!("`<peer>` to dial, or `accept|reject <peer>` for a ringing call.")),
                        )
                        .mut_arg(
                            "no_wait",
                            |a| helptext::set_help(a, &tr!("Enqueue the dial and exit without polling status.")),
                        )
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Talk to the system-service daemon.")),
                        )
                })
                .mut_subcommand("ring", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("List pending inbound phone-mode TUN calls."))
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Query the system-service daemon.")),
                        )
                })
                .mut_subcommand("down", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Stop the background TUN daemon."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Ask the local TUN daemon to shut down and wait until it is gone. Safe to call when nothing is running (exit 0). Use `--system` for the supervisor-managed daemon."
                        )))
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Target the system-service daemon (fixed runtime paths).")),
                        )
                })
                .mut_subcommand("status", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Show TUN daemon status (role, VIP, path, uptime)."))
                        .mut_arg(
                            "format",
                            |a| helptext::set_help(a, &tr!("Output format: text (default) or json (for jq).")),
                        )
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Query the system-service daemon (fixed runtime paths).")),
                        )
                })
                .mut_subcommand("peers", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("List mesh peers known to the local TUN daemon."))
                        .mut_arg(
                            "format",
                            |a| helptext::set_help(a, &tr!("Output format: text (default) or json (for jq).")),
                        )
                        .mut_arg(
                            "system",
                            |a| helptext::set_help(a, &tr!("Query the system-service daemon (fixed runtime paths).")),
                        )
                })
                .mut_subcommand("selftest", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Local diagnostics: relay TCP probe, wintun path, loopback echo drain."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Checks that do not need python or nc: TCP-probe each --relay URL, verify Windows wintun.dll beside the exe, and run a loopback TCP echo drain. Useful when validating a host before starting the mesh."
                        )))
                        .mut_arg(
                            "no_echo",
                            |a| helptext::set_help(a, &tr!("Skip the loopback TCP echo drain (relay/wintun checks only).")),
                        )
                })
                .mut_subcommand("serve", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!("Hub: roster + fallback forward for the virtual IP mesh (foreground)."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Hub: accept many concurrent peers, broadcast the VIP↔EndpointId roster, bridge this machine to each at the IP layer, and forward traffic when spokes have no direct path. Prints this node's virtual IP and EndpointId. Equivalent to `tun up --foreground --role hub`."
                        )))
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "tun_ip6",
                            |a| helptext::set_help(a, &tr!("Override this node's IPv6 VIP (default: derived in fd24:ac18::/64). Omit to auto-pick a free address.")),
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
                        .about(tr!("Dial a hub, join the mesh, and try direct peer links (foreground)."))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Dial a `tun serve` hub, install 172.24.0.0/16 and fd24:ac18::/64 on the TUN, receive the mesh roster, and attempt direct links to other spokes (packets prefer direct; otherwise via hub). Equivalent to `tun up --foreground --role spoke --to <hub>`."
                        )))
                        .mut_arg(
                            "to",
                            |a| helptext::set_help(a, &peer_to_help()),
                        )
                        .mut_arg(
                            "tun_ip",
                            |a| helptext::set_help(a, &tr!("Override this node's virtual IP (default: derived from its EndpointId, inside 172.24.0.0/16). Omit to auto-pick a free address.")),
                        )
                        .mut_arg(
                            "tun_ip6",
                            |a| helptext::set_help(a, &tr!("Override this node's IPv6 VIP (default: derived in fd24:ac18::/64). Omit to auto-pick a free address.")),
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
                        .mut_arg(
                            "hidden",
                            |a| helptext::set_help(a, &tr!("Omit yourself from other spokes' rosters (hub still knows you).")),
                        )
                })
                .mut_subcommand("service", |ss| {
                    ss.disable_help_flag(true)
                        .arg(help_arg())
                        .about(tr!(
                            "Install or remove a TUN system service (Linux systemd; macOS LaunchDaemon; Windows SCM)."
                        ))
                        .long_about(helptext::hard_wrap_help(&tr!(
                            "Manage a platform service for `tun up --foreground --system`. Requires root/Administrator. Refuses to install if this binary is under a user-writable path. Identity defaults to /etc/link-p2p/identity.key (Unix) or %ProgramData%/link-p2p/identity.key (Windows). macOS runs as root LaunchDaemon; Linux uses a dedicated service user with CAP_NET_ADMIN; Windows runs as LocalSystem."
                        )))
                        .mut_subcommand("install", |sss| {
                            sss.disable_help_flag(true)
                                .arg(help_arg())
                                .about(tr!("Install the TUN system service and start it."))
                                .mut_arg(
                                    "role",
                                    |a| helptext::set_help(a, &tr!("`hub` or `spoke`. Default: spoke if `--to` is set, otherwise hub.")),
                                )
                                .mut_arg(
                                    "to",
                                    |a| helptext::set_help(a, &peer_to_help()),
                                )
                                .mut_arg(
                                    "identity",
                                    |a| helptext::set_help(a, &tr!("Service identity key path (default /etc/link-p2p/identity.key).")),
                                )
                                .mut_arg(
                                    "user",
                                    |a| helptext::set_help(a, &tr!(
                                        "Linux systemd only: Unix user the service runs as (default link-p2p). Ignored on macOS (root LaunchDaemon)."
                                    )),
                                )
                        })
                        .mut_subcommand("uninstall", |sss| {
                            sss.disable_help_flag(true)
                                .arg(help_arg())
                                .about(tr!("Disable and remove the TUN system service."))
                        })
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
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Phone-mode stream call: standing callee + dial / ring / accept."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Standing callee daemon (like tun call, without TUN). Start with `call up` (or dial and auto-spawn), then the peer runs `call <your-name>`. Known contacts auto-accept; strangers ring until `call accept` / `call reject` / timeout. Use serve/connect for explicit roles."
                )))
                .mut_arg("args", |a| {
                    helptext::set_help(
                        a,
                        &tr!("`up` | `down` | `ring` | `status` | `accept <peer>` | `reject <peer>` | `<peer>` to dial."),
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
                })
                .mut_arg("no_wait", |a| {
                    helptext::set_help(
                        a,
                        &tr!("Return after enqueueing a dial on the standing daemon."),
                    )
                })
                .mut_arg("foreground", |a| {
                    helptext::set_help(
                        a,
                        &tr!("With `call up`: run in the foreground (do not daemonize)."),
                    )
                })
        })
        .mut_subcommand("stats", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Show local direct-vs-relay path history."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Aggregates samples written by ping and by connect/call/tun sessions when a connection closes (path kind + time-to-direct). Share ~/.config/link-p2p/path-stats.jsonl when debugging NAT — no lab required."
                )))
                .mut_arg(
                    "last",
                    |a| helptext::set_help(a, &tr!("How many recent samples to include (default 100).")),
                )
                .mut_arg(
                    "format",
                    |a| helptext::set_help(a, &tr!("Output format: text (default) or json (for jq).")),
                )
        })
        .mut_subcommand("selftest", |s| {
            s.disable_help_flag(true)
                .arg(help_arg())
                .about(tr!("Host diagnostics: relay TCP probe and loopback echo (no identity)."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Run before first serve/connect/call when a dial times out. TCP-probes each --relay URL (note: TCP ok does not prove UDP/QUIC or that a peer will answer a ring), then a loopback echo. Pass --tun for wintun/system-identity checks (same as tun selftest)."
                )))
                .mut_arg(
                    "no_echo",
                    |a| helptext::set_help(a, &tr!("Skip the loopback TCP echo drain.")),
                )
                .mut_arg(
                    "tun",
                    |a| helptext::set_help(a, &tr!("Also run TUN-oriented checks (wintun path, system identity directory).")),
                )
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
                            |a| helptext::set_help(a, &tr!("EndpointId hex or short code (from the peer's SHORT_CODE= line).")),
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
                .about(tr!("Print a static shell completion script to stdout."))
                .long_about(helptext::hard_wrap_help(&tr!(
                    "Print a static (AOT) shell completion script to stdout.\n\nPrefer dynamic completions so contact names stay live: add `source <(COMPLETE=bash link-p2p)` to your shell rc (fish/zsh/powershell — see docs/user-guide/usage.md). Use this subcommand when packaging files, e.g. `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`."
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

