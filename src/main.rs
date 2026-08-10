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

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use iroh::{
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::i18n::{tr, tr_fmt};
use crate::style::{ColorMode, Styler};

/// ALPN identifies this application protocol during the QUIC/TLS handshake.
/// Bump the version suffix if you make a breaking change to the framing.
const ALPN: &[u8] = b"link-p2p/tcp-forward/0";

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
    /// exist yet, a new one is generated and saved here. Keep this stable if
    /// you want your EndpointId to stay the same across restarts.
    #[arg(long, global = true, default_value = "identity.key")]
    identity: PathBuf,

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
    /// Print a shell completion script to stdout.
    ///
    /// Redirect it to wherever your shell loads completions from, e.g.
    /// `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`.
    Completions {
        /// Which shell to generate a completion script for.
        shell: Shell,
    },
}

/// The `Command` from derive, with all display strings overridden at runtime
/// so `--help` output is localized. clap derive only accepts string literals,
/// so the structure comes from derive and the text is swapped here.
fn localized_command() -> clap::Command {
    Cli::command()
        .about(tr!("Minimal TCP-over-QUIC forwarder on iroh"))
        .long_about(tr!(
            "link-p2p exposes a local TCP service to a P2P network (or dials one) over a direct, end-to-end encrypted QUIC connection. No TUN device, no root/admin privileges — just a persistent EndpointId and a QUIC hop."
        ))
        .after_help(tr!(
            "QUICK START:\n    # On the machine you want to expose (e.g. its SSH server):\n    link-p2p serve --forward 127.0.0.1:22\n    # -> prints an EndpointId, share it with the other side\n\n    # On the connecting machine:\n    link-p2p connect --to <EndpointId> --listen 127.0.0.1:2222\n    ssh -p 2222 localhost\n\nSHELL COMPLETIONS:\n    link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish\n    link-p2p completions bash > /etc/bash_completion.d/link-p2p\n\nSee README.md for self-hosted --relay setup and benchmarking against WireGuard/Tailscale."
        ))
        .mut_arg(
            "identity",
            |a| a.help(tr!("Path to store/load this node's persistent secret key. If it doesn't exist yet, a new one is generated and saved here. Keep this stable if you want your EndpointId to stay the same across restarts.")),
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
        .mut_subcommand("serve", |s| {
            s.about(tr!("Expose a local TCP service to the P2P network."))
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
            s.about(tr!("Dial a remote node and expose it as a local TCP listener."))
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
        .mut_subcommand("completions", |s| {
            s.about(tr!("Print a shell completion script to stdout."))
                .long_about(tr!(
                    "Print a shell completion script to stdout.\n\nRedirect it to wherever your shell loads completions from, e.g. `link-p2p completions fish > ~/.config/fish/completions/link-p2p.fish`."
                ))
                .mut_arg(
                    "shell",
                    |a| a.help(tr!("Which shell to generate a completion script for.")),
                )
        })
}

#[tokio::main]
async fn main() {
    // gettext first, before any output; falls back to English if the
    // locale/catalogs aren't available.
    if let Err(e) = i18n::init() {
        eprintln!("i18n init failed, falling back to English: {e}");
    }

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

    // Enable iroh's internal logging (RUST_LOG=iroh=debug etc). Without this
    // iroh's tracing events go nowhere, so RUST_LOG would be a no-op.
    //
    // Default filter is scoped rather than a blanket "info": iroh emits a
    // fair amount of info-level chatter internally (relay/discovery churn),
    // which would drown out our own connection-lifecycle logs. Explicit
    // RUST_LOG always wins, e.g. `RUST_LOG=iroh=trace` for the path-selection
    // debugging described in README.md.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("link_p2p=info,iroh=warn")),
        )
        .with_target(true)
        // Skip ANSI color codes when stdout isn't a real terminal (piped to
        // a file, `| tee`, log aggregator, etc) — otherwise every line gets
        // littered with raw escape sequences.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let styler = style::apply_color_mode(color_mode);
    let secret_key = load_or_create_secret_key(&cli.identity)
        .context(tr!("loading/creating persistent identity"))?;

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
        Command::Completions { .. } => unreachable!("handled above"),
    }
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
    match relay {
        Some(relay_url) => {
            // Minimal sets only the mandatory crypto provider; we configure
            // everything else ourselves. Custom relay map from the given URL.
            let relay_map = RelayMap::try_from_iter([relay_url])
                .with_context(|| tr_fmt!("'{0}' is not a valid --relay URL", relay_url))?;
            Ok(Endpoint::builder(presets::Minimal)
                .secret_key(secret_key)
                .relay_mode(RelayMode::Custom(relay_map)))
        }
        None => Ok(Endpoint::builder(presets::N0).secret_key(secret_key)),
    }
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
        .alpns(vec![ALPN.to_vec()])
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

    let handler = ForwardHandler {
        target: forward,
        // 0 = unlimited. usize::MAX keeps the acquire() call shape uniform.
        semaphore: Arc::new(Semaphore::new(if max_conns == 0 {
            usize::MAX
        } else {
            max_conns
        })),
    };
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, handler)
        .spawn();

    tokio::signal::ctrl_c().await?;
    println!("{}", styler.warn(&tr!("shutting down...")));
    router.shutdown().await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct ForwardHandler {
    /// Fixed `--forward` target; `None` means `--proxy` mode where the
    /// destination comes from each stream's header.
    target: Option<SocketAddr>,
    /// Bounds the number of concurrently forwarded streams.
    semaphore: Arc<Semaphore>,
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
            tokio::spawn(async move {
                // The permit lives as long as this stream does; dropping it
                // after handle_forward_stream frees the slot.
                let _permit = permit;
                if let Err(e) = handle_forward_stream(target, send, recv).await {
                    warn!(%peer, error = %e, "{}", tr!("stream error"));
                }
            });
        }

        connection.closed().await;
        info!(%peer, "{}", tr!("connection closed"));
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
    let connection = endpoint
        .connect(dial_addr, ALPN)
        .await
        .context(tr!("connecting to remote endpoint"))?;
    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "connected. local TCP listener on {0} now forwards to the remote peer.",
            local_addr
        ))
    );

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

    loop {
        tokio::select! {
            accepted = tcp_listener.accept() => {
                let (mut tcp_stream, client_addr) = accepted?;
                let connection = connection.clone();
                let semaphore = semaphore.clone();
                tokio::spawn(async move {
                    let result = async {
                        if is_socks5 {
                            // SOCKS5 mode: parse the local client's CONNECT
                            // request, then tell the remote `serve --proxy`
                            // where to dial via the stream header. The
                            // handshake happens before the permit so a client
                            // that never completes it doesn't hold a slot.
                            let target = socks5::accept_handshake(&mut tcp_stream).await?;
                            let _permit = semaphore.acquire_owned().await?;
                            let (mut send, recv) = connection.open_bi().await?;
                            socks5::write_target(&mut send, &target).await?;
                            pipe_streams(tcp_stream, send, recv).await
                        } else {
                            // Plain mode: forward to the remote serve's
                            // fixed --forward target.
                            let _permit = semaphore.acquire_owned().await?;
                            let (send, recv) = connection.open_bi().await?;
                            pipe_streams(tcp_stream, send, recv).await
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        warn!(%client_addr, error = %e, "{}", tr!("stream error"));
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                // Stop accepting new local connections. Streams already
                // spawned above keep running in their own tasks and finish
                // on their own — we don't forcibly cut them here. The
                // process exits once main() returns and those tasks are
                // dropped, so a truly graceful drain would need to track
                // and await their JoinHandles; left out for this MVP.
                println!("{}", styler.warn(&tr!("shutting down...")));
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shared: bidirectional copy between a TCP socket and a QUIC stream pair.
// ---------------------------------------------------------------------------

async fn pipe_streams(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let client_to_remote = async {
        copy(&mut tcp_read, &mut send).await?;
        // Signal "no more data" on the QUIC send side so the peer's
        // tokio::io::copy on its end returns instead of hanging forever.
        send.finish().context(tr!("finishing send stream"))?;
        Ok::<_, anyhow::Error>(())
    };
    let remote_to_client = async {
        copy(&mut recv, &mut tcp_write).await?;
        Ok::<_, anyhow::Error>(())
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
    match (res_client, res_remote) {
        (Some(a), Some(b)) => {
            a?;
            b?;
            Ok(())
        }
        // One direction errored; the other was cancelled by the select! drop.
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => unreachable!("loop exits only when both complete or one errors"),
    }
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
