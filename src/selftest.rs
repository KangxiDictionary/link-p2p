//! Host diagnostics shared by top-level `selftest` and `tun selftest`.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::i18n::{tr, tr_fmt};
use crate::relay_probe;
use crate::runtime::{Ui, ENDPOINT_ONLINE_STEPS};
use crate::style::Styler;
#[cfg(windows)]
use crate::tun;
use crate::tun_ctl;

/// Options for [`run_selftest`].
#[derive(Clone, Copy, Debug)]
pub struct SelftestOpts {
    /// Skip loopback TCP echo (relay / platform checks only).
    pub no_echo: bool,
    /// Also run TUN-oriented checks (wintun path, system identity dir).
    pub tun: bool,
}

/// Relay TCP probe (+ optional TUN host checks and loopback echo).
///
/// TCP reachability ≠ UDP/QUIC hole-punch success — selftest says so explicitly.
pub async fn run_selftest(
    relays: &[String],
    opts: SelftestOpts,
    ui: Ui,
    styler: &Styler,
) -> Result<()> {
    let mut failed = 0u32;
    let title = if opts.tun {
        tr!("link-p2p tun selftest")
    } else {
        tr!("link-p2p selftest")
    };
    ui.line(styler.banner(&title));

    ui.line(styler.dim(&tr!("bring-up order (custom relay before online wait):")));
    ui.line(format!("  {}", ENDPOINT_ONLINE_STEPS.join(" → ")));

    if relays.is_empty() {
        ui.line(format!(
            "  {}",
            styler.warn(&tr!(
                "no --relay URLs configured (will use n0 public relays only)"
            ))
        ));
    } else {
        ui.line(styler.dim(&tr!(
            "probing --relay URL(s) over TCP (2s timeout; TCP ok ≠ UDP/QUIC path):"
        )));
        for (url, rtt) in relay_probe::probe_report(relays).await {
            match rtt {
                Some(d) => ui.line(format!("  {} {url}  ({d:?})", styler.ok("ok"))),
                None => {
                    failed += 1;
                    ui.line(format!("  {} {url}", styler.err(&tr!("FAIL"))));
                }
            }
        }
    }

    if opts.tun {
        #[cfg(windows)]
        {
            match tun::wintun_dll_selftest_path() {
                Ok(p) => ui.line(format!(
                    "  {} wintun.dll → {}",
                    styler.ok("ok"),
                    p.display()
                )),
                Err(e) => {
                    failed += 1;
                    ui.line(format!("  {}: {e:#}", styler.err(&tr!("FAIL"))));
                }
            }
        }

        if let Err(e) =
            tun_ctl::verify_identity_parent_writable(&tun_ctl::default_system_identity_path())
        {
            ui.line(format!(
                "  {}: {e:#}",
                styler.warn(&tr!(
                    "system identity directory not writable (ok for ad-hoc; needed for tun service install)"
                ))
            ));
        } else {
            ui.line(format!(
                "  {} {}",
                styler.ok("ok"),
                tr!("system identity directory writable")
            ));
        }
    }

    if !opts.no_echo {
        ui.line(styler.dim(&tr!("loopback TCP echo drain:")));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context(tr!("binding selftest echo listener"))?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await?;
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await?;
            sock.write_all(&buf[..n]).await?;
            sock.shutdown().await?;
            Ok::<_, std::io::Error>(())
        });
        let payload = b"link-p2p-selftest";
        let mut client = TcpStream::connect(addr)
            .await
            .context(tr!("connecting to selftest echo listener"))?;
        client.write_all(payload).await?;
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await?;
        server.await.context("selftest echo join")??;
        if got.as_slice() == payload {
            ui.line(format!(
                "  {} {}",
                styler.ok("ok"),
                tr_fmt!("echo {0} bytes via {1}", payload.len(), addr)
            ));
        } else {
            failed += 1;
            ui.line(format!("  {}", styler.err(&tr!("FAIL echo mismatch"))));
        }
    }

    if failed > 0 {
        anyhow::bail!(crate::exit::coded(
            crate::exit::CONNECT,
            anyhow::anyhow!(tr_fmt!("selftest reported {0} failure(s)", failed)),
        ));
    }
    ui.line(styler.ok(&tr!("selftest passed")));
    Ok(())
}
