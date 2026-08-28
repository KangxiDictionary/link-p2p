//! End-to-end tests that spawn the real binaries against a local relay.
//!
//! These are marked `#[ignore]` on purpose: they spawn processes, bind ports,
//! and need `target/release/link-p2p` plus `tools/iroh-relay` to exist, so
//! they're run explicitly (`cargo test -- --ignored`) rather than on every
//! `cargo test`. Each missing prerequisite is reported and skipped, not
//! panicked on.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// DRAIN_TIMEOUT in the binary is 5s; give the exit check margin on top.
const EXIT_DEADLINE: Duration = Duration::from_secs(12);

fn manifest() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn binary() -> Option<PathBuf> {
    let p = PathBuf::from(manifest()).join("target/release/link-p2p");
    p.is_file().then_some(p)
}

fn relay_binary() -> Option<PathBuf> {
    let p = PathBuf::from(manifest()).join("tools/iroh-relay");
    p.is_file().then_some(p)
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

/// Kill every tracked child when the test ends, whatever the outcome.
struct ProcGuard(Vec<Child>);
impl Drop for ProcGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Send SIGINT (as Ctrl+C would) via the `kill` binary — no libc dependency.
fn send_sigint(child: &Child) {
    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status();
}

/// Wait for `child` to exit within `EXIT_DEADLINE` and assert it exited cleanly.
fn wait_exit(what: &str, child: &mut Child) {
    let deadline = Instant::now() + EXIT_DEADLINE;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(status.success(), "{what} exited abnormally: {status:?}");
                return;
            }
            None => {
                assert!(
                    Instant::now() < deadline,
                    "{what} did not exit within the drain window + margin"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Pin locale for spawned test binaries. `LANG=C` alone is not enough when
/// `LANGUAGE` is set — gettext prefers it over `LANG`.
fn pin_test_locale(cmd: &mut Command) {
    cmd.env("LANG", "C");
    cmd.env("LC_ALL", "C");
    cmd.env_remove("LANGUAGE");
}

/// Parse the machine line `ENDPOINT_ID=<64 hex>` from serve/tun serve stdout.
fn extract_endpoint_id(log: &Path) -> String {
    let content = std::fs::read_to_string(log).expect("serve log readable");
    for line in content.lines() {
        if let Some(id) = line.strip_prefix("ENDPOINT_ID=") {
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return id.to_string();
            }
        }
    }
    panic!("ENDPOINT_ID= line not found in {}", log.display());
}

fn serve_log_has_endpoint_id(log: &Path) -> bool {
    std::fs::read_to_string(log)
        .map(|content| {
            content.lines().any(|line| {
                line.strip_prefix("ENDPOINT_ID=")
                    .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            })
        })
        .unwrap_or(false)
}

#[test]
#[ignore = "needs release binary + local relay; run: cargo test -- --ignored"]
fn e2e_forward_roundtrip_and_clean_shutdown() {
    let Some(bin) = binary() else {
        eprintln!("skipping: target/release/link-p2p not built (run: cargo build --release)");
        return;
    };
    let Some(relay_bin) = relay_binary() else {
        eprintln!("skipping: tools/iroh-relay not found (see scripts/local-test.sh)");
        return;
    };

    let tmp = std::env::temp_dir().join(format!("lp-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    let relay_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");

    // Echo server: byte-identical round-trip target for the tunnel.
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", echo_port)).expect("echo bind");
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let mut guard = ProcGuard(Vec::new());

    // Relay on a config-file port (no --port flag on iroh-relay).
    // `enable_metrics = false`: --dev also starts a metrics server on a fixed
    // port, and two concurrent e2e tests would collide on it.
    let relay_cfg = tmp.join("relay.toml");
    std::fs::write(
        &relay_cfg,
        format!("http_bind_addr = \"127.0.0.1:{relay_port}\"\nenable_metrics = false\n"),
    )
    .expect("write relay config");
    guard.0.push(
        Command::new(&relay_bin)
            .args(["--dev", "-c"])
            .arg(&relay_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn relay"),
    );

    // serve (ephemeral identity, forward to the echo server).
    let serve_log = tmp.join("serve.log");
    let serve_out = std::fs::File::create(&serve_log).expect("serve log file");
    guard.0.push(
        {
            let mut cmd = Command::new(&bin);
            pin_test_locale(&mut cmd);
            cmd.args([
                "--ephemeral",
                "serve",
                "--forward",
                &format!("127.0.0.1:{echo_port}"),
                "--relay",
                &relay_url,
            ])
            .stdout(Stdio::from(serve_out))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve")
        },
    );

    wait_for("serve EndpointId", Duration::from_secs(30), || {
        serve_log_has_endpoint_id(&serve_log)
    });
    let ep = extract_endpoint_id(&serve_log);

    // connect (ephemeral identity, local listener).
    let conn_log = tmp.join("conn.log");
    let conn_out = std::fs::File::create(&conn_log).expect("conn log file");
    guard.0.push(
        {
            let mut cmd = Command::new(&bin);
            pin_test_locale(&mut cmd);
            cmd.args([
                "--ephemeral",
                "connect",
                "--to",
                &ep,
                "--listen",
                &format!("127.0.0.1:{listen_port}"),
                "--relay",
                &relay_url,
            ])
            .stdout(Stdio::from(conn_out))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect")
        },
    );

    // The listener is up only after the QUIC dial succeeded, so a successful
    // TCP connect to it implies the tunnel is established.
    wait_for("connect listener", Duration::from_secs(30), || {
        TcpStream::connect(("127.0.0.1", listen_port)).is_ok()
    });

    // Byte-identical round trip of a known 128KiB pattern.
    let payload: Vec<u8> = (0u8..=255).cycle().take(128 * 1024).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to tunnel");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    sock.write_all(&payload).expect("write payload");
    sock.shutdown(Shutdown::Write).expect("half-close");
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    while let Ok(n) = sock.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload, "round-tripped bytes differ from the payload");

    // Graceful shutdown: SIGINT both sides, each must exit within the drain
    // window (+ margin), and the listener port must be released.
    send_sigint(&guard.0[2]); // connect
    send_sigint(&guard.0[1]); // serve
    wait_exit("connect", &mut guard.0[2]);
    wait_exit("serve", &mut guard.0[1]);
    TcpListener::bind(("127.0.0.1", listen_port)).expect("listen port released after exit");

    // Clean up the relay and temp dir; drop the guard for anything left.
    let _ = guard.0[0].kill();
    let _ = guard.0[0].wait();
    guard.0.clear();
    let _ = std::fs::remove_dir_all(&tmp);
    eprintln!("e2e: round-trip OK, both sides exited within the drain window");
}

/// Speak the no-auth SOCKS5 CONNECT protocol to `addr`, send `payload`, and
/// return everything the target echoes back. Asserts the handshake succeeded.
fn socks5_connect_and_echo(addr: &str, target: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).expect("connect to socks5 listener");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");

    // Greeting: SOCKS5, offer no-auth.
    s.write_all(&[0x05, 0x01, 0x00]).expect("write greeting");
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).expect("read method selection");
    assert_eq!(sel, [0x05, 0x00], "server selects no-auth");

    // CONNECT to the target (IPv4).
    let (ip, port) = target;
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).expect("write connect request");
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).expect("read connect reply");
    assert_eq!(&rep[0..2], &[0x05, 0x00], "socks5 CONNECT accepted");

    // Echo round trip through the proxy.
    s.write_all(payload).expect("write payload");
    s.shutdown(Shutdown::Write).expect("half-close");
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    got
}

#[test]
#[ignore = "needs release binary + local relay; run: cargo test -- --ignored"]
fn e2e_proxy_socks5_roundtrip_and_clean_shutdown() {
    let Some(bin) = binary() else {
        eprintln!("skipping: target/release/link-p2p not built (run: cargo build --release)");
        return;
    };
    let Some(relay_bin) = relay_binary() else {
        eprintln!("skipping: tools/iroh-relay not found (see scripts/local-test.sh)");
        return;
    };

    let tmp = std::env::temp_dir().join(format!("lp-e2e-socks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    let relay_port = free_port();
    let echo_port = free_port();
    let socks_port = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");

    // Echo server: the destination the SOCKS5 client asks the proxy to reach.
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", echo_port)).expect("echo bind");
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let mut guard = ProcGuard(Vec::new());

    let relay_cfg = tmp.join("relay.toml");
    std::fs::write(
        &relay_cfg,
        format!("http_bind_addr = \"127.0.0.1:{relay_port}\"\nenable_metrics = false\n"),
    )
    .expect("write relay config");
    guard.0.push(
        Command::new(&relay_bin)
            .args(["--dev", "-c"])
            .arg(&relay_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn relay"),
    );

    // serve in proxy mode: the target comes from each stream's header.
    // --allow-private: the test's targets are loopback, which the SSRF
    // guard blocks by default (unit tests cover the guard itself).
    let serve_log = tmp.join("serve.log");
    let serve_out = std::fs::File::create(&serve_log).expect("serve log file");
    guard.0.push(
        {
            let mut cmd = Command::new(&bin);
            pin_test_locale(&mut cmd);
            cmd.args([
                "--ephemeral",
                "serve",
                "--proxy",
                "--allow-private",
                "--relay",
                &relay_url,
            ])
            .stdout(Stdio::from(serve_out))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve")
        },
    );

    wait_for("serve EndpointId", Duration::from_secs(30), || {
        serve_log_has_endpoint_id(&serve_log)
    });
    let ep = extract_endpoint_id(&serve_log);

    // connect as a local SOCKS5 server.
    let conn_log = tmp.join("conn.log");
    let conn_out = std::fs::File::create(&conn_log).expect("conn log file");
    guard.0.push(
        {
            let mut cmd = Command::new(&bin);
            pin_test_locale(&mut cmd);
            cmd.args([
                "--ephemeral",
                "connect",
                "--to",
                &ep,
                "--socks5-listen",
                &format!("127.0.0.1:{socks_port}"),
                "--relay",
                &relay_url,
            ])
            .stdout(Stdio::from(conn_out))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect")
        },
    );

    wait_for("connect socks5 listener", Duration::from_secs(30), || {
        TcpStream::connect(("127.0.0.1", socks_port)).is_ok()
    });

    // Round trip through the SOCKS5 proxy chain, two targets.
    let payload: Vec<u8> = (0u8..=255).cycle().take(128 * 1024).collect();
    let got = socks5_connect_and_echo(
        &format!("127.0.0.1:{socks_port}"),
        ([127, 0, 0, 1], echo_port),
        &payload,
    );
    assert_eq!(got, payload, "proxy round-tripped bytes differ");

    let small: Vec<u8> = b"socks5-over-quic".to_vec();
    let got = socks5_connect_and_echo(
        &format!("127.0.0.1:{socks_port}"),
        ([127, 0, 0, 1], echo_port),
        &small,
    );
    assert_eq!(got, small, "second (short) proxy round-trip differs");

    // Graceful shutdown: SIGINT both sides, exit within the drain window,
    // and the listener port is released.
    send_sigint(&guard.0[2]); // connect
    send_sigint(&guard.0[1]); // serve
    wait_exit("connect", &mut guard.0[2]);
    wait_exit("serve", &mut guard.0[1]);
    TcpListener::bind(("127.0.0.1", socks_port)).expect("socks listener port released after exit");

    let _ = guard.0[0].kill();
    let _ = guard.0[0].wait();
    guard.0.clear();
    let _ = std::fs::remove_dir_all(&tmp);
    eprintln!("e2e: proxy+socks5 round-trip OK, both sides exited within the drain window");
}
