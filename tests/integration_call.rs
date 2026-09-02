//! Phone-mode `call`: standing callee + dial / accept (ignored by default).
//!
//! Needs `target/release/link-p2p` + `tools/iroh-relay`, same as `e2e.rs`.
//! Run: `cargo test --test integration_call -- --ignored --nocapture`
//!
//! Unix-only (stream call ctl socket).

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn pin_test_locale(cmd: &mut Command) {
    cmd.env("LANG", "C")
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env_remove("LINK_P2P_LOCALEDIR");
}

struct ProcGuard(Vec<Child>);
impl Drop for ProcGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

fn read_endpoint_id(log: &Path) -> String {
    let content = std::fs::read_to_string(log).unwrap_or_default();
    for line in content.lines() {
        if let Some(id) = line.strip_prefix("ENDPOINT_ID=") {
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return id.to_string();
            }
        }
    }
    panic!("ENDPOINT_ID= not found in {}", log.display());
}

fn tcp_echo_ok(port: u16, payload: &[u8]) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
    if s.write_all(payload).is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    match s.read_exact(&mut buf) {
        Ok(()) => buf == payload,
        Err(_) => false,
    }
}

fn spawn_echo(port: u16) {
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("echo");
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
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
}

fn spawn_up(
    guard: &mut ProcGuard,
    bin: &Path,
    identity: &Path,
    xdg: &Path,
    relay_url: &str,
    listen: u16,
    forward: u16,
    log: &Path,
) {
    let out = std::fs::File::create(log).unwrap();
    let mut cmd = Command::new(bin);
    pin_test_locale(&mut cmd);
    guard.0.push(
        cmd.args([
            "--identity",
            identity.to_str().unwrap(),
            "--relay",
            relay_url,
            "--no-n0-relays",
            "call",
            "up",
            "--foreground",
            "--listen",
            &format!("127.0.0.1:{listen}"),
            "--forward",
            &format!("127.0.0.1:{forward}"),
        ])
        .env("XDG_CONFIG_HOME", xdg)
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("spawn call up"),
    );
}

fn run_dial(bin: &Path, identity: &Path, xdg: &Path, relay_url: &str, peer: &str) {
    let mut cmd = Command::new(bin);
    pin_test_locale(&mut cmd);
    let status = cmd
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--relay",
            relay_url,
            "--no-n0-relays",
            "call",
            peer,
            "--no-wait",
        ])
        .env("XDG_CONFIG_HOME", xdg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("dial");
    assert!(status.success(), "dial {peer} failed");
}

fn run_accept(bin: &Path, identity: &Path, xdg: &Path, peer: &str) {
    let mut cmd = Command::new(bin);
    pin_test_locale(&mut cmd);
    let status = cmd
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "call",
            "accept",
            peer,
        ])
        .env("XDG_CONFIG_HOME", xdg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("accept");
    assert!(status.success(), "accept {peer} failed");
}

/// Kill the callee and bring it back; dialer redials and local `--listen` works again.
#[test]
#[ignore = "needs release binary + local relay; run: cargo test --test integration_call -- --ignored"]
fn call_phone_reconnect_with_persistent_identity() {
    let Some(bin) = binary() else {
        eprintln!("skipping: target/release/link-p2p not built");
        return;
    };
    let Some(relay_bin) = relay_binary() else {
        eprintln!("skipping: tools/iroh-relay not found");
        return;
    };

    let tmp = std::env::temp_dir().join(format!("lp-call-phone-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let xdg_a = tmp.join("xdg-a");
    let xdg_b = tmp.join("xdg-b");
    std::fs::create_dir_all(&xdg_a).unwrap();
    std::fs::create_dir_all(&xdg_b).unwrap();

    let relay_port = free_port();
    let echo_port = free_port();
    let listen_a = free_port();
    let listen_b = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");
    let id_a_path = tmp.join("a.key");
    let id_b_path = tmp.join("b.key");

    spawn_echo(echo_port);

    let mut guard = ProcGuard(Vec::new());
    let relay_cfg = tmp.join("relay.toml");
    std::fs::write(
        &relay_cfg,
        format!("http_bind_addr = \"127.0.0.1:{relay_port}\"\nenable_metrics = false\n"),
    )
    .unwrap();
    guard.0.push(
        Command::new(&relay_bin)
            .args(["--dev", "-c"])
            .arg(&relay_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("relay"),
    );
    std::thread::sleep(Duration::from_millis(400));

    let log_a = tmp.join("a.log");
    spawn_up(
        &mut guard,
        &bin,
        &id_a_path,
        &xdg_a,
        &relay_url,
        listen_a,
        echo_port,
        &log_a,
    );
    wait_for("A ENDPOINT_ID", Duration::from_secs(20), || {
        std::fs::read_to_string(&log_a)
            .map(|c| c.contains("ENDPOINT_ID="))
            .unwrap_or(false)
    });
    let id_a = read_endpoint_id(&log_a);

    let log_b = tmp.join("b.log");
    spawn_up(
        &mut guard,
        &bin,
        &id_b_path,
        &xdg_b,
        &relay_url,
        listen_b,
        echo_port,
        &log_b,
    );
    wait_for("B ENDPOINT_ID", Duration::from_secs(20), || {
        std::fs::read_to_string(&log_b)
            .map(|c| c.contains("ENDPOINT_ID="))
            .unwrap_or(false)
    });
    let id_b = read_endpoint_id(&log_b);

    run_dial(&bin, &id_b_path, &xdg_b, &relay_url, &id_a);
    wait_for("A ringing", Duration::from_secs(30), || {
        std::fs::read_to_string(&log_a)
            .map(|c| c.contains("incoming call") || c.contains("ringing"))
            .unwrap_or(false)
            || Command::new(&bin)
                .args(["--identity", id_a_path.to_str().unwrap(), "call", "ring"])
                .env("XDG_CONFIG_HOME", &xdg_a)
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout).contains(&id_b)
                        || String::from_utf8_lossy(&o.stderr).contains(&id_b)
                })
                .unwrap_or(false)
    });
    run_accept(&bin, &id_a_path, &xdg_a, &id_b);

    wait_for("initial forward", Duration::from_secs(45), || {
        tcp_echo_ok(listen_a, b"ping1")
    });
    assert!(tcp_echo_ok(listen_b, b"ping1b"), "B listen should forward");

    // Drop A's standing daemon. Spawn order: relay, A, B.
    let b_proc = guard.0.pop().unwrap();
    let mut a_proc = guard.0.pop().unwrap();
    let _ = a_proc.kill();
    let _ = a_proc.wait();
    guard.0.push(b_proc);
    std::thread::sleep(Duration::from_millis(500));

    let log_a2 = tmp.join("a2.log");
    spawn_up(
        &mut guard,
        &bin,
        &id_a_path,
        &xdg_a,
        &relay_url,
        listen_a,
        echo_port,
        &log_a2,
    );
    wait_for("A2 ENDPOINT_ID", Duration::from_secs(20), || {
        std::fs::read_to_string(&log_a2)
            .map(|c| c.contains("ENDPOINT_ID="))
            .unwrap_or(false)
    });

    run_dial(&bin, &id_b_path, &xdg_b, &relay_url, &id_a);
    wait_for("A2 ringing", Duration::from_secs(30), || {
        Command::new(&bin)
            .args(["--identity", id_a_path.to_str().unwrap(), "call", "ring"])
            .env("XDG_CONFIG_HOME", &xdg_a)
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                out.contains(&id_b) || err.contains(&id_b) || !out.contains("no ringing")
            })
            .unwrap_or(false)
    });
    run_accept(&bin, &id_a_path, &xdg_a, &id_b);

    wait_for("reconnect forward", Duration::from_secs(60), || {
        tcp_echo_ok(listen_a, b"ping2")
    });
    assert!(
        tcp_echo_ok(listen_b, b"ping3"),
        "after A restart, B listen should still forward"
    );
}
