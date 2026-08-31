//! Symmetric `call` reconnect with persistent identities (ignored by default).
//!
//! Needs `target/release/link-p2p` + `tools/iroh-relay`, same as `e2e.rs`.
//! Run: `cargo test --test integration_call -- --ignored --nocapture`

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

fn spawn_call(
    guard: &mut ProcGuard,
    bin: &Path,
    identity: &Path,
    relay_url: &str,
    listen: u16,
    forward: u16,
    peer_id: &str,
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
            "call",
            "--listen",
            &format!("127.0.0.1:{listen}"),
            "--forward",
            &format!("127.0.0.1:{forward}"),
            peer_id,
        ])
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("spawn call"),
    );
}

/// Kill one side and restart with the same identity; peer should redial / re-accept
/// and local `--listen` forward should work again.
#[test]
#[ignore = "needs release binary + local relay; run: cargo test --test integration_call -- --ignored"]
fn call_reconnect_with_persistent_identity() {
    let Some(bin) = binary() else {
        eprintln!("skipping: target/release/link-p2p not built");
        return;
    };
    let Some(relay_bin) = relay_binary() else {
        eprintln!("skipping: tools/iroh-relay not found");
        return;
    };

    let tmp = std::env::temp_dir().join(format!("lp-call-id-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let relay_port = free_port();
    let echo_port = free_port();
    let listen_a = free_port();
    let listen_b = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");
    let id_a_path = tmp.join("a.key");
    let id_b_path = tmp.join("b.key");
    // A valid public key that nobody owns — parses as an EndpointId but is
    // unreachable, so the bootstrap call prints ENDPOINT_ID then idles.
    // (All-zero ids are rejected by iroh as invalid Ed25519 points.)
    let dummy = "364eb40f6eee0089c61b56d7d20d978c0911e611fd95e75dd59c592edaf5a478";

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

    // Bootstrap A: create identity + print ENDPOINT_ID (dial dummy).
    let log_a = tmp.join("a.log");
    spawn_call(
        &mut guard,
        &bin,
        &id_a_path,
        &relay_url,
        listen_a,
        echo_port,
        dummy,
        &log_a,
    );
    wait_for("A ENDPOINT_ID", Duration::from_secs(20), || {
        std::fs::read_to_string(&log_a)
            .map(|c| c.contains("ENDPOINT_ID="))
            .unwrap_or(false)
    });
    let id_a = read_endpoint_id(&log_a);
    let mut a0 = guard.0.pop().unwrap();
    let _ = a0.kill();
    let _ = a0.wait();

    let log_b = tmp.join("b.log");
    spawn_call(
        &mut guard,
        &bin,
        &id_b_path,
        &relay_url,
        listen_b,
        echo_port,
        &id_a,
        &log_b,
    );
    wait_for("B ENDPOINT_ID", Duration::from_secs(20), || {
        std::fs::read_to_string(&log_b)
            .map(|c| c.contains("ENDPOINT_ID="))
            .unwrap_or(false)
    });
    let id_b = read_endpoint_id(&log_b);

    let log_a2 = tmp.join("a2.log");
    spawn_call(
        &mut guard,
        &bin,
        &id_a_path,
        &relay_url,
        listen_a,
        echo_port,
        &id_b,
        &log_a2,
    );

    wait_for("initial forward", Duration::from_secs(45), || {
        tcp_echo_ok(listen_a, b"ping1")
    });

    let mut a_proc = guard.0.pop().unwrap();
    let _ = a_proc.kill();
    let _ = a_proc.wait();
    std::thread::sleep(Duration::from_millis(500));

    let log_a3 = tmp.join("a3.log");
    spawn_call(
        &mut guard,
        &bin,
        &id_a_path,
        &relay_url,
        listen_a,
        echo_port,
        &id_b,
        &log_a3,
    );

    wait_for("reconnect forward", Duration::from_secs(60), || {
        tcp_echo_ok(listen_a, b"ping2")
    });
    assert!(
        tcp_echo_ok(listen_b, b"ping3"),
        "after A restart, B listen should still forward"
    );
}
