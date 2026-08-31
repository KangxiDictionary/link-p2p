//! Process-spawn sanity for TUN daemon skeleton (lock + ready + probe).
//! Unix only (control socket). No root / TUN device.

#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::Duration;

fn temp_xdg() -> (std::path::PathBuf, Option<std::ffi::OsString>) {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "link-p2p-spawn-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let prev = std::env::var_os("XDG_CONFIG_HOME");
    (dir, prev)
}

fn restore_xdg(prev: Option<std::ffi::OsString>) {
    match prev {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
}

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_link-p2p")
}

fn run_test_mode(xdg: &std::path::Path, mode: &str) -> std::process::Output {
    Command::new(exe())
        .env("XDG_CONFIG_HOME", xdg)
        .env(mode, "1")
        .env("LINK_P2P_TUN_ROLE", "hub")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn test mode")
}

#[tokio::test]
async fn spawn_then_down_then_spawn_again() {
    let (dir, prev) = temp_xdg();

    let up1 = run_test_mode(&dir, "LINK_P2P_TUN_TEST_SPAWN");
    assert!(
        up1.status.success(),
        "first spawn failed: {}",
        String::from_utf8_lossy(&up1.stderr)
    );

    let up2 = run_test_mode(&dir, "LINK_P2P_TUN_TEST_SPAWN");
    assert!(
        !up2.status.success(),
        "second spawn should fail while daemon is up"
    );

    let down = run_test_mode(&dir, "LINK_P2P_TUN_TEST_DOWN");
    assert!(
        down.status.success(),
        "down failed: {}",
        String::from_utf8_lossy(&down.stderr)
    );

    // Brief pause so lock/socket cleanup settles.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let up3 = run_test_mode(&dir, "LINK_P2P_TUN_TEST_SPAWN");
    assert!(
        up3.status.success(),
        "spawn after down failed: {}",
        String::from_utf8_lossy(&up3.stderr)
    );

    let _ = run_test_mode(&dir, "LINK_P2P_TUN_TEST_DOWN");
    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_status_when_down_exits_daemon_not_running() {
    let (dir, prev) = temp_xdg();
    let out = Command::new(exe())
        .args(["--ephemeral", "tun", "status"])
        .env("XDG_CONFIG_HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("tun status");
    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(6),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    // Localized catalogs may translate the message; never dump a raw OS connect error.
    assert!(
        !err.contains("connection refused") && !err.contains("os error"),
        "expected coded daemon-not-running message, got {err}"
    );
}

#[test]
fn cli_down_when_down_exits_ok() {
    let (dir, prev) = temp_xdg();
    let out = Command::new(exe())
        .args(["--ephemeral", "tun", "down"])
        .env("XDG_CONFIG_HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("tun down");
    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn concurrent_spawns_only_one_succeeds() {
    let (dir, prev) = temp_xdg();

    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            Command::new(exe())
                .env("XDG_CONFIG_HOME", &dir)
                .env("LINK_P2P_TUN_TEST_SPAWN", "1")
                .env("LINK_P2P_TUN_ROLE", "hub")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn"),
        );
    }

    let mut oks = 0;
    for mut c in children {
        let status = c.wait().expect("wait");
        if status.success() {
            oks += 1;
        }
    }
    assert_eq!(oks, 1, "expected exactly one successful concurrent spawn, got {oks}");

    let down = run_test_mode(&dir, "LINK_P2P_TUN_TEST_DOWN");
    assert!(down.status.success());

    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
}
