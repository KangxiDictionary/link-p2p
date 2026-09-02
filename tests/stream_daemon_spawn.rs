//! Process-spawn sanity for stream phone ctl (status/down when idle).
//! Unix only (control socket). No network / Endpoint.

#![cfg(unix)]

use std::process::{Command, Stdio};

fn temp_xdg() -> (std::path::PathBuf, Option<std::ffi::OsString>) {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "link-p2p-call-spawn-{}",
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

#[test]
fn cli_call_status_when_down_exits_daemon_not_running() {
    let (dir, prev) = temp_xdg();
    let out = Command::new(exe())
        .args(["--ephemeral", "call", "status"])
        .env("XDG_CONFIG_HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("call status");
    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(6),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    assert!(
        !err.contains("connection refused") && !err.contains("os error"),
        "expected coded daemon-not-running message, got {err}"
    );
}

#[test]
fn cli_call_down_when_down_exits_ok() {
    let (dir, prev) = temp_xdg();
    let out = Command::new(exe())
        .args(["--ephemeral", "call", "down"])
        .env("XDG_CONFIG_HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("call down");
    restore_xdg(prev);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
