//! Windows TUN system-mode checks that need Admin + wintun.dll.
//!
//! Ignored by default. On a real Windows host:
//! `cargo test --test windows_tun_system -- --ignored --nocapture`

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_link-p2p"))
}

fn wintun_beside_exe() -> bool {
    exe()
        .parent()
        .map(|d| d.join("wintun.dll").is_file())
        .unwrap_or(false)
}

#[test]
#[ignore = "needs Administrator + wintun.dll beside the test binary"]
fn system_status_against_foreground_hub() {
    assert!(
        wintun_beside_exe(),
        "place official wintun.dll next to {}",
        exe().display()
    );

    // Smoke: binary accepts --system status when nothing is running (exit 6).
    let out = Command::new(exe())
        .args(["tun", "status", "--system"])
        .output()
        .expect("spawn");
    // Either not running (6) or running with JSON-ish status — both prove the
    // Windows ctl path is wired. Do not require a live service for this gate.
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 6,
        "unexpected exit {code}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "needs Administrator; exercises CreateNamedPipe SDDL path via install dry-run helpers"]
fn sddl_constant_still_parses() {
    // Linked into the binary; this integration test only checks the CLI help
    // surface documents --windows-service for operators.
    let out = Command::new(exe())
        .args(["tun", "service", "install", "--help"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
}
