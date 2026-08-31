//! Windows Defender Firewall helpers for the TUN service binary.
//!
//! Program-scoped inbound allow (not a global disable). Uses `netsh` so we
//! stay consistent with route/MTU helpers and avoid more Win32 FFI.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::i18n::{tr, tr_fmt};

/// Stable rule name so install is idempotent and uninstall can find it.
pub const RULE_NAME: &str = "link-p2p-tun";

/// Allow inbound traffic for `exe` (UDP/TCP — QUIC + any control the process needs).
pub fn add_inbound_for_exe(exe: &Path) -> Result<()> {
    let exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    let _ = remove_inbound(); // replace stale rule pointing at an old path
    let program = exe.display().to_string();
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={RULE_NAME}"),
            "dir=in",
            "action=allow",
            &format!("program={program}"),
            "enable=yes",
            "profile=any",
        ])
        .status()
        .context(tr!("running netsh advfirewall to add inbound rule"))?;
    if !status.success() {
        bail!(tr_fmt!(
            "netsh failed to add firewall rule {0} for {1} (exit {2})",
            RULE_NAME,
            program,
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Remove the rule created by [`add_inbound_for_exe`] (idempotent).
pub fn remove_inbound() -> Result<()> {
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={RULE_NAME}"),
        ])
        .status()
        .context(tr!("running netsh advfirewall to delete inbound rule"))?;
    // exit 1 = rule not found — treat as success
    if status.success() || status.code() == Some(1) {
        return Ok(());
    }
    bail!(tr_fmt!(
        "netsh failed to delete firewall rule {0} (exit {1})",
        RULE_NAME,
        status.code().unwrap_or(-1)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_name_is_stable() {
        assert_eq!(RULE_NAME, "link-p2p-tun");
    }
}
