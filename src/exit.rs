//! Process exit codes for shell / systemd / PowerShell scripting.
//!
//! On Unix, see `docs/user-guide/platforms.md`. Stable codes are enabled on all platforms.
//!
//! Prefer wrapping failures with [`coded`] at the call site (locale-safe).
//! [`code_from`]'s English substring fallback is a last resort for errors that
//! never went through `coded` — do not rely on it for new code, especially
//! anything that uses `tr!()` (translated context strings will not match).

use std::fmt;

/// Success.
#[allow(dead_code)]
pub const OK: i32 = 0;
/// Unexpected / unclassified error.
pub const OTHER: i32 = 1;
/// Bad CLI usage / argument parse failure.
pub const USAGE: i32 = 2;
/// Could not dial or establish the P2P connection.
pub const CONNECT: i32 = 3;
/// Idle / operation timeout.
pub const TIMEOUT: i32 = 4;
/// Peer rejected by `--allow` (or equivalent authorization).
pub const DENIED: i32 = 5;

/// An error that carries a stable process exit code.
#[derive(Debug)]
pub struct CodedError {
    pub code: i32,
    pub source: anyhow::Error,
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for CodedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Wrap `err` so [`code_from`] returns `code`.
pub fn coded(code: i32, err: impl Into<anyhow::Error>) -> anyhow::Error {
    CodedError {
        code,
        source: err.into(),
    }
    .into()
}

/// Resolve the process exit code for a failure.
pub fn code_from(err: &anyhow::Error) -> i32 {
    for cause in err.chain() {
        if let Some(c) = cause.downcast_ref::<CodedError>() {
            return c.code;
        }
    }
    // Last-resort English heuristics for legacy / uncoded paths.
    // `--allow` rejection intentionally uses a non-translated reason
    // (`peer not allowed`) so DENIED still works under any locale.
    let s = format!("{err:#}").to_ascii_lowercase();
    if s.contains("peer not allowed") || s.contains("not in the --allow") {
        return DENIED;
    }
    OTHER
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn coded_wins_over_message_text() {
        let err = coded(CONNECT, anyhow!("完全不相关的中文"));
        assert_eq!(code_from(&err), CONNECT);
        let err = coded(TIMEOUT, anyhow!("binding endpoint"));
        assert_eq!(code_from(&err), TIMEOUT);
    }

    #[test]
    fn denied_heuristic_for_allow_list() {
        let err = anyhow!("peer not allowed");
        assert_eq!(code_from(&err), DENIED);
    }

    #[test]
    fn uncoded_translated_connect_is_other() {
        // Documents why tun/stream must use `coded`: translated contexts
        // must not be expected to match English substrings.
        let err = anyhow!("正在连接到远程端点");
        assert_eq!(code_from(&err), OTHER);
    }
}
