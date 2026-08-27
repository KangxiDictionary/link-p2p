//! Process exit codes for shell / systemd scripting.
//!
//! Prefer wrapping failures with [`coded`] at the call site so the code is
//! intentional. [`code_from`] also applies light heuristics for errors that
//! bubble up as plain `anyhow` (e.g. iroh connect failures).

use std::fmt;

/// Success.
#[allow(dead_code)] // documented in docs/unix.md; success path returns Ok(())
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
    let s = format!("{err:#}").to_ascii_lowercase();
    if s.contains("peer not allowed") || s.contains("not in the --allow") {
        return DENIED;
    }
    if s.contains("timed out") || s.contains("idle timeout") || s.contains("timeout") {
        return TIMEOUT;
    }
    if s.contains("connecting to remote")
        || s.contains("connection refused")
        || s.contains("failed to connect")
        || s.contains("dial")
    {
        return CONNECT;
    }
    OTHER
}
