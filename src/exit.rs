//! Process exit codes for shell / systemd / PowerShell scripting.
//!
//! On Unix, see `docs/user-guide/platforms.md`. Stable codes are enabled on all platforms.
//!
//! **Every** failure that should map to a non-[`OTHER`] code must be wrapped with
//! [`coded`] at the call site (locale-safe). [`code_from`] only looks for
//! [`CodedError`] in the chain — there is no English-substring fallback.

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
/// TUN daemon is not running (control socket missing / unreachable).
pub const DAEMON_NOT_RUNNING: i32 = 6;

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
    /// Skip the wrapped `anyhow` *root* and expose its cause.
    ///
    /// [`Display`] already prints that root (`self.source`), so returning it
    /// again from `source()` would duplicate the same message in `{:#}` /
    /// reporter chains. Call sites that must recover a typed marker wrapped
    /// by [`coded`] (e.g. `ProtocolMismatch`) should walk
    /// `CodedError.source.chain()` — see `tun_ctl::ProtocolMismatch::from_error`.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Wrap `err` so [`code_from`] returns `code`.
///
/// **Contract:** do not nest `coded` wrappers. [`code_from`] returns the
/// *outermost* [`CodedError`] in the chain; an inner, more precise code is
/// silently ignored. Nesting is a programmer error — we `assert!` in every
/// build profile so CI / release catches it immediately (not a silent wrong
/// exit code months later).
pub fn coded(code: i32, err: impl Into<anyhow::Error>) -> anyhow::Error {
    let err = err.into();
    assert!(
        !err.chain().any(|c| c.is::<CodedError>()),
        "nested exit::coded(): outermost code wins; wrap the root cause once"
    );
    CodedError {
        code,
        source: err,
    }
    .into()
}

/// Resolve the process exit code for a failure.
///
/// Returns [`OTHER`] unless a [`CodedError`] appears in the error chain.
/// If several are nested (should not happen — see [`coded`]), the **first**
/// (outermost) one wins.
pub fn code_from(err: &anyhow::Error) -> i32 {
    for cause in err.chain() {
        if let Some(c) = cause.downcast_ref::<CodedError>() {
            return c.code;
        }
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
    fn denied_requires_coded_wrapper() {
        // Substring heuristics were removed: uncoded allow-list messages must
        // not accidentally map to DENIED under other locales.
        let err = anyhow!("peer not allowed");
        assert_eq!(code_from(&err), OTHER);
        let err = coded(DENIED, anyhow!("peer not allowed"));
        assert_eq!(code_from(&err), DENIED);
    }

    #[test]
    fn uncoded_translated_connect_is_other() {
        let err = anyhow!("正在连接到远程端点");
        assert_eq!(code_from(&err), OTHER);
    }

    #[test]
    fn nested_coded_outer_wins_when_built_manually() {
        // `coded()` itself panics on nesting; `code_from` still documents
        // outermost-wins if a `CodedError` is constructed by hand.
        let inner = coded(TIMEOUT, anyhow!("idle"));
        let outer = CodedError {
            code: CONNECT,
            source: inner,
        };
        let err: anyhow::Error = outer.into();
        assert_eq!(code_from(&err), CONNECT);
    }

    #[test]
    #[should_panic(expected = "nested exit::coded()")]
    fn coded_rejects_nesting() {
        let inner = coded(TIMEOUT, anyhow!("idle"));
        let _ = coded(CONNECT, inner);
    }
}
