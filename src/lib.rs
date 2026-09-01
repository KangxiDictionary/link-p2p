//! link-p2p: P2P TCP/UDP bridging on iroh (QUIC).
//!
//! Primary commands:
//! - **`serve` / `connect`** — stream mode: forward TCP (or SOCKS5 proxy) over
//!   a QUIC session identified by EndpointId.
//! - **`call`** — symmetric dial (EndpointId tie-break); optional local listen
//!   and `--forward`.
//! - **`tun`** — Layer-3 mesh (hub/spoke VIP routing) with optional system
//!   service install (systemd / LaunchDaemon / Windows SCM).
//! - **`ping` / `contact` / `config`** — diagnostics and local bookkeeping.
//!
//! Identity keys live in [`identity`]; stream pipes in [`pipe`]; SOCKS5 in
//! [`socks5`]. CLI definitions in [`cli`]; shared session helpers in [`runtime`].
//!
//! NOTE ON API STABILITY: iroh's surface has moved a lot release to release
//! (NodeId → EndpointId, …). Calls match the documented 1.x API; if something
//! fails to compile, check `cargo doc -p iroh --open` before assuming the
//! overall approach is wrong.

// Unsafe is confined to audited Windows FFI modules (`win_*.rs` with
// `#![allow(unsafe_code)]`). Use `deny` (not `forbid`): crate-level `forbid`
// cannot be overridden by a module `allow`, so the Windows FFI would not
// compile. `deny` + scoped `allow` still fails the build if someone adds
// `unsafe` outside those modules — on every target, including Windows.
#![deny(unsafe_code)]

mod call;
mod cli;
mod commands;
mod config;
mod contacts;
mod dispatch;
pub mod exit;
mod helptext;
mod i18n;
mod identity;
mod path_kind;
mod path_stats;
mod pipe;
mod relay_probe;
mod relay_rtt;
mod runtime;
mod selftest;
mod socks5;
mod ssrf;
pub mod style;
mod tun;
pub mod tun_ctl;
mod tun_daemon;
mod tun_roster;
mod tun_service;
#[cfg(windows)]
mod win_eventlog;
#[cfg(windows)]
mod win_firewall;
#[cfg(windows)]
mod win_pipe;
#[cfg(windows)]
mod win_service;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!(
    "link-p2p supports Linux, macOS, and Windows only.      Please open a GitHub issue if you need another platform."
);

pub use dispatch::real_main;
pub use i18n::init;
pub use i18n::lookup;

#[cfg(windows)]
pub use win_service::run_dispatcher as run_windows_service_dispatcher;

#[cfg(windows)]
pub fn win_eventlog_error(msg: &str) -> Result<(), String> {
    win_eventlog::error(msg)
}

pub(crate) use identity::{load_or_create_secret_key, resolve_identity_path, validate_passphrase};
pub(crate) use runtime::{
    bring_endpoint_online, build_dial_addr, build_endpoint, conn_semaphore, handle_forward_stream,
    open_stream_wait, push_task, reject_relay_only_with_to_addr, spawn_path_monitor,
    spawn_reconnect_watcher, Backoff, ConnSlot, PingHandler, ServeMode, TransportTune, Ui, ALPN,
    ENDPOINT_ONLINE_STEPS, MIN_STABLE_CONN, PING_ALPN, RECONNECT_BASE, RECONNECT_MAX,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Backoff, ENDPOINT_ONLINE_STEPS};
    use crate::cli::localized_command;

    /// Every help/about text that clap derives must be overridden by
    /// `localized_command()` — otherwise the affected arg/subcommand shows
    /// untranslated English and no check catches it (the derived text is a
    /// plain string literal, not a `tr!` msgid). This walks both command
    /// trees (raw derive output vs the localized builder) and fails if any
    /// text survived unchanged, so adding an arg/subcommand without a
    /// matching mut_arg/mut_subcommand entry breaks `cargo test` instead of
    /// silently shipping English help.
    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        assert_eq!(b.next(), Duration::from_secs(1));
        assert_eq!(b.next(), Duration::from_secs(2));
        assert_eq!(b.next(), Duration::from_secs(4));
        assert_eq!(b.next(), Duration::from_secs(8));
        assert_eq!(b.next(), Duration::from_secs(16));
        // Next would be 32 -> capped at 30, and stays there.
        assert_eq!(b.next(), Duration::from_secs(30));
        assert_eq!(b.next(), Duration::from_secs(30));
        // reset() restarts from the base.
        b.reset();
        assert_eq!(b.next(), Duration::from_secs(1));
    }

    /// Handshake-then-instant-kick must not reset backoff (the bug behind
    /// thousands of redials when a relay rejects a just-opened connection.
    #[test]
    fn backoff_only_resets_after_stable_session() {
        let min = Duration::from_secs(5);
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        // Short-lived: climb 1s → 2s → 4s, never reset.
        assert_eq!(
            b.after_session(Duration::from_millis(50), min),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            b.after_session(Duration::from_millis(200), min),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            b.after_session(Duration::from_secs(4), min),
            Some(Duration::from_secs(4))
        );
        // Lived past the floor → reset; next short death starts at base again.
        assert_eq!(b.after_session(Duration::from_secs(5), min), None);
        assert_eq!(
            b.after_session(Duration::from_millis(10), min),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn endpoint_online_steps_install_relays_before_wait() {
        // Regression: wait_online-before-install_extra_relays made custom
        // --relay useless whenever n0 was unreachable (Windows lab case).
        assert_eq!(
            ENDPOINT_ONLINE_STEPS,
            &["install_extra_relays", "wait_online"]
        );
    }

    #[test]
    fn cli_help_is_fully_localized() {
        // The localized builder resolves translations via the loaded catalog,
        // so pin the language and init it before walking the tree. The shared
        // lock keeps the env mutation race-free with the i18n tests.
        //
        // Catalog is a OnceLock, so we cannot rebuild an English tree in the
        // same process. Instead require every user-facing string under zh_CN
        // to contain CJK — that catches missing .po entries even when
        // `helptext::set_help` shortens an untranslated msgid (brief ≠ full
        // English doc would otherwise make a naive assert_ne pass).
        let _guard = crate::i18n::ENV_LOCK.lock().unwrap();
        std::env::set_var("LANGUAGE", "zh_CN");
        crate::i18n::init();
        check_cmd(&localized_command(), "<root>");
        std::env::remove_var("LANGUAGE");
        std::env::set_var("LANG", "C");
        std::env::set_var("LC_ALL", "C");
        // Restore the English fallback for the rest of the test process —
        // the catalog OnceLock would otherwise keep zh_CN forever.
        crate::i18n::reset_catalog();
        crate::i18n::init();
    }

    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| {
            matches!(
                c,
                '\u{4E00}'..='\u{9FFF}' // CJK Unified Ideographs
                | '\u{3400}'..='\u{4DBF}' // Extension A
                | '\u{F900}'..='\u{FAFF}' // Compatibility Ideographs
            )
        })
    }

    fn check_cmd(loc: &clap::Command, path: &str) {
        for (tag, text) in [
            ("about", loc.get_about()),
            ("long_about", loc.get_long_about()),
            // after_help is the platform quick-start block (command examples stay
            // English by design); skip CJK check for it.
        ] {
            if let Some(t) = text {
                let s = t.to_string();
                assert!(
                    has_cjk(&s),
                    "{path}: {tag} is not localized under zh_CN:\n{s}"
                );
            }
        }

        for arg in loc.get_arguments() {
            // Hidden args (internal flags) are not user-facing help.
            if arg.is_hide_set() {
                continue;
            }
            // Built-in / structural args with no help text are skipped.
            let Some(h) = arg.get_help() else { continue };
            let id = arg.get_id();
            let hs = h.to_string();
            assert!(
                has_cjk(&hs),
                "{path}: arg --{id} short help is not localized under zh_CN:\n{hs}"
            );
            // `set_help` always attaches long_help; bare `.help()` (e.g. -V) may not.
            if let Some(lh) = arg.get_long_help() {
                let ls = lh.to_string();
                assert!(
                    has_cjk(&ls),
                    "{path}: arg --{id} long_help is not localized under zh_CN:\n{ls}"
                );
            }
        }

        for sub in loc.get_subcommands() {
            check_cmd(sub, &format!("{path} {}", sub.get_name()));
        }
    }
}
