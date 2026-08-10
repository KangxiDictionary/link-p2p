//! gettext-based internationalization.
//!
//! Two macros are exported at the crate root:
//!   - [`tr!`](crate::tr)  — translate a static string: `tr!("Hello")`
//!   - [`tr_fmt!`](crate::tr_fmt) — translate a template with Rust `{}`
//!     placeholders, then format: `tr_fmt!("hello {0}", name)`
//!
//! Translation lookup is done *before* `format!`, so the `.po`/`.mo`
//! catalogs use Rust-style `{0}` placeholders (not printf `%`).
//!
//! Catalogs live at `<locale_dir>/<lang>/LC_MESSAGES/link-p2p.mo` and are
//! searched for in this order:
//!   1. `LINK_P2P_LOCALEDIR` environment variable
//!   2. `<dir of the running binary>/locales`
//!   3. `<cwd>/locales`
//!   4. `$OUT_DIR/locales` (the build-time compiled catalogs, see build.rs)
//!
//! If no catalog is found (or the locale isn't available), every lookup
//! falls back to the English msgid — same as `gettext` semantics.

use std::path::{Path, PathBuf};

/// Domain name used in `textdomain`/`bindtextdomain`. Must match the .mo
/// file names (`link-p2p.mo`).
const DOMAIN: &str = "link-p2p";

/// Initialize gettext: set the locale from the environment, point the
/// catalog lookup at our locale directory, and force UTF-8 output.
///
/// Must be called from `main` before any threads are spawned — `setlocale`
/// is not thread-safe.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Safety: called before the runtime spawns any threads.
    unsafe {
        // Empty string = use LANG/LC_ALL/LC_MESSAGES from the environment.
        gettextrs::setlocale(gettextrs::LocaleCategory::LcAll, "");
    }

    if let Some(locale_dir) = resolve_locale_dir() {
        gettextrs::bindtextdomain(DOMAIN, &locale_dir)?;
    }
    // The .mo files are UTF-8; without this gettext converts to the
    // locale's legacy codeset (or panics on non-UTF-8 output).
    gettextrs::bind_textdomain_codeset(DOMAIN, "UTF-8")?;
    gettextrs::textdomain(DOMAIN)?;
    Ok(())
}

/// Translate `msgid` and return an owned `String`.
macro_rules! tr {
    ($msgid:literal $(,)?) => {
        gettextrs::gettext($msgid)
    };
}
pub(crate) use tr;

/// Translate a template (with `{0}`, `{1}`, ... placeholders), then format
/// it. `std::format!` requires a literal format string, so placeholders are
/// replaced textually instead — our templates only use positional ones.
macro_rules! tr_fmt {
    ($template:literal, $($arg:expr),* $(,)?) => {{
        // clippy's from_ref suggestion for the single-arg case has a type
        // mismatch inside a macro; the slice is intentional.
        #[allow(clippy::unnecessary_to_owned)]
        let _args = [$($arg.to_string()),*];
        let _template = gettextrs::gettext($template);
        $crate::i18n::tr_fmt_impl(&_template, &_args)
    }};
}
pub(crate) use tr_fmt;

/// Replace `{0}`, `{1}`, ... in `template` with the corresponding `args`.
pub fn tr_fmt_impl(template: &str, args: &[String]) -> String {
    let mut out = template.to_string();
    for (i, arg) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), arg);
    }
    out
}

fn resolve_locale_dir() -> Option<PathBuf> {
    // Explicit override wins unconditionally.
    if let Ok(dir) = std::env::var("LINK_P2P_LOCALEDIR") {
        return Some(PathBuf::from(dir));
    }

    // Candidates in priority order. A directory only counts if it actually
    // contains compiled catalogs — the repo's `locales/` source dir (with
    // .po files but no .mo) must not shadow the compiled ones.
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("locales")); // installed layout
        }
    }
    candidates.push(PathBuf::from("locales")); // running from repo root
    candidates.push(PathBuf::from(env!("OUT_DIR")).join("locales")); // build.rs output

    candidates.into_iter().find(|dir| has_catalog(dir))
}

/// True if `dir` contains at least one `*/LC_MESSAGES/*.mo` file.
fn has_catalog(dir: &Path) -> bool {
    let Ok(langs) = std::fs::read_dir(dir) else {
        return false;
    };
    langs.flatten().any(|lang| {
        if !lang.path().is_dir() {
            return false;
        }
        let messages = lang.path().join("LC_MESSAGES");
        std::fs::read_dir(messages)
            .map(|mut entries| {
                entries.any(|e| {
                    e.ok()
                        .is_some_and(|e| e.path().extension() == Some("mo".as_ref()))
                })
            })
            .unwrap_or(false)
    })
}
