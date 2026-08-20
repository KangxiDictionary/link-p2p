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
///
/// One-pass scan of the template: tokens are located in the original text
/// and the output is built by concatenation, so an argument that itself
/// contains placeholder-shaped text (e.g. "{1}") is inserted verbatim and
/// never re-scanned. The previous implementation replaced tokens one at a
/// time, which let an argument containing "{1}" be substituted a second time
/// by a later pass. Out-of-range indexes and stray braces stay literal.
pub fn tr_fmt_impl(template: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let Some(start) = rest.find('{') else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let digits_end = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits_end == 0 || after.as_bytes().get(digits_end) != Some(&b'}') {
            // Stray "{" (no digits, or no closing "}"): keep the brace
            // literal and keep scanning from the next character.
            out.push('{');
            rest = after;
            continue;
        }
        let token_len = digits_end + 1; // digits + closing '}'
        match after[..digits_end].parse::<usize>() {
            Ok(i) if i < args.len() => out.push_str(&args[i]),
            _ => {
                // Out-of-range or malformed index: keep the token verbatim.
                out.push('{');
                out.push_str(&after[..token_len]);
            }
        }
        rest = &after[token_len..];
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize the env-var-mutating tests: `cargo test` runs them in
    /// parallel and they share the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lp-i18n-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn args_are_not_rescanned() {
        // The {0} argument itself contains "{1}": it must be inserted
        // verbatim, not substituted again by a later pass.
        let args = ["{1}".to_string(), "X".to_string()];
        assert_eq!(tr_fmt_impl("{0} and {1}", &args), "{1} and X");
    }

    #[test]
    fn literal_fallback_cases() {
        // Out-of-range index, stray brace, and plain text stay untouched.
        let args = ["a".to_string()];
        assert_eq!(tr_fmt_impl("{0} {1} {", &args), "a {1} {");
        assert_eq!(tr_fmt_impl("plain", &args), "plain");
        // Multi-digit indexes work.
        let args2 = ["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(tr_fmt_impl("{2}{0}{1}", &args2), "cab");
    }

    #[test]
    fn has_catalog_sees_mo_files() {
        let d = tmp_dir("mo");
        std::fs::create_dir_all(d.join("zh_CN/LC_MESSAGES")).unwrap();
        std::fs::write(d.join("zh_CN/LC_MESSAGES/link-p2p.mo"), b"x").unwrap();
        assert!(has_catalog(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn has_catalog_ignores_po_only_dirs() {
        // The repo's `locales/` source dir has .po but no .mo: it must not
        // be picked as a catalog dir (build.rs compiles .mo into OUT_DIR).
        let d = tmp_dir("po");
        std::fs::create_dir_all(d.join("zh_CN/LC_MESSAGES")).unwrap();
        std::fs::write(d.join("zh_CN/LC_MESSAGES/link-p2p.po"), b"x").unwrap();
        assert!(!has_catalog(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn has_catalog_missing_dir_is_false() {
        assert!(!has_catalog(&PathBuf::from(
            "/nonexistent/link-p2p-no-such-dir"
        )));
    }

    #[test]
    fn locale_dir_override_wins_unconditionally() {
        let _guard = ENV_LOCK.lock().unwrap();
        // The override is honored even when it points at a bogus dir (the
        // caller takes responsibility for the path).
        let bogus = "/nonexistent/link-p2p-locales";
        std::env::set_var("LINK_P2P_LOCALEDIR", bogus);
        assert_eq!(resolve_locale_dir(), Some(PathBuf::from(bogus)));
        std::env::remove_var("LINK_P2P_LOCALEDIR");
    }

    #[test]
    fn locale_dir_falls_back_to_a_compiled_catalog_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("LINK_P2P_LOCALEDIR");
        // The cwd candidate (repo `locales/`) holds only .po files, so the
        // first candidate with a real catalog must be build.rs's OUT_DIR
        // output. Only asserted when msgfmt actually compiled the catalogs.
        let out = PathBuf::from(env!("OUT_DIR")).join("locales");
        if has_catalog(&out) {
            let dir = resolve_locale_dir().expect("compiled catalog exists, so a dir must resolve");
            assert!(has_catalog(&dir));
        }
    }
}
