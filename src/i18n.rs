//! Internationalization.
//!
//! Two macros are exported at the crate root:
//!   - [`tr!`](crate::tr)  — translate a static string: `tr!("Hello")`
//!   - [`tr_fmt!`](crate::tr_fmt) — translate a template with Rust `{}`
//!     placeholders, then format: `tr_fmt!("hello {0}", name)`
//!
//! Translation lookup is done *before* `format!`, so the `.po`/`.mo`
//! catalogs use Rust-style `{0}` placeholders (not printf `%`).
//!
//! Language selection is ours, not gettext's: the environment variables are
//! read directly (LANGUAGE > LC_ALL > LC_MESSAGES > LANG). When those are
//! unset (typical on Windows), the OS UI language list from `sys-locale` is
//! used instead. The matching catalog is loaded from the `.mo` files compiled
//! by build.rs — `LANG=ja_JP.UTF-8` gives Japanese even on a system that only
//! knows `zh_CN.utf8`, and `LANGUAGE=es_ES` overrides anything (GNU gettext
//! semantics: LANGUAGE is the highest-priority override). `C`/`POSIX`/unknown
//! languages fall back to the English msgids.
//!
//! Catalogs are searched for in this order:
//!   1. `LINK_P2P_LOCALEDIR` environment variable
//!   2. `<dir of the running binary>/locales`
//!   3. `<cwd>/locales`
//!   4. `$OUT_DIR/locales` (the build-time compiled catalogs, see build.rs)
//!
//! If no catalog is found (or the language isn't supported), every lookup
//! falls back to the English msgid — same as gettext semantics.
//!
//! ## Deliberately NOT supported
//!
//! - **Plural forms (ngettext)**: the catalog is a flat msgid -> msgstr map.
//!   No message today needs a quantity-dependent plural (every `{N}`
//!   argument is an identifier, address, duration or a fixed-plural noun),
//!   and Chinese/Japanese have no plural morphology to choose anyway. If a
//!   quantity-based message ever appears, the extension points are `parse_mo`
//!   (msgid_plural entries) and `lookup` (plural-rule selection).
//! - **Runtime language switching**: the catalog is fixed at startup
//!   (`init()` writes it once). A CLI run speaks one language; nothing needs
//!   to change it mid-process. Adding a `--lang` flag later is a change before
//!   `init()`, not a reason to make the catalog hot-swappable. (Test builds
//!   may `reset_catalog()` to re-resolve the language.)
//! - **Zero-copy catalog**: strings are loaded into an owned HashMap once at
//!   startup. At ~150 entries this is microseconds and tens of KB — keeping
//!   the .mo files loadable from disk (LINK_P2P_LOCALEDIR) beats baking them
//!   into the binary with include_bytes!.

use std::collections::HashMap;
use std::path::PathBuf;

/// Domain name used in textdomain/bindtextdomain. Must match the .mo file
/// names (`link-p2p.mo`).
const DOMAIN: &str = "link-p2p";

/// Language code -> catalog directory name. The keys are what the
/// environment variables may contain (after normalization); the values are
/// the on-disk directory names under `locales/`.
const SUPPORTED: &[(&str, &str)] = &[("zh_cn", "zh_CN"), ("ja_jp", "ja_JP"), ("es_es", "es_ES")];

/// Serializes tests that mutate the process environment (both the i18n tests
/// and main.rs's cli_help_is_fully_localized touch LANG/LANGUAGE).
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Loaded catalog (msgid -> msgstr) for the resolved language, or `None`
/// when no catalog applies (English fallback).
///
/// A `Mutex` (not `OnceLock`) so tests can reset the language; production
/// only writes once from [`init`], so reads stay uncontended.
static CATALOG: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);

/// Initialize i18n: resolve the language from the environment and load its
/// catalog. Called once from `main` before anything is printed. Never fails —
/// a missing catalog is the English fallback.
pub fn init() {
    *CATALOG.lock().unwrap() = resolve_lang().and_then(load_catalog);
}

/// Test-only: forget the loaded catalog so [`init`] can resolve a new
/// language. Without this, the zh_CN help check would permanently switch
/// `tr!` lookups to translated strings, breaking message-text assertions in
/// other tests running in the same process.
#[cfg(test)]
pub fn reset_catalog() {
    *CATALOG.lock().unwrap() = None;
}

/// Translate `msgid` and return an owned `String`.
macro_rules! tr {
    ($msgid:literal $(,)?) => {
        $crate::i18n::lookup($msgid)
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
        let _template = $crate::i18n::lookup($template);
        $crate::i18n::tr_fmt_impl(&_template, &_args)
    }};
}
pub(crate) use tr_fmt;

/// Look up `msgid` in the loaded catalog, falling back to the msgid itself
/// (English) when there is no catalog or no entry.
pub fn lookup(msgid: &str) -> String {
    CATALOG
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(msgid))
        .cloned()
        .unwrap_or_else(|| msgid.to_string())
}

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

/// The raw language setting from the environment, first non-empty wins, in
/// GNU gettext's priority order (LANGUAGE overrides everything).
fn env_lang() -> Option<String> {
    ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|var| {
            let v = std::env::var(var).ok()?;
            (!v.is_empty()).then_some(v)
        })
}

/// Normalize one language specifier (e.g. `ja_JP.UTF-8`, `zh-CN`, `es`) to a
/// catalog directory name, or `None` for C/POSIX/unsupported.
fn normalize_lang(raw: &str) -> Option<&'static str> {
    // LANGUAGE may carry a list ("ja_JP:zh_CN") — the caller splits it; here
    // strip an encoding suffix and normalize case/separators.
    let base = raw.split('.').next().unwrap_or(raw);
    let norm = base.replace('-', "_").to_ascii_lowercase();
    match norm.as_str() {
        "c" | "posix" => None,
        // ISO-639 language codes as well as the full language_territory form.
        "zh" => Some("zh_CN"),
        "ja" => Some("ja_JP"),
        "es" => Some("es_ES"),
        _ => SUPPORTED
            .iter()
            .find(|(key, _)| *key == norm)
            .map(|(_, dir)| *dir),
    }
}

/// Candidate locale dirs, in priority order. A dir only counts if it
/// actually contains compiled catalogs.
fn candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("LINK_P2P_LOCALEDIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("locales")); // installed layout
        }
    }
    dirs.push(PathBuf::from("locales")); // running from repo root
    dirs.push(PathBuf::from(env!("OUT_DIR")).join("locales")); // build.rs output
    dirs
}

/// Path to `<lang>/LC_MESSAGES/link-p2p.mo` in the first candidate dir that
/// has one.
fn find_mo_path(lang: &str) -> Option<PathBuf> {
    candidates()
        .into_iter()
        .map(|dir| {
            dir.join(lang)
                .join("LC_MESSAGES")
                .join(format!("{DOMAIN}.mo"))
        })
        .find(|p| p.is_file())
}

/// Preferred language tags for this run: env vars first (GNU gettext order),
/// then the OS UI language list when those are unset (Windows typically has
/// no LANG).
fn language_prefs() -> Vec<String> {
    if let Some(raw) = env_lang() {
        return raw
            .split(':')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    sys_locale::get_locales().collect()
}

/// Resolve the language for this run: walk the preference list and pick the
/// first language we have a catalog for.
fn resolve_lang() -> Option<&'static str> {
    for part in language_prefs() {
        // Skip empty / C / POSIX / unsupported parts; keep looking.
        if let Some(dir) = normalize_lang(&part) {
            if find_mo_path(dir).is_some() {
                return Some(dir);
            }
        }
    }
    None
}

/// Load the msgid -> msgstr map from the compiled catalog for `lang`.
fn load_catalog(lang: &str) -> Option<HashMap<String, String>> {
    let path = find_mo_path(lang)?;
    let bytes = std::fs::read(path).ok()?;
    parse_mo(&bytes)
}

/// Parse a GNU gettext `.mo` file (version 0) into a msgid -> msgstr map.
///
/// Layout: 28-byte header (magic, revision, nstrings, orig_tab_offset,
/// trans_tab_offset, hash_tab_size, hash_tab_offset), then two tables of
/// `nstrings` (length, offset) descriptors, then the string blobs. The hash
/// table is ignored — a linear map is fine at our catalog size. Endianness
/// is detected from the magic.
fn parse_mo(bytes: &[u8]) -> Option<HashMap<String, String>> {
    if bytes.len() < 28 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let big_endian = magic != 0x9504_12de;
    let rd = |off: usize| -> Option<u32> {
        let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(if big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let n = rd(8)? as usize;
    let orig_tab = rd(12)? as usize;
    let trans_tab = rd(16)? as usize;
    let desc = |tab: usize, i: usize| -> Option<(usize, usize)> {
        let off = tab + i * 8;
        let len = rd(off)? as usize;
        let str_off = rd(off + 4)? as usize;
        Some((len, str_off))
    };
    let mut map = HashMap::with_capacity(n);
    for i in 0..n {
        let (olen, ooff) = desc(orig_tab, i)?;
        let (tlen, toff) = desc(trans_tab, i)?;
        let orig = bytes.get(ooff..ooff + olen)?;
        let trans = bytes.get(toff..toff + tlen)?;
        if !orig.is_empty() {
            map.insert(
                String::from_utf8_lossy(orig).into_owned(),
                String::from_utf8_lossy(trans).into_owned(),
            );
        }
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn normalize_lang_handles_suffixes_and_casing() {
        assert_eq!(normalize_lang("ja_JP.UTF-8"), Some("ja_JP"));
        assert_eq!(normalize_lang("zh-CN"), Some("zh_CN"));
        assert_eq!(normalize_lang("es_ES.utf8"), Some("es_ES"));
        assert_eq!(normalize_lang("ja"), Some("ja_JP"));
        assert_eq!(normalize_lang("C"), None);
        assert_eq!(normalize_lang("POSIX"), None);
        assert_eq!(normalize_lang("fr_FR"), None);
    }

    /// Build a minimal valid .mo with the given (msgid, msgstr) pairs.
    fn build_mo(pairs: &[(&str, &str)]) -> Vec<u8> {
        let n = pairs.len() as u32;
        // String offsets in .mo are relative to the file start, so add the
        // header + both tables.
        let base = 28 + 2 * n as usize * 8;
        let mut body = Vec::new();
        let mut origs = Vec::new();
        let mut trans = Vec::new();
        for (o, t) in pairs {
            origs.push((o.len(), base + body.len()));
            body.extend_from_slice(o.as_bytes());
            body.push(0);
            trans.push((t.len(), base + body.len()));
            body.extend_from_slice(t.as_bytes());
            body.push(0);
        }
        let orig_tab = 28u32;
        let trans_tab = 28 + n * 8;
        let mut out = Vec::new();
        out.extend_from_slice(&0x9504_12deu32.to_le_bytes()); // magic
        out.extend_from_slice(&0u32.to_le_bytes()); // revision
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&orig_tab.to_le_bytes());
        out.extend_from_slice(&trans_tab.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // hash size
        out.extend_from_slice(&0u32.to_le_bytes()); // hash offset
        for (len, off) in origs {
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(&(off as u32).to_le_bytes());
        }
        for (len, off) in trans {
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(&(off as u32).to_le_bytes());
        }
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parse_mo_reads_pairs() {
        let mo = build_mo(&[
            ("Hello", "こんにちは"),
            (
                "peer {0} is reachable at {1}",
                "ピア {0} は {1} で到達可能です",
            ),
        ]);
        let map = parse_mo(&mo).expect("parse");
        assert_eq!(map.get("Hello").map(String::as_str), Some("こんにちは"));
        assert_eq!(
            map.get("peer {0} is reachable at {1}").map(String::as_str),
            Some("ピア {0} は {1} で到達可能です")
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_mo_rejects_garbage() {
        assert!(parse_mo(&[]).is_none());
        assert!(parse_mo(&[0u8; 10]).is_none());
    }

    #[test]
    fn locale_dir_override_wins_unconditionally() {
        let _guard = ENV_LOCK.lock().unwrap();
        // The override is honored even when it points at a bogus dir (the
        // caller takes responsibility for the path) — it becomes the first
        // candidate, and resolve_lang just won't find a catalog there.
        let bogus = "/nonexistent/link-p2p-locales";
        std::env::set_var("LINK_P2P_LOCALEDIR", bogus);
        assert_eq!(
            candidates()
                .first()
                .map(|p| p.to_string_lossy().into_owned()),
            Some(bogus.to_string())
        );
        std::env::remove_var("LINK_P2P_LOCALEDIR");
    }

    #[test]
    fn resolve_lang_prefers_language_and_ignores_unsupported() {
        let _guard = ENV_LOCK.lock().unwrap();
        for var in [
            "LANGUAGE",
            "LC_ALL",
            "LC_MESSAGES",
            "LANG",
            "LINK_P2P_LOCALEDIR",
        ] {
            std::env::remove_var(var);
        }
        // LANGUAGE wins over LANG even when LANG is an uninstalled locale
        // (the whole point of reading the environment ourselves).
        std::env::set_var("LANG", "ja_JP.UTF-8");
        std::env::set_var("LANGUAGE", "es_ES");
        assert_eq!(resolve_lang(), Some("es_ES"));

        // Colon lists: first supported language we actually have a catalog
        // for (fr_FR is unsupported -> skipped).
        std::env::set_var("LANGUAGE", "fr_FR:zh_CN");
        assert_eq!(resolve_lang(), Some("zh_CN"));

        // C locale means English.
        std::env::set_var("LANG", "C");
        std::env::remove_var("LANGUAGE");
        assert_eq!(resolve_lang(), None);

        // Uninstalled locale alone now resolves anyway (our own lookup).
        std::env::set_var("LANG", "ja_JP.UTF-8");
        assert_eq!(resolve_lang(), Some("ja_JP"));

        for var in ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
            std::env::remove_var(var);
        }
    }
}
