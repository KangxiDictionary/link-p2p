//! Persistent user config (`~/.config/link-p2p/config.toml`).
//!
//! CLI flags still win when set; this file is the defaults for `call` and for
//! merging extra relays into the n0 map without typing flags every time.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::i18n::{tr, tr_fmt};

/// On-disk config. Missing file → [`UserConfig::default`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserConfig {
    pub relays: RelaySection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RelaySection {
    /// Extra relay URLs (self-hosted). Merged with n0 unless `no_n0` is set.
    pub urls: Vec<String>,
    /// If true, use only `urls` (old `--relay` replace behavior). Default false
    /// so auto/call mode keeps n0 discovery + public relays as fallback.
    pub no_n0: bool,
    /// Default `--relay-only` when the CLI flag is absent.
    pub relay_only: bool,
}

/// Directory that holds identity, config, and contacts.
pub fn config_dir() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(base).join("link-p2p");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".config").join("link-p2p");
    }
    PathBuf::from(".")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn load(path: &Path) -> Result<UserConfig> {
    match fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).with_context(|| tr_fmt!("parsing config {0}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserConfig::default()),
        Err(e) => Err(e).with_context(|| tr_fmt!("reading config {0}", path.display())),
    }
}

/// Like [`load`], but on parse/IO errors log a warning and return defaults
/// instead of failing the whole process (CLI still works). Missing file is
/// silent success via [`load`]; permission / TOML failures are warned with
/// the underlying error so operators can tell "ignored bad file" from
/// "no config yet".
pub fn load_or_default(path: &Path) -> UserConfig {
    match load(path) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "{}",
                tr!("failed to load config; using defaults")
            );
            UserConfig::default()
        }
    }
}

pub fn save(path: &Path, cfg: &UserConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating config directory {0}", parent.display()))?;
    }
    let text = toml::to_string_pretty(cfg).context(tr!("serializing config"))?;
    fs::write(path, text).with_context(|| tr_fmt!("writing config {0}", path.display()))
}

/// Merge CLI `--relay` with config file relays (**CLI entries first**, then
/// config URLs not already listed). Preserves first-seen order; equality is
/// exact string match (no URL normalization — `https://a/` ≠ `https://a`).
pub fn merge_relay_urls(cli: &[String], cfg: &UserConfig) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for u in cli.iter().chain(cfg.relays.urls.iter()) {
        if seen.insert(u.as_str()) {
            out.push(u.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty() {
        let dir = std::env::temp_dir().join(format!("link-p2p-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let cfg = UserConfig {
            relays: RelaySection {
                urls: vec!["http://127.0.0.1:3340".into()],
                no_n0: false,
                relay_only: false,
            },
        };
        save(&path, &cfg).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.relays.urls, cfg.relays.urls);
        let _ = fs::remove_dir_all(&dir);
    }
}
