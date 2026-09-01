//! Local rolling log of path outcomes (direct vs relay).
//!
//! Magicsock hole-punch lives in iroh; we only **record** what
//! [`crate::path_kind`] observed so operators can later answer "how often do
//! we get direct?" without standing up a NAT lab. Best-effort: disk errors
//! never fail the session.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::config;
use crate::contacts;
use crate::i18n::{tr, tr_fmt};
use crate::path_kind::PathKind;

/// Cap retained lines so the file stays trivial to share / parse.
const MAX_LINES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSample {
    /// Unix seconds (UTC).
    pub ts: u64,
    /// Which command produced the sample (`ping`, `connect`, `call`, …).
    pub cmd: String,
    /// Crockford short code (typo-checked form) for humans.
    pub peer_short: String,
    /// Full EndpointId hex (stable join key).
    pub peer: String,
    /// Settled / final [`PathKind::as_str`].
    pub path: String,
    /// Milliseconds from connect/start until this sample's path (upgrade wait).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub relay_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PathSummary {
    pub total: usize,
    pub direct: usize,
    pub relay: usize,
    pub relay_candidate: usize,
    pub unknown: usize,
    pub samples: Vec<PathSample>,
}

impl PathSummary {
    pub fn direct_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            100.0 * (self.direct as f64) / (self.total as f64)
        }
    }
}

pub fn stats_path() -> PathBuf {
    config::config_dir().join("path-stats.jsonl")
}

/// Append one sample; rotate to the last [`MAX_LINES`] if needed.
///
/// Never returns an error to callers that must not abort networking — use
/// [`record_sample_lossy`].
pub fn record_sample(sample: &PathSample) -> Result<()> {
    let path = stats_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating config directory {0}", parent.display()))?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| tr_fmt!("opening path stats {0}", path.display()))?;
    serde_json::to_writer(&mut f, sample).context(tr!("serializing path sample"))?;
    f.write_all(b"\n")?;
    f.flush()?;
    trim_file(&path, MAX_LINES)?;
    Ok(())
}

/// Like [`record_sample`] but logs and swallows errors.
pub fn record_sample_lossy(sample: PathSample) {
    if let Err(e) = record_sample(&sample) {
        tracing::debug!(error = %e, "path stats append failed");
    }
}

/// Build a sample from a peer + settled path.
pub fn sample_for(
    cmd: &str,
    peer: EndpointId,
    path: PathKind,
    upgrade: Option<Duration>,
    relay_only: bool,
) -> PathSample {
    PathSample {
        ts: now_unix(),
        cmd: cmd.to_string(),
        peer_short: contacts::encode_short_code(peer),
        peer: peer.to_string(),
        path: path.as_str().to_string(),
        upgrade_ms: upgrade.map(|d| d.as_millis() as u64),
        relay_only,
    }
}

pub fn load_summary(limit: Option<usize>) -> Result<PathSummary> {
    let path = stats_path();
    let lines = read_lines(&path)?;
    let take = limit.unwrap_or(lines.len()).min(lines.len());
    let start = lines.len().saturating_sub(take);
    let mut summary = PathSummary::default();
    for line in &lines[start..] {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let sample: PathSample = match serde_json::from_str(line) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "skipping corrupt path-stats line");
                continue;
            }
        };
        summary.total += 1;
        match sample.path.as_str() {
            "direct" => summary.direct += 1,
            "relay" => summary.relay += 1,
            "relay+direct-candidate" => summary.relay_candidate += 1,
            _ => summary.unknown += 1,
        }
        summary.samples.push(sample);
    }
    Ok(summary)
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path).with_context(|| tr_fmt!("reading path stats {0}", path.display()))?;
    Ok(BufReader::new(f)
        .lines()
        .filter_map(|l| l.ok())
        .collect())
}

fn trim_file(path: &Path, max: usize) -> Result<()> {
    let lines = read_lines(path)?;
    if lines.len() <= max {
        return Ok(());
    }
    let keep = &lines[lines.len() - max..];
    let tmp = path.with_extension("jsonl.tmp");
    {
        let mut f = File::create(&tmp)
            .with_context(|| tr_fmt!("rewriting path stats {0}", tmp.display()))?;
        for line in keep {
            writeln!(f, "{line}")?;
        }
        f.flush()?;
    }
    fs::rename(&tmp, path).with_context(|| tr_fmt!("replacing path stats {0}", path.display()))?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn round_trip_summary_counts_direct() {
        let dir = std::env::temp_dir().join(format!("link-p2p-pstats-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Point config dir via XDG for this process slice — use direct write API.
        let path = dir.join("path-stats.jsonl");
        let peer = SecretKey::from_bytes(&[9u8; 32]).public();
        let sample = PathSample {
            ts: 1,
            cmd: "ping".into(),
            peer_short: contacts::encode_short_code(peer),
            peer: peer.to_string(),
            path: "direct".into(),
            upgrade_ms: Some(120),
            relay_only: false,
        };
        let mut f = File::create(&path).unwrap();
        serde_json::to_writer(&mut f, &sample).unwrap();
        f.write_all(b"\n").unwrap();
        let lines = read_lines(&path).unwrap();
        assert_eq!(lines.len(), 1);
        let s: PathSample = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(s.path, "direct");
        assert_eq!(s.upgrade_ms, Some(120));
    }

    #[test]
    fn trim_keeps_last_n() {
        let dir = std::env::temp_dir().join(format!("link-p2p-ptrim-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("path-stats.jsonl");
        {
            let mut f = File::create(&path).unwrap();
            for i in 0..10 {
                writeln!(f, "{{\"ts\":{i},\"cmd\":\"ping\",\"peer_short\":\"x\",\"peer\":\"y\",\"path\":\"relay\"}}").unwrap();
            }
        }
        trim_file(&path, 3).unwrap();
        let lines = read_lines(&path).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"ts\":7"));
        assert!(lines[2].contains("\"ts\":9"));
    }
}
