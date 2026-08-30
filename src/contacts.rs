//! Local contacts book + human short codes for EndpointIds.
//!
//! No directory server: names live in `~/.config/link-p2p/contacts.toml`.
//! Short codes are Crockford Base32 of the 32-byte id (offline round-trip).

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::config;
use crate::i18n::{tr, tr_fmt};

/// One saved peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Contact {
    /// Full EndpointId hex (iroh display form).
    pub id: String,
    /// Optional relay hints for dial.
    pub relays: Vec<String>,
    /// Optional direct IP hints.
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactBook {
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
}

pub fn contacts_path() -> PathBuf {
    config::config_dir().join("contacts.toml")
}

pub fn load(path: &Path) -> Result<ContactBook> {
    if !path.exists() {
        return Ok(ContactBook::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| tr_fmt!("reading contacts {0}", path.display()))?;
    toml::from_str(&text).with_context(|| tr_fmt!("parsing contacts {0}", path.display()))
}

pub fn save(path: &Path, book: &ContactBook) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating config directory {0}", parent.display()))?;
    }
    let text = toml::to_string_pretty(book).context(tr!("serializing contacts"))?;
    fs::write(path, text).with_context(|| tr_fmt!("writing contacts {0}", path.display()))
}

/// Resolved peer for dialing.
#[derive(Debug, Clone)]
pub struct ResolvedPeer {
    pub id: EndpointId,
    pub relays: Vec<String>,
    pub addrs: Vec<SocketAddr>,
    pub name: Option<String>,
}

/// Resolve `name` / EndpointId hex / short code against the contact book.
pub fn resolve(book: &ContactBook, to: &str) -> Result<ResolvedPeer> {
    let key = to.trim();
    if let Some((name, c)) = book.contacts.get_key_value(key) {
        return contact_to_resolved(Some(name.clone()), c);
    }
    // Case-insensitive name match.
    if let Some((name, c)) = book
        .contacts
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(key))
    {
        return contact_to_resolved(Some(name.clone()), c);
    }
    let id = parse_endpoint_token(key)?;
    Ok(ResolvedPeer {
        id,
        relays: Vec::new(),
        addrs: Vec::new(),
        name: None,
    })
}

fn contact_to_resolved(name: Option<String>, c: &Contact) -> Result<ResolvedPeer> {
    let id: EndpointId = c
        .id
        .parse()
        .with_context(|| tr_fmt!("contact has invalid EndpointId '{0}'", c.id))?;
    let mut addrs = Vec::new();
    for a in &c.addrs {
        addrs.push(
            a.parse()
                .with_context(|| tr_fmt!("contact has invalid address '{0}'", a))?,
        );
    }
    Ok(ResolvedPeer {
        id,
        relays: c.relays.clone(),
        addrs,
        name,
    })
}

/// Parse a hex EndpointId or Crockford short code.
///
/// Short codes include a trailing Crockford check character (typo detection).
/// Legacy 52-character codes without a check digit are still accepted.
pub fn parse_endpoint_token(token: &str) -> Result<EndpointId> {
    let t = token.trim();
    if let Ok(id) = t.parse::<EndpointId>() {
        return Ok(id);
    }
    let compact: String = t
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect();

    // New format: 52 payload chars + 1 check symbol.
    if compact.chars().count() >= 53 {
        let (body, check) = compact.split_at(compact.len() - 1);
        let check = check
            .chars()
            .next()
            .ok_or_else(|| anyhow::anyhow!(tr!("invalid character in short code")))?;
        let bytes = decode_crockford(body)?;
        if bytes.len() < 32 {
            return Err(anyhow::anyhow!(tr_fmt!(
                "'{0}' is not a contact name, EndpointId, or short code",
                token
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        if check_symbol(&arr) != check {
            return Err(anyhow::anyhow!(tr!(
                "short code check digit mismatch (typo?)"
            )));
        }
        return EndpointId::from_bytes(&arr)
            .map_err(|e| anyhow::Error::new(e).context(tr!("invalid EndpointId in short code")));
    }

    // Legacy: payload only (no check digit), exactly 52 Crockford chars.
    if compact.len() == 52 {
        if let Ok(bytes) = decode_crockford(&compact) {
            if bytes.len() >= 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[..32]);
                return EndpointId::from_bytes(&arr).map_err(|e| {
                    anyhow::Error::new(e).context(tr!("invalid EndpointId in short code"))
                });
            }
        }
    }
    Err(anyhow::anyhow!(tr_fmt!(
        "'{0}' is not a contact name, EndpointId, or short code",
        token
    )))
}

/// Encode EndpointId as grouped Crockford Base32 plus a trailing check char.
pub fn encode_short_code(id: EndpointId) -> String {
    let raw = encode_crockford(id.as_bytes());
    let with_check = format!("{}{}", raw, check_symbol(id.as_bytes()));
    with_check
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

// --- Crockford Base32 ---
//
// Payload uses the standard alphabet; a single trailing check symbol is the
// CRC-ish residue of the 32 raw bytes mod 32 (typo detection only — QUIC
// still authenticates the peer key).

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn check_symbol(data: &[u8]) -> char {
    let mut x = 0u32;
    for &b in data {
        x = x.wrapping_mul(31).wrapping_add(u32::from(b));
    }
    CROCKFORD[(x % 32) as usize] as char
}

fn encode_crockford(data: &[u8]) -> String {
    // Stream bits without accumulating into a widening integer (32 bytes
    // would overflow u64).
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((buf >> nbits) & 0x1f) as usize;
            out.push(CROCKFORD[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((buf << (5 - nbits)) & 0x1f) as usize;
        out.push(CROCKFORD[idx] as char);
    }
    out
}

fn decode_crockford(s: &str) -> Result<Vec<u8>> {
    let mut buf: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        let u = c.to_ascii_uppercase();
        let v = CROCKFORD
            .iter()
            .position(|&b| b == u as u8)
            .ok_or_else(|| anyhow::anyhow!(tr!("invalid character in short code")))?
            as u32;
        buf = (buf << 5) | v;
        nbits += 5;
        while nbits >= 8 {
            nbits -= 8;
            out.push(((buf >> nbits) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn short_code_round_trip() {
        let sk = SecretKey::from_bytes(&[7u8; 32]);
        let id = sk.public();
        let code = encode_short_code(id);
        assert!(code.contains('-'));
        let back = parse_endpoint_token(&code).unwrap();
        assert_eq!(back, id);
        let compact: String = code.chars().filter(|c| *c != '-').collect();
        assert_eq!(parse_endpoint_token(&compact).unwrap(), id);
        assert_eq!(parse_endpoint_token(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn short_code_check_digit_catches_typo() {
        let sk = SecretKey::from_bytes(&[9u8; 32]);
        let id = sk.public();
        let code = encode_short_code(id);
        let mut chars: Vec<char> = code.chars().collect();
        // Flip a payload character (not a dash, not the final check group).
        let idx = chars
            .iter()
            .position(|&c| c != '-' && c.is_ascii_alphanumeric())
            .unwrap();
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        let bad: String = chars.into_iter().collect();
        let err = parse_endpoint_token(&bad).unwrap_err().to_string();
        assert!(
            err.contains("check digit") || err.contains("校验"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn short_code_legacy_without_check_still_parses() {
        let sk = SecretKey::from_bytes(&[3u8; 32]);
        let id = sk.public();
        let legacy = encode_crockford(id.as_bytes());
        assert_eq!(legacy.len(), 52);
        assert_eq!(parse_endpoint_token(&legacy).unwrap(), id);
    }
}
