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
pub fn parse_endpoint_token(token: &str) -> Result<EndpointId> {
    let t = token.trim();
    if let Ok(id) = t.parse::<EndpointId>() {
        return Ok(id);
    }
    let compact: String = t
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .collect();
    if let Ok(bytes) = decode_crockford(&compact) {
        // 32 bytes = 256 bits → 52 Crockford chars carry 260 bits; ignore pad.
        if bytes.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[..32]);
            return EndpointId::from_bytes(&arr)
                .map_err(|e| anyhow::Error::new(e).context(tr!("invalid EndpointId in short code")));
        }
    }
    Err(anyhow::anyhow!(tr_fmt!(
        "'{0}' is not a contact name, EndpointId, or short code",
        token
    )))
}

/// Encode EndpointId as grouped Crockford Base32.
pub fn encode_short_code(id: EndpointId) -> String {
    let raw = encode_crockford(id.as_bytes());
    raw.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

// --- Crockford Base32 (no check symbol) ---

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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
        let u = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
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
}
