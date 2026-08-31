//! Persistent EndpointId identity files (plaintext hex or passphrase-encrypted).
//!
//! Owns path resolution (XDG + legacy migration), Argon2id + XChaCha20-Poly1305
//! encryption, and 0600 file creation. Extracted from `main` so command
//! dispatch does not share a file with key material logic.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use iroh::SecretKey;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::exit;
use crate::i18n::{tr, tr_fmt};

/// Resolve the identity file path: an explicit `--identity` wins; otherwise
/// the XDG config location. A legacy `./identity.key` in the working
/// directory (pre-XDG versions kept it there) is migrated to the XDG
/// location once, so existing EndpointIds stay stable across the move.
pub(crate) fn resolve_identity_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let xdg = default_identity_path();
    if xdg.exists() {
        return Ok(xdg);
    }
    let legacy = PathBuf::from("identity.key");
    if !legacy.exists() {
        return Ok(xdg);
    }
    match migrate_identity(&legacy, &xdg) {
        Ok(()) => {
            info!(
                "{}",
                tr_fmt!(
                    "migrated legacy identity from {0} to {1}",
                    legacy.display(),
                    xdg.display()
                )
            );
            Ok(xdg)
        }
        Err(e) => {
            // Keep the EndpointId stable: fall back to the legacy file
            // rather than silently generating a brand-new identity.
            warn!(error = %e, "{}", tr!("identity migration failed; using the legacy file"));
            Ok(legacy)
        }
    }
}

/// The XDG config location for the identity key:
/// `$XDG_CONFIG_HOME/link-p2p/identity.key`, or `~/.config/link-p2p/...`
/// when `XDG_CONFIG_HOME` is unset. Falls back to `./identity.key` if
/// neither `XDG_CONFIG_HOME` nor `HOME` is set.
fn default_identity_path() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(base).join("link-p2p").join("identity.key");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home)
            .join(".config")
            .join("link-p2p")
            .join("identity.key");
    }
    PathBuf::from("identity.key")
}

/// Move the legacy identity file to the XDG location (directory created as
/// needed), keeping the key material and thus the EndpointId intact.
///
/// Written through [`open_key_file_for_write`] (mode 0600 at creation), never
/// `fs::copy`: a copy would inherit umask-derived permissions and be
/// world-readable until the chmod below lands. The key material must not
/// briefly exist with broad perms on disk.
pub(crate) fn migrate_identity(from: &Path, to: &Path) -> Result<()> {
    let ctx = || {
        tr_fmt!(
            "migrating legacy identity from {0} to {1}",
            from.display(),
            to.display()
        )
    };
    let bytes = std::fs::read(from).with_context(ctx)?;
    let mut file = open_key_file_for_write(to)?;
    file.write_all(&bytes).with_context(ctx)?;
    drop(file);
    harden_key_permissions(to)?;
    // The key material is now safely at its XDG home; drop the legacy copy
    // so the private key doesn't linger in the working directory.
    if let Err(e) = std::fs::remove_file(from) {
        warn!(error = %e, "{}", tr_fmt!(
            "could not remove the legacy identity file {0} (you can delete it manually)",
            from.display()
        ));
    }
    Ok(())
}

/// Minimum Unicode scalar values (`chars().count()`) for a passphrase.
pub(crate) const PASSPHRASE_MIN_LEN: usize = 8;
/// Maximum UTF-8 byte length — DoS bound for Argon2 input size (not a
/// "character" limit). CJK passphrases hit the min via chars, the max via bytes.
pub(crate) const PASSPHRASE_MAX_LEN: usize = 1024;

/// Reject empty-looking, too-short, or absurdly long passphrases before KDF.
///
/// - **Minimum**: Unicode scalar values (`chars()`), so CJK / emoji are not
///   forced to pad to 8 UTF-8 bytes.
/// - **Maximum**: raw UTF-8 **bytes**, to bound Argon2 memory/time.
/// - Does **not** trim whitespace: a trailing newline from a file/`echo` is
///   part of the passphrase (document this for callers that read from files).
pub(crate) fn validate_passphrase(passphrase: &str) -> Result<()> {
    let char_count = passphrase.chars().count();
    let byte_len = passphrase.len();
    if char_count < PASSPHRASE_MIN_LEN {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr_fmt!(
                "passphrase must be at least {0} characters (Unicode scalar values; you have {1})",
                PASSPHRASE_MIN_LEN,
                char_count
            )),
        ));
    }
    if byte_len > PASSPHRASE_MAX_LEN {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr_fmt!(
                "passphrase is too long (max {0} UTF-8 bytes, you have {1})",
                PASSPHRASE_MAX_LEN,
                byte_len
            )),
        ));
    }
    Ok(())
}

/// File magic + version for passphrase-encrypted identity keys.
/// Layout: magic | salt(16) | nonce(24) | ciphertext(64 hex chars + 16 tag).
/// The plaintext format is exactly 64 hex chars (0-9a-f) and `l` is not a hex
/// digit, so a plaintext file can never collide with this prefix.
const KEY_FILE_MAGIC: &[u8] = b"linkp2p-k1";
const KEY_FILE_SALT_LEN: usize = 16;
const KEY_FILE_NONCE_LEN: usize = 24;
const KEY_FILE_TAG_LEN: usize = 16;
const KEY_FILE_OVERHEAD: usize =
    KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN + KEY_FILE_NONCE_LEN + KEY_FILE_TAG_LEN;

/// Whether `data` looks like a passphrase-encrypted key file (vs legacy
/// plaintext hex).
fn is_encrypted_key(data: &[u8]) -> bool {
    data.starts_with(KEY_FILE_MAGIC)
}

/// Argon2id key derivation from the passphrase + per-file salt.
///
/// Parameters follow the OWASP "Interactive logins / authentication" row for
/// Argon2id (m=19 MiB, t=2, p=1):  
/// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
///
/// 19 MiB is intentional friction against offline guessing; very small containers
/// may OOM — prefer a machine with spare RAM over weakening params silently.
/// `p=1` matches the OWASP interactive profile (not a throughput-optimized hash).
///
/// The KDF salt input is the PHC "B64" encoding of the on-disk salt bytes
/// (same as argon2 0.5 `SaltString::encode_b64`), so existing encrypted
/// identity files keep decrypting after the 0.6 upgrade.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::password_hash::phc::Salt;
    use argon2::{Algorithm, Argon2, Params, Version};

    let salt_b64 = Salt::new(salt)
        .map_err(|e| anyhow::anyhow!(tr!("encoding the passphrase salt")).context(e))?
        .to_salt_string();
    let params = Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| {
        anyhow::anyhow!(tr!(
            "OWASP interactive-login Argon2 params rejected by argon2 crate (please file a bug)"
        ))
        .context(e)
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut dk = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_b64.as_bytes(), &mut dk)
        .map_err(|e| anyhow::anyhow!(tr!("deriving key from passphrase")).context(e))?;
    Ok(dk)
}

/// Encrypt a 64-char hex key into the on-disk format (magic + salt + nonce +
/// ciphertext). XChaCha20-Poly1305 with the file magic as AAD, so a header
/// can't be swapped between files. The derived key is zeroized on return.
fn encrypt_key_hex(hex: &str, passphrase: &str) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

    let mut salt = [0u8; KEY_FILE_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| {
        anyhow::anyhow!(tr!(
            "gathering entropy for identity salt (Unix: check /dev/urandom; containers/embedded may lack a CSPRNG)"
        ))
        .context(e)
    })?;
    let mut nonce_bytes = [0u8; KEY_FILE_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|e| {
        anyhow::anyhow!(tr!(
            "gathering entropy for identity nonce (Unix: check /dev/urandom; containers/embedded may lack a CSPRNG)"
        ))
        .context(e)
    })?;

    let mut dk = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(dk));
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: hex.as_bytes(),
                aad: KEY_FILE_MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!(tr!("encrypting identity file failed")))?;
    dk.zeroize();

    let mut out = Vec::with_capacity(KEY_FILE_OVERHEAD + hex.len());
    out.extend_from_slice(KEY_FILE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a key file written by [`encrypt_key_hex`], returning the 64-char
/// hex. A wrong passphrase or any tampering fails the AEAD tag check and
/// errors here.
fn decrypt_key_hex(data: &[u8], passphrase: &str) -> Result<String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

    if !is_encrypted_key(data) {
        bail!(tr!("identity file is not passphrase-encrypted"));
    }
    let salt = &data[KEY_FILE_MAGIC.len()..KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN];
    let nonce_off = KEY_FILE_MAGIC.len() + KEY_FILE_SALT_LEN;
    let nonce_bytes: [u8; KEY_FILE_NONCE_LEN] = data[nonce_off..nonce_off + KEY_FILE_NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!(tr!("identity file is truncated")))?;
    let ciphertext = &data[nonce_off + KEY_FILE_NONCE_LEN..];

    let mut dk = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(dk));
    let nonce = XNonce::from(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: KEY_FILE_MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!(tr!("incorrect passphrase or corrupted identity file")))?;
    dk.zeroize();
    // Plaintext is the 64-char hex; ownership moves out, caller zeroizes.
    String::from_utf8(plaintext).context(tr!("decrypted identity file is not valid UTF-8"))
}

/// Parse a 64-char hex identity blob into a [`SecretKey`], hardening the
/// file permissions along the way (covers pre-existing plaintext files).
fn secret_key_from_hex(hex: &str, path: &Path) -> Result<SecretKey> {
    let hex = hex.trim();
    if hex.len() != 64 {
        anyhow::bail!(tr_fmt!(
            "identity file exists but has unexpected length {0} (expected 64 hex chars)",
            hex.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .context(tr!("identity file exists but contains non-hex characters"))?;
    }
    harden_key_permissions(path)?;
    let key = SecretKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

/// Load a persisted SecretKey from `path`, or generate + save a new one.
///
/// With a passphrase the file is stored encrypted (Argon2id + XChaCha20-
/// Poly1305); without one, plaintext hex (legacy behaviour, 0600 on Unix).
/// A legacy plaintext file loaded *with* a passphrase is transparently
/// re-encrypted on disk (best-effort — if that write fails the key still
/// loads, it just stays plaintext).
///
/// Storage format: 64 hex chars (32-byte ed25519 seed). iroh 1.0
/// SecretKey does not implement Display, so we hex-encode `to_bytes()`
/// ourselves instead of relying on the old Display-based round-trip.
pub(crate) fn load_or_create_secret_key(path: &Path, passphrase: Option<&str>) -> Result<SecretKey> {
    if let Some(p) = passphrase {
        validate_passphrase(p)?;
    }
    if let Ok(data) = std::fs::read(path) {
        let result = if is_encrypted_key(&data) {
            // Passphrase-encrypted file: the passphrase is mandatory.
            let pass = passphrase.context(tr!(
                "identity file is passphrase-encrypted but no passphrase was provided (use --identity-passphrase or LINK_P2P_PASSPHRASE)"
            ))?;
            let mut hex = decrypt_key_hex(&data, pass).context(tr!("decrypting identity file"))?;
            let key = secret_key_from_hex(&hex, path);
            hex.zeroize();
            key
        } else {
            // Legacy plaintext hex (the only other format that exists).
            let mut hex = String::from_utf8(data)
                .context(tr!("identity file is neither plaintext hex nor encrypted"))?;
            // A passphrase on a plaintext file means "encrypt it now": load
            // the key, then rewrite the file encrypted (best-effort).
            if let Some(pass) = passphrase {
                match write_key_file_encrypted(path, hex.trim(), pass) {
                    Ok(()) => info!(
                        "{}",
                        tr!("re-encrypting the legacy plaintext identity file with the provided passphrase")
                    ),
                    Err(e) => warn!(
                        error = %e,
                        "{}",
                        tr!("could not encrypt the legacy identity file; it stays plaintext on disk")
                    ),
                }
            }
            let key = secret_key_from_hex(&hex, path);
            hex.zeroize();
            key
        };
        return result;
    }
    // No file yet: generate, then persist in the requested format.
    let key = SecretKey::generate();
    let mut hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let written = match passphrase {
        Some(pass) => write_key_file_encrypted(path, &hex, pass),
        None => write_key_file(path, &hex),
    };
    hex.zeroize();
    written?;
    Ok(key)
}

/// Open (create/truncate) the identity file with owner-only permissions on
/// Unix — no window where the key material is world-readable.
fn open_key_file_for_write(path: &Path) -> Result<std::fs::File> {
    // The XDG default lives under a per-app config dir that may not exist
    // yet; create it so the very first run can persist the new key.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| tr_fmt!("creating identity directory {0}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))
}

/// Write the key material to `path` as plaintext hex (legacy format). On
/// Unix the file is created with mode 0600 directly, then hardened again
/// to cover the case where the file already existed.
fn write_key_file(path: &Path, hex: &str) -> Result<()> {
    let mut file = open_key_file_for_write(path)?;
    file.write_all(hex.as_bytes())
        .with_context(|| tr_fmt!("writing new identity to {0}", path.display()))?;
    harden_key_permissions(path)
}

/// Write the key material to `path` passphrase-encrypted. Same 0600
/// discipline as [`write_key_file`]; the on-disk bytes are magic + salt +
/// nonce + ciphertext, so a disk/backup leak without the passphrase yields
/// nothing.
fn write_key_file_encrypted(path: &Path, hex: &str, passphrase: &str) -> Result<()> {
    let encrypted = encrypt_key_hex(hex, passphrase)?;
    let mut file = open_key_file_for_write(path)?;
    let written = file.write_all(&encrypted);
    drop(file);
    if let Err(e) = written {
        return Err(e).with_context(|| {
            tr_fmt!(
                "writing passphrase-encrypted identity to {0}",
                path.display()
            )
        });
    }
    harden_key_permissions(path)
}

/// Ensure the key file is owner-only (0600) on Unix. No-op elsewhere.
#[cfg(unix)]
fn harden_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| tr_fmt!("setting permissions on {0}", path.display()))
}

#[cfg(not(unix))]
fn harden_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;


/// Passphrase encryption: round-trip, wrong passphrase, tampering, and
/// non-confusability with plaintext hex.
#[test]
fn key_encryption_round_trip() {
    let hex = "abcdef0123456789".repeat(4); // 64 hex chars
    let encrypted = encrypt_key_hex(&hex, "hunter2").unwrap();
    assert!(is_encrypted_key(&encrypted));
    assert_eq!(encrypted.len(), KEY_FILE_OVERHEAD + 64);
    assert_eq!(decrypt_key_hex(&encrypted, "hunter2").unwrap(), hex);
}

#[test]
fn key_encryption_rejects_wrong_passphrase() {
    let hex = "0123456789abcdef".repeat(4);
    let encrypted = encrypt_key_hex(&hex, "right").unwrap();
    assert!(decrypt_key_hex(&encrypted, "wrong").is_err());
}

#[test]
fn key_encryption_rejects_tampered_ciphertext() {
    let hex = "0123456789abcdef".repeat(4);
    let mut encrypted = encrypt_key_hex(&hex, "hunter2").unwrap();
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01; // flip one ciphertext byte -> AEAD tag fails
    assert!(decrypt_key_hex(&encrypted, "hunter2").is_err());
    // Tampering with the header (salt/nonce) also fails, and swapping a
    // header between files is blocked by the AAD (magic is the AAD).
    encrypted[KEY_FILE_MAGIC.len()] ^= 0x01;
    assert!(decrypt_key_hex(&encrypted, "hunter2").is_err());
}

#[test]
fn plaintext_hex_is_not_confusable_with_encrypted() {
    // 'l' (magic's first byte) is not a hex digit, so a legacy 64-char
    // plaintext file can never look encrypted.
    let plain = "0123456789abcdef".repeat(4);
    assert!(!is_encrypted_key(plain.as_bytes()));
    assert!(!is_encrypted_key(b""));
    assert!(!is_encrypted_key(b"linkp2p-k0")); // wrong version byte
}

#[test]
fn identity_file_passphrase_round_trip_on_disk() {
    let dir = std::env::temp_dir().join(format!("link-p2p-keytest-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("identity.key");
    let _ = std::fs::remove_file(&path);

    // Create with a passphrase: file lands encrypted, key round-trips.
    let key1 = load_or_create_secret_key(&path, Some("s3cret!!")).unwrap();
    assert!(is_encrypted_key(&std::fs::read(&path).unwrap()));
    let key2 = load_or_create_secret_key(&path, Some("s3cret!!")).unwrap();
    assert_eq!(key1.to_bytes(), key2.to_bytes());
    // Wrong passphrase and missing passphrase both fail loudly.
    assert!(load_or_create_secret_key(&path, Some("wrong!!!")).is_err());
    assert!(load_or_create_secret_key(&path, None).is_err());
    // Too-short passphrase rejected before KDF.
    assert!(validate_passphrase("short").is_err());
    // Min length is Unicode chars, not UTF-8 bytes ("你好世界测试口令" = 8 chars).
    assert!(validate_passphrase("你好世界测试口令").is_ok());
    assert!(validate_passphrase("你好世界").is_err()); // 4 chars
    // Max is bytes.
    assert!(validate_passphrase(&"a".repeat(PASSPHRASE_MAX_LEN + 1)).is_err());

    // Legacy upgrade: overwrite with plaintext hex, load with a
    // passphrase -> same key, file becomes encrypted.
    let hex: String = key1.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, &hex).unwrap();
    let key3 = load_or_create_secret_key(&path, Some("newpass1")).unwrap();
    assert_eq!(key1.to_bytes(), key3.to_bytes());
    assert!(is_encrypted_key(&std::fs::read(&path).unwrap()));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(unix)]
#[test]
fn migrate_identity_writes_0600_and_removes_legacy() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("link-p2p-migrate-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let legacy = dir.join("identity.key");
    let target = dir.join("nested").join("identity.key");
    let key = "0123456789abcdef".repeat(4); // 64 hex chars
    // Legacy file deliberately broad (0644): the migrated copy must never
    // inherit that — it goes through open_key_file_for_write (0600 at
    // creation), not fs::copy.
    std::fs::write(&legacy, &key).unwrap();
    std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o644)).unwrap();

    migrate_identity(&legacy, &target).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), key.as_bytes());
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "migrated identity must be owner-only, got {mode:o}");
    assert!(!legacy.exists(), "legacy identity should be removed");

    let _ = std::fs::remove_dir_all(&dir);
}
}
