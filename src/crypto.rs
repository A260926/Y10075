//! Local-at-rest encryption of signing secret material and HMAC signatures.
//!
//! Secret bytes never leave the process unencrypted: SQLite stores only the
//! AES-256-GCM ciphertext (nonce prepended). The master key lives in a local
//! file with 0600 permissions and is generated on first run. UI and logs only
//! ever reference keys by their `key_id`.

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MASTER_KEY_LEN: usize = 32;

/// Load the local master key, generating and persisting it (mode 0600) on first
/// use. Returns the raw 32-byte key.
pub fn load_or_create_master_key(path: &Path) -> anyhow::Result<[u8; MASTER_KEY_LEN]> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != MASTER_KEY_LEN {
            anyhow::bail!(
                "master key at {} has invalid length {}",
                path.display(),
                bytes.len()
            );
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    fs::write(path, key)?;
    set_file_mode_600(path)?;
    Ok(key)
}

#[cfg(unix)]
fn set_file_mode_600(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_600(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[derive(Clone)]
pub struct Cipher {
    key: [u8; MASTER_KEY_LEN],
}

impl Cipher {
    pub fn new(master_key: [u8; MASTER_KEY_LEN]) -> Self {
        Self { key: master_key }
    }

    /// Encrypt plaintext secret material. Output layout: 12-byte nonce ||
    /// ciphertext+tag, hex encoded for storage.
    pub fn encrypt_to_hex(&self, plaintext: &[u8]) -> anyhow::Result<String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(hex::encode(out))
    }

    pub fn decrypt_hex(&self, encoded: &str) -> anyhow::Result<Vec<u8>> {
        let raw = hex::decode(encoded)?;
        if raw.len() < 12 + 16 {
            anyhow::bail!("ciphertext too short");
        }
        let (nonce_bytes, ct) = raw.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))
    }
}

/// HMAC-SHA256 over the exact frozen payload bytes, keyed by the chosen signing
/// key's secret material.
pub fn sign_payload(secret: &[u8], payload: &[u8]) -> anyhow::Result<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("invalid hmac key length: {e}"))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time signature verification (used by the fake receiver).
pub fn verify_payload(secret: &[u8], payload: &[u8], signature_hex: &str) -> bool {
    let provided = match hex::decode(signature_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(payload);
    mac.verify_slice(&provided).is_ok()
}
