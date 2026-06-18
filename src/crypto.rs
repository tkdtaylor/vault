//! Encrypted-at-rest store internals — the key-provider seam, the backend seam, and the
//! production AES-256-GCM backend (ADR-005).
//!
//! The store never holds a secret value in plaintext: `put`/`rotate` encrypt to AES-256-GCM
//! ciphertext with a fresh 96-bit nonce per value, and `inject` decrypts only at the injection
//! edge. The encryption key is sourced through a [`KeyProvider`] seam — it is never serialized
//! beside the ciphertext and never logged. A second backend (e.g. a test plaintext one) can slot
//! in behind [`StoreBackend`] without changing `resolve`/`inject`/callers.
//!
//! Nonce randomness comes from the OS CSPRNG via `/dev/urandom` (the same source as `handle.rs`)
//! — no `rand` crate (project rule D4). Failed decryption (tampered/truncated ciphertext, wrong
//! key) fails closed: the AEAD tag check rejects it and the backend returns an error that `inject`
//! surfaces as `{error:{code:"decrypt_failed",…}}` — never a silent wrong value, never a panic.

use std::fs::File;
use std::io::Read;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

/// AES-256-GCM nonce width in bytes (96 bits — the standard GCM nonce size).
const NONCE_LEN: usize = 12;
/// AES-256 key width in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// An encrypted secret value as held at rest: AEAD ciphertext (value + appended 128-bit tag) plus
/// the unique 96-bit nonce it was sealed with. The cleartext value is **not** present — this is the
/// only representation of the value the store keeps (REQ-001 / REQ-006). The nonce is not secret
/// (it may travel in the clear); the tag is appended to `ciphertext` by the AEAD.
#[derive(Clone)]
pub struct EncryptedValue {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

/// Source of the 32-byte AES-256 master key (REQ-003). The key lives behind this seam — it is
/// never stored beside the ciphertext and never serialized into the store. A provider that cannot
/// produce a key fails closed (the backend refuses to construct / encrypt / decrypt; there is no
/// plaintext fallback).
pub trait KeyProvider: Send + Sync {
    /// Return the 32-byte key, or an error string if no key is configured/readable.
    fn key(&self) -> Result<[u8; KEY_LEN], String>;
}

/// Default production key provider: read the master key from the environment, fail closed if
/// unconfigured.
///
/// Sources, in precedence order:
///   1. `VAULT_MASTER_KEY_FILE` — path to a file whose contents are the key (hex or base64),
///   2. `VAULT_MASTER_KEY` — the key inline (hex or base64).
///
/// The key material is decoded to exactly 32 bytes; anything else is an error. Missing/unreadable
/// → error (fail-closed, never a default/zero key). The key is never logged.
pub struct EnvKeyProvider;

impl KeyProvider for EnvKeyProvider {
    fn key(&self) -> Result<[u8; KEY_LEN], String> {
        let raw = if let Ok(path) = std::env::var("VAULT_MASTER_KEY_FILE") {
            let mut s = String::new();
            File::open(&path)
                .and_then(|mut f| f.read_to_string(&mut s))
                .map_err(|e| format!("VAULT_MASTER_KEY_FILE unreadable: {e}"))?;
            s
        } else if let Ok(inline) = std::env::var("VAULT_MASTER_KEY") {
            inline
        } else {
            return Err(
                "no master key configured (set VAULT_MASTER_KEY or VAULT_MASTER_KEY_FILE)".into(),
            );
        };
        decode_key(raw.trim())
    }
}

/// Decode a 32-byte key from hex (64 chars) or base64. Any other length → error. Never logs the
/// input.
fn decode_key(s: &str) -> Result<[u8; KEY_LEN], String> {
    let bytes = if let Some(b) = decode_hex(s) {
        b
    } else if let Some(b) = decode_base64(s) {
        b
    } else {
        return Err("master key is not valid hex or base64".into());
    };
    if bytes.len() != KEY_LEN {
        return Err(format!(
            "master key must be {KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Decode an all-hex string to bytes; `None` if it contains any non-hex char or has odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Minimal standard-base64 decoder (no padding-relaxation, no external crate). `None` on any
/// invalid char. Accepts optional `=` padding.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| -> Option<u32> {
        if c == b'=' {
            return Some(0);
        }
        TABLE.iter().position(|&t| t == c).map(|p| p as u32)
    };
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut chunk = bytes.chunks(4);
    for c in &mut chunk {
        let mut acc = 0u32;
        for (i, &b) in c.iter().enumerate() {
            acc |= val(b)? << (18 - 6 * i);
        }
        let n = c.len(); // 2,3,or 4 valid chars
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
        if n < 2 {
            return None;
        }
    }
    Some(out)
}

/// The store-encryption seam (REQ-005). `resolve`/`inject`/callers are unchanged when the backend
/// swaps; no AEAD type leaks into the contract responses — only the `EncryptedValue` opaque blob
/// crosses this seam, and the plaintext `String` it returns from [`decrypt`](StoreBackend::decrypt)
/// is handed straight to the injection edge.
pub trait StoreBackend: Send + Sync {
    /// Seal a plaintext value into an [`EncryptedValue`] with a fresh unique nonce (REQ-004).
    fn encrypt(&self, plaintext: &str) -> Result<EncryptedValue, String>;
    /// Open a previously sealed value. Fails closed on a bad tag / wrong key / truncation.
    fn decrypt(&self, value: &EncryptedValue) -> Result<String, String>;
}

/// Production backend: AES-256-GCM with the key from a [`KeyProvider`]. The key is held in this
/// backend's memory only (never beside the ciphertext). Each `encrypt` draws a fresh 96-bit nonce
/// from `/dev/urandom`, so identical plaintexts produce different ciphertexts and no nonce is
/// reused across puts/rotations (REQ-004).
pub struct AesGcmBackend {
    cipher: Aes256Gcm,
}

impl AesGcmBackend {
    /// Construct from a key provider. Fails closed if the provider cannot produce a 32-byte key —
    /// there is no plaintext fallback (REQ-003).
    pub fn new(provider: &dyn KeyProvider) -> Result<Self, String> {
        let key_bytes = provider.key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(AesGcmBackend { cipher })
    }
}

impl StoreBackend for AesGcmBackend {
    fn encrypt(&self, plaintext: &str) -> Result<EncryptedValue, String> {
        let nonce = fresh_nonce()?;
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| "encryption failed".to_string())?;
        Ok(EncryptedValue {
            ciphertext: ct,
            nonce,
        })
    }

    fn decrypt(&self, value: &EncryptedValue) -> Result<String, String> {
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&value.nonce), value.ciphertext.as_slice())
            // Fail closed: a bad tag (tamper), wrong key, or truncation lands here. Never a value.
            .map_err(|_| "decrypt_failed".to_string())?;
        String::from_utf8(pt).map_err(|_| "decrypt_failed".to_string())
    }
}

/// A key provider that yields a fixed in-memory 32-byte key. Used to build a self-contained
/// AES-256-GCM backend with an **ephemeral** key generated for the lifetime of one process (the
/// `demo` subcommand and parity tests) — the key never leaves memory and is never persisted.
pub struct InMemoryKeyProvider(pub [u8; KEY_LEN]);
impl KeyProvider for InMemoryKeyProvider {
    fn key(&self) -> Result<[u8; KEY_LEN], String> {
        Ok(self.0)
    }
}

/// Draw a fresh random 32-byte key from `/dev/urandom` (no `rand` crate). Used to seed an ephemeral
/// in-memory backend for the `demo` subcommand — a real AES-256-GCM key, just not operator-supplied.
pub fn random_key() -> Result<[u8; KEY_LEN], String> {
    let mut buf = [0u8; KEY_LEN];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("key rng failure: {e}"))?;
    Ok(buf)
}

/// Draw a fresh 96-bit nonce from the OS CSPRNG (`/dev/urandom`) — same source as `handle.rs`, no
/// `rand` crate. A read failure fails closed (no nonce ⇒ no encryption).
fn fresh_nonce() -> Result<[u8; NONCE_LEN], String> {
    let mut buf = [0u8; NONCE_LEN];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("nonce rng failure: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-key provider for tests — injects a deterministic 32-byte key via the seam.
    pub struct FixedKeyProvider(pub [u8; KEY_LEN]);
    impl KeyProvider for FixedKeyProvider {
        fn key(&self) -> Result<[u8; KEY_LEN], String> {
            Ok(self.0)
        }
    }

    /// A provider that never yields a key — models a missing/unconfigured key source.
    struct MissingKeyProvider;
    impl KeyProvider for MissingKeyProvider {
        fn key(&self) -> Result<[u8; KEY_LEN], String> {
            Err("no key".into())
        }
    }

    fn backend_with(key: [u8; KEY_LEN]) -> AesGcmBackend {
        AesGcmBackend::new(&FixedKeyProvider(key)).expect("backend constructs with a fixed key")
    }

    #[test]
    fn round_trips_exact_plaintext() {
        let b = backend_with([7u8; KEY_LEN]);
        for pt in ["", "SK-SECRET", &"x".repeat(100)] {
            let ev = b.encrypt(pt).unwrap();
            assert_eq!(b.decrypt(&ev).unwrap(), pt, "round-trip must be exact");
        }
    }

    #[test]
    fn missing_key_fails_closed_at_construction() {
        let r = AesGcmBackend::new(&MissingKeyProvider);
        assert!(r.is_err(), "missing key must fail closed, no backend built");
    }

    #[test]
    fn identical_plaintext_yields_different_ciphertext_and_nonce() {
        let b = backend_with([3u8; KEY_LEN]);
        let a = b.encrypt("SK-SAME").unwrap();
        let c = b.encrypt("SK-SAME").unwrap();
        assert_ne!(a.nonce, c.nonce, "fresh nonce per encrypt (no reuse)");
        assert_ne!(
            a.ciphertext, c.ciphertext,
            "identical plaintext ⇒ different ciphertext"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let b = backend_with([9u8; KEY_LEN]);
        let mut ev = b.encrypt("SK-SECRET").unwrap();
        ev.ciphertext[0] ^= 0xff; // flip a byte → bad tag
        let r = b.decrypt(&ev);
        assert_eq!(r.unwrap_err(), "decrypt_failed", "bad tag ⇒ fail closed");
    }

    #[test]
    fn truncated_ciphertext_fails_closed() {
        let b = backend_with([9u8; KEY_LEN]);
        let mut ev = b.encrypt("SK-SECRET").unwrap();
        ev.ciphertext.truncate(2); // shorter than the tag → cannot authenticate
        assert_eq!(b.decrypt(&ev).unwrap_err(), "decrypt_failed");
    }

    #[test]
    fn different_key_cannot_decrypt() {
        let sealer = backend_with([1u8; KEY_LEN]);
        let ev = sealer.encrypt("SK-SECRET").unwrap();
        let other = backend_with([2u8; KEY_LEN]);
        assert_eq!(
            other.decrypt(&ev).unwrap_err(),
            "decrypt_failed",
            "key is external — a different key must not decrypt"
        );
    }

    #[test]
    fn hex_and_base64_key_decode_to_32_bytes() {
        // 64 hex chars = 32 bytes.
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let k = decode_key(hex).unwrap();
        assert_eq!(k.len(), KEY_LEN);
        assert_eq!(&k[..2], &[0x00, 0x11]);
        // base64 of 32 zero bytes.
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let kz = decode_key(b64).unwrap();
        assert_eq!(kz, [0u8; KEY_LEN]);
        // wrong length → error.
        assert!(decode_key("00112233").is_err(), "short key rejected");
    }
}
