//! Persistent encrypted-on-disk store — the `StoreFile` serialization layer (ADR-008).
//!
//! This is **orthogonal to the `StoreBackend` value-crypto seam** (ADR-008 §1): it does not
//! encrypt or decrypt anything. It serializes the *already-encrypted* `EncryptedValue`s plus their
//! non-secret metadata to / from a single `0600` JSON file via a dedicated [`StoredRecord`] DTO, so
//! the internal `Secret` / `EncryptedValue` stay wire-free (ADR-008 §2, REQ-009).
//!
//! Load-bearing properties (ADR-008):
//!   - **Ciphertext only at rest** — the file holds base64 ciphertext + nonce + cleartext metadata;
//!     the master key is NEVER written (REQ-002, §6) and the plaintext value is NEVER written.
//!   - **Handles never persist** — only `store` records cross this layer; the handle table is
//!     ephemeral (REQ-003, §5). That guarantee lives in `vault.rs` (it only ever passes `store`
//!     records here), reinforced by this module never having a handle type.
//!   - **No decrypt at load** — load base64-decodes into `EncryptedValue`s; decryption stays at the
//!     `inject` edge (REQ-001, §7). A wrong key surfaces later as `decrypt_failed`, not at load.
//!   - **Atomic + `0600` write** — temp file in the same dir, `chmod 0600` BEFORE any bytes, fsync,
//!     atomic rename (REQ-005/REQ-006, §4).
//!   - **Refuse to start on a corrupt file** — bad JSON / unknown version / bad base64 / wrong-length
//!     nonce → a structured [`LoadError`]; the caller refuses to start, never panics (REQ-004, §8).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{decode_base64, encode_base64, EncryptedValue};
use crate::vault::{Binding, Mode};

/// The on-disk file format version. An unknown version fails closed at load (refuse to start) —
/// a forward-compat hook so a future shape change can't silently misparse (ADR-008 §2).
const FORMAT_VERSION: u64 = 1;

/// AES-256-GCM nonce width (must match `crypto::NONCE_LEN`). A record whose decoded nonce is not
/// exactly this many bytes is structurally corrupt → refuse to start (ADR-008 §8).
const NONCE_LEN: usize = 12;

/// The on-disk record DTO (ADR-008 §2). Carries the serde derives so the internal `Secret` /
/// `EncryptedValue` need none — the disk format is an intentional, reviewable surface. A leak of the
/// plaintext value would have to be *typed in here*; there is no field for it.
#[derive(Serialize, Deserialize)]
pub struct StoredRecord {
    /// AEAD ciphertext (value + 128-bit tag), base64-encoded.
    pub ciphertext_b64: String,
    /// The 96-bit nonce the value was sealed with, base64-encoded (non-secret).
    pub nonce_b64: String,
    /// The injection floor (`env` / `proxy`) — non-secret metadata (ADR-008 §3).
    pub injection_floor: Mode,
    /// The proxy/env binding — non-secret metadata.
    pub binding: Binding,
    /// The rotate generation counter (ADR-004) — must persist so on-disk truth stays correct.
    pub generation: u64,
}

/// The whole store file: a version tag plus a `ref -> record` map.
#[derive(Serialize, Deserialize)]
struct StoreFileDoc {
    version: u64,
    records: std::collections::BTreeMap<String, StoredRecord>,
}

/// A record reconstructed from disk, ready for `vault.rs` to map back into its internal `Secret`.
/// Ciphertext only — no plaintext, no key (REQ-001/§7).
pub struct LoadedRecord {
    pub secret_ref: String,
    pub enc: EncryptedValue,
    pub injection_floor: Mode,
    pub binding: Binding,
    pub generation: u64,
}

/// A view `vault.rs` hands to [`persist`] for each in-memory secret — the already-encrypted value
/// plus its cleartext metadata. Borrowed, so persisting never clones the whole store needlessly.
pub struct RecordView<'a> {
    pub secret_ref: &'a str,
    pub enc: &'a EncryptedValue,
    pub injection_floor: Mode,
    pub binding: &'a Binding,
    pub generation: u64,
}

/// A structured load failure (ADR-008 §8). The caller turns this into a clear stderr diagnostic and
/// a non-zero exit (refuse to start) — there is **no panic path** and the store is never silently
/// emptied. (A *missing* file is NOT a `LoadError`: [`load`] returns an empty store for it.)
#[derive(Debug)]
pub struct LoadError {
    pub message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LoadError {}

fn load_err(msg: impl Into<String>) -> LoadError {
    LoadError {
        message: msg.into(),
    }
}

/// Load the store from `path`.
///
/// - A **missing** file → `Ok(vec![])` (first-run bootstrap, NOT an error — ADR-008 §8).
/// - A **present** file → parse JSON, check `version`, base64-decode each record into an
///   `EncryptedValue`, validate the nonce length. Any structural corruption → `Err(LoadError)`
///   (refuse to start). No decryption happens here (ADR-008 §7).
pub fn load(path: &Path) -> Result<Vec<LoadedRecord>, LoadError> {
    let raw = match std::fs::read(path) {
        Ok(bytes) => bytes,
        // Missing file is the normal first-run path: a fresh empty store.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(load_err(format!("store file unreadable: {e}"))),
    };

    let doc: StoreFileDoc = serde_json::from_slice(&raw)
        .map_err(|e| load_err(format!("store file is not valid JSON: {e}")))?;

    if doc.version != FORMAT_VERSION {
        return Err(load_err(format!(
            "unsupported store file version {} (expected {FORMAT_VERSION})",
            doc.version
        )));
    }

    let mut out = Vec::with_capacity(doc.records.len());
    for (secret_ref, rec) in doc.records {
        let ciphertext = decode_base64(&rec.ciphertext_b64).ok_or_else(|| {
            load_err(format!(
                "record {secret_ref}: ciphertext_b64 is not valid base64"
            ))
        })?;
        let nonce_bytes = decode_base64(&rec.nonce_b64).ok_or_else(|| {
            load_err(format!(
                "record {secret_ref}: nonce_b64 is not valid base64"
            ))
        })?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(load_err(format!(
                "record {secret_ref}: nonce must be {NONCE_LEN} bytes, got {}",
                nonce_bytes.len()
            )));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        out.push(LoadedRecord {
            secret_ref,
            enc: EncryptedValue { ciphertext, nonce },
            injection_floor: rec.injection_floor,
            binding: rec.binding,
            generation: rec.generation,
        });
    }
    Ok(out)
}

/// Persist the whole store to `path`, atomically and `0600` (ADR-008 §4).
///
/// Write path: a temp file `<path>.tmp.<pid>` **in the same directory** → `chmod 0600` BEFORE any
/// ciphertext bytes are written → `write_all` → `fsync` → atomic `rename` over `path`. A crash
/// mid-write leaves either the old complete file or the temp file — never a half-written store. Any
/// I/O failure returns `Err` so the caller surfaces `store_persist_failed` — never a silent success
/// (REQ-006). On error the temp file is best-effort removed and the prior `path` is left intact.
pub fn persist(path: &Path, records: &[RecordView<'_>]) -> Result<(), String> {
    let doc = StoreFileDoc {
        version: FORMAT_VERSION,
        records: records
            .iter()
            .map(|r| {
                (
                    r.secret_ref.to_string(),
                    StoredRecord {
                        ciphertext_b64: encode_base64(&r.enc.ciphertext),
                        nonce_b64: encode_base64(&r.enc.nonce),
                        injection_floor: r.injection_floor,
                        binding: r.binding.clone(),
                        generation: r.generation,
                    },
                )
            })
            .collect(),
    };
    let json =
        serde_json::to_vec_pretty(&doc).map_err(|e| format!("store serialization failed: {e}"))?;

    let tmp = temp_path(path);
    // Scope the file handle so it is closed before the rename.
    let write_result = (|| -> std::io::Result<()> {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        // chmod 0600 BEFORE writing any ciphertext (ADR-008 §4) — Unix only.
        set_0600(&f)?;
        let mut f = f;
        f.write_all(&json)?;
        f.sync_all()?; // fsync — durable before the rename
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp); // best-effort cleanup; prior `path` untouched
        return Err(format!("store_persist write failed: {e}"));
    }

    // Atomic replace. Same directory ⇒ same filesystem ⇒ rename can't degrade to copy.
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("store_persist rename failed: {e}")
    })?;
    Ok(())
}

/// `<path>.tmp.<pid>` in the SAME directory as `path` (ADR-008 §4 — same-fs atomic rename).
fn temp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".tmp.{}", std::process::id()));
    PathBuf::from(s)
}

#[cfg(unix)]
fn set_0600(f: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_0600(_f: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let mut d = std::env::temp_dir();
        let unique = format!(
            "vault-storefile-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        d.push(unique);
        std::fs::create_dir_all(&d).expect("create temp dir");
        d
    }

    fn proxy_binding() -> Binding {
        Binding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            env_var: "API_KEY".into(),
        }
    }

    fn sample_enc() -> EncryptedValue {
        EncryptedValue {
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            nonce: [9u8; NONCE_LEN],
        }
    }

    /// REQ-001 round-trip at the file layer: persist then load reconstructs the exact ciphertext,
    /// nonce, floor, binding and generation (no decrypt involved here).
    #[test]
    fn persist_then_load_round_trips_records() {
        let dir = temp_dir();
        let path = dir.join("store.json");
        let enc = sample_enc();
        let binding = proxy_binding();
        let views = vec![RecordView {
            secret_ref: "vault://test/api_key",
            enc: &enc,
            injection_floor: Mode::Proxy,
            binding: &binding,
            generation: 3,
        }];
        persist(&path, &views).expect("persist ok");

        let loaded = load(&path).expect("load ok");
        assert_eq!(loaded.len(), 1);
        let r = &loaded[0];
        assert_eq!(r.secret_ref, "vault://test/api_key");
        assert_eq!(r.enc.ciphertext, enc.ciphertext);
        assert_eq!(r.enc.nonce, enc.nonce);
        assert_eq!(r.injection_floor, Mode::Proxy);
        assert_eq!(r.binding.host, "api.example.com");
        assert_eq!(r.generation, 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// REQ-004(c): a missing file with the path set is NOT an error — a fresh empty store.
    #[test]
    fn missing_file_loads_empty() {
        let dir = temp_dir();
        let path = dir.join("does-not-exist.json");
        let loaded = load(&path).expect("missing file is not an error");
        assert!(loaded.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// REQ-004(b): each structural-corruption variant refuses to load (Err, no panic).
    #[test]
    fn corrupt_files_refuse_to_load() {
        let dir = temp_dir();

        let bad_json = dir.join("badjson.json");
        std::fs::write(&bad_json, b"this is not json{").unwrap();
        assert!(load(&bad_json).is_err(), "bad JSON refuses");

        let bad_version = dir.join("badver.json");
        std::fs::write(&bad_version, br#"{"version":999,"records":{}}"#).unwrap();
        assert!(load(&bad_version).is_err(), "unknown version refuses");

        let bad_b64 = dir.join("badb64.json");
        std::fs::write(
            &bad_b64,
            br#"{"version":1,"records":{"r":{"ciphertext_b64":"!!!notbase64!!!","nonce_b64":"CQkJCQkJCQkJCQkJ","injection_floor":"proxy","binding":{"host":"h","header":"Authorization","scheme":"Bearer","env_var":"API_KEY"},"generation":0}}}"#,
        )
        .unwrap();
        assert!(load(&bad_b64).is_err(), "invalid base64 refuses");

        // nonce that decodes to the wrong length (1 byte instead of 12).
        let bad_nonce = dir.join("badnonce.json");
        std::fs::write(
            &bad_nonce,
            br#"{"version":1,"records":{"r":{"ciphertext_b64":"AQID","nonce_b64":"AA==","injection_floor":"proxy","binding":{"host":"h","header":"Authorization","scheme":"Bearer","env_var":"API_KEY"},"generation":0}}}"#,
        )
        .unwrap();
        assert!(load(&bad_nonce).is_err(), "wrong-length nonce refuses");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// REQ-005: the persisted file is `0600`.
    #[cfg(unix)]
    #[test]
    fn persisted_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("store.json");
        let enc = sample_enc();
        let binding = proxy_binding();
        let views = vec![RecordView {
            secret_ref: "r",
            enc: &enc,
            injection_floor: Mode::Proxy,
            binding: &binding,
            generation: 0,
        }];
        persist(&path, &views).expect("persist ok");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "persisted file must be 0600");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// REQ-006: persist into a non-existent directory fails (no temp file can be created there) and
    /// leaves any prior file at the real path intact. (Models the failed-persist path; the
    /// caller maps the Err to `store_persist_failed`.)
    #[test]
    fn persist_into_unwritable_dir_errors() {
        let path = Path::new("/nonexistent-dir-vault-007/store.json");
        let enc = sample_enc();
        let binding = proxy_binding();
        let views = vec![RecordView {
            secret_ref: "r",
            enc: &enc,
            injection_floor: Mode::Proxy,
            binding: &binding,
            generation: 0,
        }];
        assert!(persist(path, &views).is_err(), "unwritable dir must error");
    }

    /// REQ-006: after a successful persist, only the real path exists — the temp file is gone.
    #[test]
    fn persist_leaves_no_temp_file() {
        let dir = temp_dir();
        let path = dir.join("store.json");
        let enc = sample_enc();
        let binding = proxy_binding();
        let views = vec![RecordView {
            secret_ref: "r",
            enc: &enc,
            injection_floor: Mode::Proxy,
            binding: &binding,
            generation: 0,
        }];
        persist(&path, &views).expect("persist ok");
        assert!(path.exists(), "real path exists");
        assert!(!temp_path(&path).exists(), "temp file removed after rename");
        std::fs::remove_dir_all(&dir).ok();
    }
}
