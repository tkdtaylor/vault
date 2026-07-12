// SPDX-License-Identifier: Apache-2.0
//! Cloud secret-manager backend **core** (ADR-007), behind task 004's `StoreBackend` seam.
//!
//! At the injection edge, `inject` resolves the plaintext by calling a remote store's "get value"
//! API instead of decrypting a local AES ciphertext. To keep the seam vendor-neutral, the backend
//! is split in two:
//!
//! - [`SecretManagerBackend`] — a cloud-agnostic `StoreBackend` that owns store-on-put /
//!   fetch-at-inject and the zero-knowledge invariants. Its `encrypt` stores the value in the remote
//!   and returns an **opaque locator** packed into `EncryptedValue` (the AES nonce/cipher path is
//!   NOT used); its `decrypt` fetches the live value via the client. A failed remote op is
//!   fail-closed: `backend_unavailable`, never a plaintext fallback (via the `StoreBackend`
//!   `store_error_code`/`fetch_error_code` seam).
//! - [`SecretManagerClient`] — **the single, documented pluggability seam**: the actual remote
//!   (`get_value` / `put_value` / `rotate_value`). Adopting a different secret store = **one new
//!   trait impl + a selection entry** ([`make_client`]); nothing in `SecretManagerBackend`, `Vault`,
//!   the contract, or any caller changes.
//!
//! This task ships the seam proven against **mock** clients only ([`MockSecretManagerClient`] +
//! [`AltMockSecretManagerClient`], the ≥2-adapter pluggability proof). The real per-cloud adapters
//! (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault), their SDK/REST dependency trees,
//! and the live get-value round-trip are **task 012** (credential-gated, feature-gated); each is a
//! third/fourth `SecretManagerClient` impl behind this same trait plus a `make_client` arm.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::crypto::{EncryptedValue, StoreBackend, NONCE_LEN};
use crate::handle::new_handle;

/// The single pluggability seam (ADR-007). One concrete adapter per secret store implements this;
/// the backend delegates all store/fetch to it. `&self` + interior mutability so a real adapter can
/// hold a connection pool and a test double can hold an in-memory map. `Err(String)` models a
/// denied / unavailable / not-found remote op (mapped to `backend_unavailable` above the seam).
pub trait SecretManagerClient: Send + Sync {
    /// Fetch the plaintext value stored under `remote_id`. Not-found / denied / unreachable → `Err`.
    fn get_value(&self, remote_id: &str) -> Result<String, String>;
    /// Store `value` under `remote_id` (create-or-replace). Denied / unreachable → `Err`.
    fn put_value(&self, remote_id: &str, value: &str) -> Result<(), String>;
    /// Rotate the value under an existing `remote_id` in place. For stable-remote-id adapters; the
    /// `StoreBackend`-seam wiring routes vault `rotate` through `encrypt` → `put_value` (a fresh
    /// locator + the per-secret generation bump handle invalidation), so this is the in-place path a
    /// real adapter uses when it tracks a stable id. Unknown id / denied → `Err`. `allow(dead_code)`:
    /// part of the ADR-007 client contract, exercised directly in tests, not called by the current
    /// put-through-`encrypt` wiring (a stable-id adapter, task 012, is its first production caller).
    #[allow(dead_code)]
    fn rotate_value(&self, remote_id: &str, value: &str) -> Result<(), String>;
}

/// The cloud-agnostic backend behind task 004's `StoreBackend` seam. Owns the zero-knowledge flow;
/// delegates the actual store/fetch to the [`SecretManagerClient`]. Swappable for `AesGcmBackend`
/// with no change to `resolve`/`inject`/`put`/`rotate` signatures or contract responses.
pub struct SecretManagerBackend {
    client: Arc<dyn SecretManagerClient>,
}

impl SecretManagerBackend {
    pub fn new(client: Arc<dyn SecretManagerClient>) -> Self {
        SecretManagerBackend { client }
    }
}

impl StoreBackend for SecretManagerBackend {
    /// Store the value in the remote under a fresh opaque locator; return the locator (not the
    /// value) packed into `EncryptedValue.ciphertext` with an unused zero nonce. The cleartext is
    /// never retained in the in-process `Secret` — only the locator is (REQ-001 / REQ-006).
    fn encrypt(&self, plaintext: &str) -> Result<EncryptedValue, String> {
        let remote_id = new_handle().map_err(|e| format!("locator rng: {e}"))?;
        self.client.put_value(&remote_id, plaintext)?;
        Ok(EncryptedValue {
            ciphertext: remote_id.into_bytes(),
            nonce: [0u8; NONCE_LEN],
        })
    }

    /// Re-materialise the value at the injection edge by fetching it from the remote via the client
    /// (REQ-002). A failed/denied/not-found fetch fails closed (`backend_unavailable` above the
    /// seam), never a plaintext fallback.
    fn decrypt(&self, value: &EncryptedValue) -> Result<String, String> {
        let remote_id = std::str::from_utf8(&value.ciphertext)
            .map_err(|_| "corrupt remote locator".to_string())?;
        self.client.get_value(remote_id)
    }

    fn store_error_code(&self) -> &'static str {
        "backend_unavailable"
    }
    fn fetch_error_code(&self) -> &'static str {
        "backend_unavailable"
    }
}

/// Resolve a backend name (e.g. from `--secret-backend <name>`) to a client — the **documented
/// drop-in registry**. Adopting a new store adds ONE match arm here plus its `SecretManagerClient`
/// impl; nothing else changes. The real per-cloud adapters (`aws` / `gcp` / `azure`) are task 012
/// (feature-gated); an unknown name is `None`.
pub fn make_client(name: &str) -> Option<Arc<dyn SecretManagerClient>> {
    match name {
        "mock" => Some(Arc::new(MockSecretManagerClient::new())),
        "alt-mock" => Some(Arc::new(AltMockSecretManagerClient::new())),
        // "aws" | "gcp" | "azure" => task 012 (feature-gated real adapters)
        _ => None,
    }
}

/// In-memory test double for the remote (mirrors task 004's `FixedKeyProvider`). Holds a
/// `remote-id → value` map, a settable failure mode (any op returns `Err` on demand, modelling a
/// denied / unavailable remote), and call counters. Performs **no** AES/nonce work, proving the
/// cloud path does not re-use the local crypto primitives.
pub struct MockSecretManagerClient {
    store: Mutex<HashMap<String, String>>,
    failing: AtomicBool,
    get_calls: AtomicUsize,
    put_calls: AtomicUsize,
}

impl Default for MockSecretManagerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSecretManagerClient {
    pub fn new() -> Self {
        MockSecretManagerClient {
            store: Mutex::new(HashMap::new()),
            failing: AtomicBool::new(false),
            get_calls: AtomicUsize::new(0),
            put_calls: AtomicUsize::new(0),
        }
    }
}

// Test-only inspection/injection helpers (the production path uses only the trait methods).
#[cfg(test)]
impl MockSecretManagerClient {
    /// Toggle the failure mode (models a denied / unreachable remote).
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
    /// How many times a value was fetched (a value materialises only at inject).
    pub fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }
    pub fn put_calls(&self) -> usize {
        self.put_calls.load(Ordering::SeqCst)
    }
    /// Whether the remote holds `value` anywhere (test helper for the store-via-client assertion).
    pub fn holds_value(&self, value: &str) -> bool {
        self.store.lock().unwrap().values().any(|v| v == value)
    }
}

impl SecretManagerClient for MockSecretManagerClient {
    fn get_value(&self, remote_id: &str) -> Result<String, String> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err("mock remote unavailable".into());
        }
        self.store
            .lock()
            .unwrap()
            .get(remote_id)
            .cloned()
            .ok_or_else(|| "mock remote: no such secret".to_string())
    }
    fn put_value(&self, remote_id: &str, value: &str) -> Result<(), String> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err("mock remote unavailable".into());
        }
        self.store
            .lock()
            .unwrap()
            .insert(remote_id.to_string(), value.to_string());
        Ok(())
    }
    fn rotate_value(&self, remote_id: &str, value: &str) -> Result<(), String> {
        if self.failing.load(Ordering::SeqCst) {
            return Err("mock remote unavailable".into());
        }
        let mut store = self.store.lock().unwrap();
        if !store.contains_key(remote_id) {
            return Err("mock remote: cannot rotate a missing id".into());
        }
        store.insert(remote_id.to_string(), value.to_string());
        Ok(())
    }
}

/// A **second, behaviorally-distinct** adapter (TC-007 pluggability proof), standing in for "a
/// different secret store". It uses a different internal representation (a `Vec` of pairs instead of
/// a `HashMap`) and no AES; the observable round-trip is identical. Proves that swapping stores needs
/// only a new trait impl.
pub struct AltMockSecretManagerClient {
    store: Mutex<Vec<(String, String)>>,
}

impl Default for AltMockSecretManagerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AltMockSecretManagerClient {
    pub fn new() -> Self {
        AltMockSecretManagerClient {
            store: Mutex::new(Vec::new()),
        }
    }
}

impl SecretManagerClient for AltMockSecretManagerClient {
    fn get_value(&self, remote_id: &str) -> Result<String, String> {
        self.store
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| id == remote_id)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| "alt-mock remote: no such secret".to_string())
    }
    fn put_value(&self, remote_id: &str, value: &str) -> Result<(), String> {
        let mut store = self.store.lock().unwrap();
        store.retain(|(id, _)| id != remote_id);
        store.push((remote_id.to_string(), value.to_string()));
        Ok(())
    }
    fn rotate_value(&self, remote_id: &str, value: &str) -> Result<(), String> {
        let mut store = self.store.lock().unwrap();
        match store.iter_mut().find(|(id, _)| id == remote_id) {
            Some(entry) => {
                entry.1 = value.to_string();
                Ok(())
            }
            None => Err("alt-mock remote: cannot rotate a missing id".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Binding, Mode, SystemClock, Vault};
    use serde_json::Value;

    fn binding() -> Binding {
        Binding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            env_var: "API_KEY".into(),
        }
    }

    /// A vault whose store backend is `SecretManagerBackend` over the given client.
    fn vault_over(client: Arc<dyn SecretManagerClient>) -> Vault {
        Vault::with_clock_and_backend(
            Box::new(SystemClock),
            Box::new(SecretManagerBackend::new(client)),
        )
    }

    fn handle_of(v: &mut Vault) -> String {
        v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string()
    }

    // TC-001 (REQ-001): `encrypt` stores via the client; the locator is NOT the cleartext, and the
    // value materialises only later at fetch. The in-process representation is the opaque locator.
    #[test]
    fn tc001_put_stores_via_client_locator_not_cleartext() {
        let mock = Arc::new(MockSecretManagerClient::new());
        let backend = SecretManagerBackend::new(mock.clone());
        let enc = backend.encrypt("SK-SECRET").expect("store via client");
        // The locator (the only thing the in-process Secret keeps) is NOT the cleartext.
        assert!(
            String::from_utf8_lossy(&enc.ciphertext)
                .find("SK-SECRET")
                .is_none(),
            "the locator must not be the cleartext"
        );
        // The value now lives in the (mock) remote, held by the client.
        assert!(
            mock.holds_value("SK-SECRET"),
            "remote holds the value after put"
        );
        assert_eq!(mock.put_calls(), 1);
        assert_eq!(mock.get_calls(), 0, "no fetch happens at put/encrypt time");
        // Edge: empty and a long (>1 KB) value both round-trip through the client.
        for value in ["", &"x".repeat(2048)] {
            let e = backend.encrypt(value).unwrap();
            assert_eq!(backend.decrypt(&e).unwrap(), value);
        }
    }

    // TC-002 (REQ-002): resolve→inject round-trips the value the client supplied, materialised only
    // at the inject edge; resolve carries no value; contract response identical to the AES backend.
    #[test]
    fn tc002_resolve_inject_round_trips_via_client() {
        let mock = Arc::new(MockSecretManagerClient::new());
        let mut v = vault_over(mock.clone());
        assert_eq!(
            v.put("vault://test/api_key", "SK-SECRET", Mode::Proxy, binding())["ok"],
            true
        );
        // resolve carries no value; the client has not been fetched yet.
        let resolved = v.resolve("vault://test/api_key", 300);
        assert!(
            resolved.to_string().find("SK-SECRET").is_none(),
            "resolve is value-free"
        );
        assert_eq!(
            mock.get_calls(),
            0,
            "value materialises only at inject, not resolve"
        );
        let handle = resolved["handle"].as_str().unwrap().to_string();
        // inject re-materialises the value via get_value; contract shape unchanged.
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["ok"], true);
        assert_eq!(inj["delivery"], "proxy");
        assert_eq!(inj["credential"], "SK-SECRET");
        assert_eq!(inj["binding"]["host"], "api.example.com");
        assert_eq!(mock.get_calls(), 1, "exactly one fetch at the inject edge");
        // Edge: env-mode delivery also round-trips the plaintext and fills wiped_at.
        let mut ve = vault_over(Arc::new(MockSecretManagerClient::new()));
        ve.put("vault://test/env_key", "SK-ENV", Mode::Env, binding());
        let he = ve.resolve("vault://test/env_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let env = ve.inject(&he, "sbx-1", Some(Mode::Env));
        assert_eq!(env["delivery"], "env");
        assert_eq!(env["credential"], "SK-ENV");
        assert!(env.get("wiped_at").is_some());
    }

    // TC-003 (REQ-003): a denied/unavailable/not-found fetch → `backend_unavailable`, no credential,
    // no plaintext, no panic; the fetch is BEFORE consume, so a transient failure does not burn the
    // handle (a retry after recovery delivers).
    #[test]
    fn tc003_fetch_failure_is_backend_unavailable_handle_not_burned() {
        let mock = Arc::new(MockSecretManagerClient::new());
        let mut v = vault_over(mock.clone());
        v.put("vault://test/api_key", "SK-SECRET", Mode::Proxy, binding());
        let handle = handle_of(&mut v);
        // Remote unavailable → fail closed.
        mock.set_failing(true);
        let failed = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(failed["error"]["code"], "backend_unavailable");
        assert!(
            failed.get("credential").is_none(),
            "no credential on a failed fetch"
        );
        assert!(
            failed.to_string().find("SK-SECRET").is_none(),
            "no plaintext leaks"
        );
        assert_eq!(failed["error"]["retryable"], false);
        // The handle was NOT burned by the fetch failure (decrypt-before-consume) — a retry delivers.
        mock.set_failing(false);
        let recovered = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(
            recovered["credential"], "SK-SECRET",
            "handle survived the transient failure"
        );
        // Not-found (entry removed) is also backend_unavailable on a fresh handle.
        let mut v2 = vault_over(mock.clone());
        v2.put("vault://test/other", "SK-OTHER", Mode::Proxy, binding());
        let h2 = v2.resolve("vault://test/other", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        // Clear the whole remote so the locator is not found.
        mock.store.lock().unwrap().clear();
        let nf = v2.inject(&h2, "sbx-1", Some(Mode::Proxy));
        assert_eq!(nf["error"]["code"], "backend_unavailable");
        // Edge: a put_value failure stores nothing (fail-closed) — the ref does not exist.
        let mock2 = Arc::new(MockSecretManagerClient::new());
        let mut v3 = vault_over(mock2.clone());
        mock2.set_failing(true);
        let put = v3.put("vault://test/nope", "SK-NEVER", Mode::Proxy, binding());
        assert_eq!(put["error"]["code"], "backend_unavailable");
        assert!(
            !mock2.holds_value("SK-NEVER"),
            "nothing stored on a failed put"
        );
        assert_eq!(
            v3.resolve("vault://test/nope", 300)["error"]["code"],
            "no_such_secret"
        );
    }

    // TC-004 (REQ-004): rotate updates the value through the client; the generation bump invalidates
    // the pre-rotation handle (`handle_invalidated`); a fresh resolve→inject returns the new value.
    #[test]
    fn tc004_rotate_updates_via_client_and_invalidates_old_handles() {
        let mock = Arc::new(MockSecretManagerClient::new());
        let mut v = vault_over(mock.clone());
        v.put("vault://test/api_key", "SK-OLD", Mode::Proxy, binding());
        let old_handle = handle_of(&mut v); // against generation 0
        assert_eq!(v.rotate("vault://test/api_key", "SK-NEW")["rotated"], true);
        assert!(
            mock.holds_value("SK-NEW"),
            "remote now holds the rotated value"
        );
        // The pre-rotation handle is invalidated (generation counter, task 003).
        let old = v.inject(&old_handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(old["error"]["code"], "handle_invalidated");
        // A fresh resolve→inject returns the rotated value.
        let fresh = handle_of(&mut v);
        assert_eq!(
            v.inject(&fresh, "sbx-1", Some(Mode::Proxy))["credential"],
            "SK-NEW"
        );
        // Edge: rotate on an unknown ref → no_such_secret (no store call).
        assert_eq!(
            v.rotate("vault://nope/x", "y")["error"]["code"],
            "no_such_secret"
        );
        // Edge: a rotate whose store fails → backend_unavailable, prior remote value untouched.
        mock.set_failing(true);
        let failed = v.rotate("vault://test/api_key", "SK-BLOCKED");
        assert_eq!(failed["error"]["code"], "backend_unavailable");
        mock.set_failing(false);
        assert!(
            mock.holds_value("SK-NEW"),
            "prior value untouched after a failed rotate"
        );
        assert!(
            !mock.holds_value("SK-BLOCKED"),
            "the blocked rotate stored nothing"
        );
        // The client's in-place rotate_value path (for stable-id adapters) round-trips directly.
        mock.put_value("stable-id", "V1").unwrap();
        mock.rotate_value("stable-id", "V2").unwrap();
        assert_eq!(mock.get_value("stable-id").unwrap(), "V2");
        assert!(
            mock.rotate_value("absent-id", "V3").is_err(),
            "rotate a missing id is an error"
        );
    }

    // TC-005 (REQ-005): the backend is swappable for AesGcmBackend with unchanged signatures and
    // contract responses; single-use / first-use binding / TTL / floor are not regressed.
    #[test]
    fn tc005_backend_swappable_full_round_trip() {
        let mut v = vault_over(Arc::new(MockSecretManagerClient::new()));
        v.put("vault://test/api_key", "SK-SECRET", Mode::Proxy, binding());
        let handle = handle_of(&mut v);
        // Deliver, then replay-rejected (single-use).
        assert_eq!(
            v.inject(&handle, "sbx-1", Some(Mode::Proxy))["credential"],
            "SK-SECRET"
        );
        assert_eq!(
            v.inject(&handle, "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "handle_consumed"
        );
        // Raise-only floor holds over the remote backend: an env request against a proxy floor stays proxy.
        let h2 = handle_of(&mut v);
        assert_eq!(v.inject(&h2, "sbx-1", Some(Mode::Env))["delivery"], "proxy");
        // TTL expiry unaffected by the backend (unknown handle after nothing resolved is unknown).
        assert_eq!(
            v.inject("deadbeef", "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "unknown_handle"
        );
    }

    // TC-006 (REQ-006): zero-knowledge — the value appears in no resolve/get/list response and not in
    // the in-process locator; it lives only in the remote and re-materialises only at inject.
    #[test]
    fn tc006_zero_knowledge_value_absent_everywhere_but_inject() {
        const SECRET: &str = "SK-DEMO-DO-NOT-LEAK";
        let mock = Arc::new(MockSecretManagerClient::new());
        let mut v = vault_over(mock.clone());
        v.put("vault://test/api_key", SECRET, Mode::Proxy, binding());
        v.put(
            "vault://test/second",
            "SK-SECOND-SECRET",
            Mode::Env,
            binding(),
        );
        let scan = |resp: Value, where_: &str| {
            assert!(
                resp.to_string().find(SECRET).is_none(),
                "value must not appear in {where_}"
            );
        };
        scan(v.resolve("vault://test/api_key", 300), "resolve");
        scan(v.get("vault://test/api_key"), "get");
        scan(v.list(), "list");
        // The in-process locator (backend.encrypt output) is not the cleartext.
        let enc = SecretManagerBackend::new(mock.clone())
            .encrypt(SECRET)
            .unwrap();
        assert!(String::from_utf8_lossy(&enc.ciphertext)
            .find(SECRET)
            .is_none());
        // It DOES re-materialise at the inject edge.
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            v.inject(&handle, "sbx-1", Some(Mode::Proxy))["credential"],
            SECRET
        );
    }

    // TC-007 (REQ-007): pluggability — ≥2 distinct adapters drive the identical round-trip behind the
    // one trait, with no change to SecretManagerBackend/Vault/contract; the selection registry
    // (make_client) maps names → the right adapter (unknown → None).
    #[test]
    fn tc007_pluggability_two_adapters_and_selection_registry() {
        // Adapter A: MockSecretManagerClient.
        let mut va = vault_over(Arc::new(MockSecretManagerClient::new()));
        va.put("vault://test/api_key", "SK-A", Mode::Proxy, binding());
        let ha = va.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let ra = va.inject(&ha, "sbx-1", Some(Mode::Proxy));

        // Adapter B: AltMockSecretManagerClient — a different impl, same wiring, identical round-trip.
        let mut vb = vault_over(Arc::new(AltMockSecretManagerClient::new()));
        vb.put("vault://test/api_key", "SK-B", Mode::Proxy, binding());
        let hb = vb.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let rb = vb.inject(&hb, "sbx-1", Some(Mode::Proxy));

        assert_eq!(ra["credential"], "SK-A");
        assert_eq!(rb["credential"], "SK-B");
        // Both produced the identical contract shape; only the trait object differed.
        assert_eq!(ra["delivery"], rb["delivery"]);
        assert_eq!(ra["ok"], rb["ok"]);

        // The selection registry maps known names to adapters that round-trip, unknown → None.
        for name in ["mock", "alt-mock"] {
            let client = make_client(name).unwrap_or_else(|| panic!("{name} must be selectable"));
            let mut v = vault_over(client);
            v.put("vault://test/api_key", "SK-SEL", Mode::Proxy, binding());
            let h = v.resolve("vault://test/api_key", 300)["handle"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(
                v.inject(&h, "sbx-1", Some(Mode::Proxy))["credential"],
                "SK-SEL"
            );
        }
        assert!(
            make_client("aws").is_none(),
            "real adapters are task 012 (not yet registered)"
        );
        assert!(make_client("unknown").is_none());
    }
}
