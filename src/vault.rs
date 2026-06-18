//! vault core — store + resolve/inject broker.
//!
//! Contract (interface-contracts.md §2, v1):
//! ```text
//! resolve(secret_ref, requester_identity) -> { handle, ttl, injection_mode }   // NOT value
//! inject(handle, sandbox_identity, mode)  -> proxy: { ok, delivery, credential, binding }
//!                                            env:   { ok, delivery, credential, var_name, wiped_at }
//! ```
//!
//! The secret value lives only in this process's memory and is delivered to exec-sandbox's
//! egress proxy (proxy mode) or env-setter (env mode) at inject time — never to the agent.
//! The `credential` + `binding` return is the v0→v1 change the tracer-bullet surfaced (A7).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crypto::{
    random_key, AesGcmBackend, EncryptedValue, EnvKeyProvider, InMemoryKeyProvider, StoreBackend,
};
use crate::handle::new_handle;

/// Injectable clock seam — lets TTL expiry be tested deterministically without sleeping.
///
/// Production uses [`SystemClock`] (wall-clock seconds since the Unix epoch). Tests inject a
/// controllable clock and advance it to cross an expiry boundary in zero real time (TC-005).
pub trait Clock: Send + Sync {
    /// Current time as whole seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// Production clock: wall time via `std::time::SystemTime`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Injection mode. `proxy` is stronger than `env` (value never enters the sandbox).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Env,
    Proxy,
}

impl Mode {
    fn rank(self) -> u8 {
        match self {
            Mode::Env => 0,
            Mode::Proxy => 1,
        }
    }
    fn parse(s: &str) -> Option<Mode> {
        match s {
            "env" => Some(Mode::Env),
            "proxy" => Some(Mode::Proxy),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Mode::Env => "env",
            Mode::Proxy => "proxy",
        }
    }
}

/// Where/how the egress proxy injects the credential (proxy mode).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub host: String,
    #[serde(default = "default_header")]
    pub header: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default = "default_env_var")]
    pub env_var: String,
}
fn default_header() -> String {
    "Authorization".into()
}
fn default_scheme() -> String {
    "Bearer".into()
}
fn default_env_var() -> String {
    "API_KEY".into()
}

struct Secret {
    // The value at rest: AES-256-GCM ciphertext + its unique nonce (ADR-005). The cleartext is
    // **never** held here — it exists in plaintext only transiently inside `put`/`rotate` (before
    // encryption) and at the injection edge (after `inject` decrypts). REQ-001 / REQ-006.
    enc: EncryptedValue,
    injection_floor: Mode,
    binding: Binding,
    // Bumped on every `rotate`. A handle resolved against generation N is invalidated the moment
    // the secret advances past N — this is how rotate-invalidates-outstanding-handles is enforced
    // (ADR-004). A freshly `put` secret starts at generation 0.
    generation: u64,
}

struct HandleRec {
    secret_ref: String,
    mode: Mode, // the secret's floor at resolve time
    // Absolute expiry: now_unix() at resolve time + ttl. A handle is expired IFF
    // now_unix() >= expires_at (exactly-at-expiry counts as expired). ttl=0 ⇒ expires immediately.
    expires_at: u64,
    consumed: bool,
    bound_sandbox: Option<String>,
    // The secret's generation captured at resolve time. On inject, a mismatch with the secret's
    // current generation ⇒ the handle was resolved against a now-rotated value ⇒ `handle_invalidated`.
    generation: u64,
}

pub struct Vault {
    store: HashMap<String, Secret>,
    handles: HashMap<String, HandleRec>,
    clock: Box<dyn Clock>,
    // The store-encryption seam (REQ-005): the AES-256-GCM backend in production, swappable behind
    // the trait. `resolve`/`inject`/callers do not change when this swaps. The backend holds the
    // master key (from the key-provider seam) in its own memory — never beside the ciphertext.
    backend: Box<dyn StoreBackend>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault::new()
    }
}

impl Vault {
    /// Production constructor — wall-clock TTL enforcement, AES-256-GCM at-rest backend keyed from
    /// the environment ([`EnvKeyProvider`]).
    ///
    /// If no master key is configured/readable, the backend is left **unconfigured**: it fails
    /// closed on every encrypt/decrypt (no plaintext fallback — REQ-003). A `put` then stores
    /// nothing and a later `inject` returns `decrypt_failed`; the vault never holds or returns a
    /// plaintext value without a key. Construction itself does not panic.
    pub fn new() -> Self {
        let backend = production_backend();
        Vault::with_clock_and_backend(Box::new(SystemClock), backend)
    }

    /// Construct with an explicit clock and the production (env-keyed) at-rest backend (task 002
    /// API). Since task 004 the at-rest store needs a key, so tests use
    /// [`with_clock_and_backend`](Self::with_clock_and_backend) to inject a fixed-key backend; this
    /// env-keyed variant remains the public clock-only constructor.
    #[allow(dead_code)]
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Vault::with_clock_and_backend(clock, production_backend())
    }

    /// Construct with a self-contained **ephemeral** AES-256-GCM backend: a fresh random 32-byte
    /// key from `/dev/urandom`, held in memory for this process only (never persisted, never
    /// logged). Used by the `demo` subcommand so it is genuinely encrypted-at-rest without an
    /// operator-supplied master key. Falls back to the unconfigured (fail-closed) backend only if
    /// the RNG read fails — never to plaintext.
    pub fn with_ephemeral_key() -> Self {
        let backend: Box<dyn StoreBackend> =
            match random_key().and_then(|k| AesGcmBackend::new(&InMemoryKeyProvider(k))) {
                Ok(b) => Box::new(b),
                Err(_) => Box::new(UnconfiguredBackend),
            };
        Vault::with_clock_and_backend(Box::new(SystemClock), backend)
    }

    /// Construct with an explicit clock **and** an explicit store backend — the seam tests use to
    /// inject a fixed-key AES backend (deterministic) or a non-AES backend (REQ-005 / TC-007).
    pub fn with_clock_and_backend(clock: Box<dyn Clock>, backend: Box<dyn StoreBackend>) -> Self {
        Vault {
            store: HashMap::new(),
            handles: HashMap::new(),
            clock,
            backend,
        }
    }

    /// Admin: store a secret with its injection floor + binding. The value is **encrypted on put**
    /// (REQ-001) — the cleartext is not retained in the store after this returns.
    ///
    /// Fail-closed: if encryption fails (no key configured, RNG failure), **nothing is stored** for
    /// this ref — no plaintext fallback. A later `resolve` of an unstored ref returns
    /// `no_such_secret`; the vault never holds the value in the clear.
    pub fn put(&mut self, secret_ref: &str, value: &str, floor: Mode, binding: Binding) {
        let Ok(enc) = self.backend.encrypt(value) else {
            // Fail closed: do not store plaintext, do not store a half-secret. The ref simply
            // does not exist until a key-configured put succeeds.
            return;
        };
        self.store.insert(
            secret_ref.to_string(),
            Secret {
                enc,
                injection_floor: floor,
                binding,
                generation: 0,
            },
        );
    }

    /// Admin: read a secret's metadata — **never the value** (REQ-001 / TC-001).
    ///
    /// Fail-closed: an unknown or empty `secret_ref` → `no_such_secret`. The response carries only
    /// `{exists, injection_floor, binding}`; the stored value never appears.
    pub fn get(&self, secret_ref: &str) -> Value {
        let Some(secret) = self.store.get(secret_ref) else {
            return err("no_such_secret", secret_ref);
        };
        json!({
            "exists": true,
            "injection_floor": secret.injection_floor.as_str(),
            "binding": secret.binding,
        })
    }

    /// Admin: list the stored `secret_ref`s with their floors — **never any value** (REQ-002 / TC-003).
    ///
    /// An empty store returns an empty list, not an error. Ordering is unspecified (HashMap).
    pub fn list(&self) -> Value {
        let secrets: Vec<Value> = self
            .store
            .iter()
            .map(|(secret_ref, secret)| {
                json!({
                    "secret_ref": secret_ref,
                    "injection_floor": secret.injection_floor.as_str(),
                })
            })
            .collect();
        json!({ "secrets": secrets })
    }

    /// Admin: replace a secret's value in place, preserving floor + binding — **never echoes the
    /// value** (REQ-003 / TC-004). Bumps the secret's generation, which invalidates every
    /// outstanding handle resolved against the old value (REQ-004 / TC-005, ADR-004).
    ///
    /// Fail-closed: an unknown or empty `secret_ref` → `no_such_secret`, nothing rotated.
    pub fn rotate(&mut self, secret_ref: &str, value: &str) -> Value {
        // The ref must exist before we spend effort encrypting (fail-closed on unknown ref).
        if !self.store.contains_key(secret_ref) {
            return err("no_such_secret", secret_ref);
        }
        // Encrypt the new value with a FRESH nonce (REQ-004 — no reuse with the prior value),
        // borrowing the backend immutably before we take a mutable borrow on the store entry. A
        // failed encrypt fails closed: the old ciphertext is left untouched, nothing is rotated.
        let enc = match self.backend.encrypt(value) {
            Ok(e) => e,
            Err(e) => return err("encrypt_failed", &e),
        };
        let secret = self
            .store
            .get_mut(secret_ref)
            .expect("ref present (checked above)");
        secret.enc = enc;
        // Advance the generation: every handle minted against the prior value is now stale and
        // will be rejected with `handle_invalidated` on inject (rotate-invalidates, ADR-004).
        secret.generation = secret.generation.saturating_add(1);
        json!({
            "ok": true,
            "rotated": true,
            "injection_floor": secret.injection_floor.as_str(),
            "binding": secret.binding,
        })
    }

    /// Agent-facing: mint an opaque single-use handle. Never returns the value.
    pub fn resolve(&mut self, secret_ref: &str, ttl: u64) -> Value {
        let Some(secret) = self.store.get(secret_ref) else {
            return err("no_such_secret", secret_ref);
        };
        let floor = secret.injection_floor;
        let generation = secret.generation;
        let handle = match new_handle() {
            Ok(h) => h,
            Err(e) => return err("rng_error", &e.to_string()),
        };
        // Saturating add so a huge ttl can't wrap; ttl=0 ⇒ expires_at == now ⇒ expired on any inject.
        let expires_at = self.clock.now_unix().saturating_add(ttl);
        self.handles.insert(
            handle.clone(),
            HandleRec {
                secret_ref: secret_ref.to_string(),
                mode: floor,
                expires_at,
                consumed: false,
                bound_sandbox: None,
                generation,
            },
        );
        json!({ "handle": handle, "ttl": ttl, "injection_mode": floor.as_str() })
    }

    /// exec-sandbox-facing: pull-triggered push. Validates the handle↔sandbox binding,
    /// enforces single-use, then delivers the credential to the injection edge.
    pub fn inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>) -> Value {
        // Read the clock before borrowing the handle record (avoids overlapping borrows of self).
        let now = self.clock.now_unix();
        // Snapshot the read-only handle fields needed by the precedence checks, dropping the
        // immutable borrow before we touch `self.store` (rotation check) or re-borrow mutably.
        let (secret_ref, handle_generation) = {
            let Some(rec) = self.handles.get(handle) else {
                return err("unknown_handle", "no such handle");
            };
            // Precedence (ADR-003): unknown_handle → consumed → expired → invalidated → binding →
            // deliver. Consumption is checked BEFORE expiry: a handle that is both consumed and
            // expired returns handle_consumed (the use already happened — single-use is prior).
            if rec.consumed {
                return err("handle_consumed", "handle already used (replay rejected)");
            }
            // Expired IFF now >= expires_at (exactly-at-expiry is expired; ttl=0 ⇒ immediate).
            // No credential is delivered and the handle is left unconsumed.
            if now >= rec.expires_at {
                return err("handle_expired", "handle TTL has elapsed");
            }
            (rec.secret_ref.clone(), rec.generation)
        };
        // Rotation invalidation (ADR-004): a handle minted against an earlier value is stale once
        // the secret rotates. Checked after consumed/expired and before binding/delivery, so a
        // pre-rotation handle can never inject the post-rotation value (no credential delivered).
        let cur_generation = self.store.get(&secret_ref).map(|s| s.generation);
        if cur_generation != Some(handle_generation) {
            return err(
                "handle_invalidated",
                "handle resolved against a rotated secret",
            );
        }
        // Re-borrow the handle mutably for the binding check and the consume/bind mutation.
        let rec = self
            .handles
            .get_mut(handle)
            .expect("handle present (checked above)");
        match &rec.bound_sandbox {
            Some(s) if s != sandbox_id => {
                return err(
                    "handle_bound_to_other_sandbox",
                    "bound to a different sandbox",
                );
            }
            _ => {}
        }
        // effective mode = max(secret floor, policy-raised). vault may RAISE, never LOWER.
        let mut effective = rec.mode;
        if let Some(m) = requested {
            if m.rank() > effective.rank() {
                effective = m;
            }
        }

        // Decrypt at the injection edge (REQ-002) — the ONLY place the cleartext re-materialises.
        // Done BEFORE consuming the handle so a tamper/integrity fault (`decrypt_failed`) does not
        // burn the single-use handle and, critically, never yields a silent wrong value (REQ-004 /
        // TC-005). A failed decrypt fails closed: no credential, no state mutation.
        let secret = self.store.get(&secret_ref).expect("secret present");
        let credential = match self.backend.decrypt(&secret.enc) {
            Ok(pt) => pt,
            Err(_) => return err("decrypt_failed", "stored ciphertext failed authentication"),
        };
        // Re-read the immutable fields we still need, then consume + bind (single-use, first-use).
        let secret = self.store.get(&secret_ref).expect("secret present");
        let binding = secret.binding.clone();
        let env_var = secret.binding.env_var.clone();
        let rec = self
            .handles
            .get_mut(handle)
            .expect("handle present (checked above)");
        rec.bound_sandbox = Some(sandbox_id.to_string());
        rec.consumed = true;
        // env-mode auto-wipe timestamp: the moment the credential is handed to the env-setter.
        // It is the inject-time / scheduled-wipe instant per the injectable clock — proxy mode
        // does not carry a wiped_at (it has no in-sandbox value to wipe).
        let wiped_at = now;

        match effective {
            Mode::Proxy => json!({
                "ok": true, "delivery": "proxy",
                "credential": credential,
                "binding": binding,
            }),
            Mode::Env => json!({
                "ok": true, "delivery": "env",
                "credential": credential,
                "var_name": env_var,
                "wiped_at": wiped_at,
            }),
        }
    }
}

/// Build the production at-rest backend: AES-256-GCM keyed from the environment. If no key is
/// configured, return an [`UnconfiguredBackend`] that fails closed on every operation — there is no
/// plaintext fallback (REQ-003). Construction never panics.
fn production_backend() -> Box<dyn StoreBackend> {
    match AesGcmBackend::new(&EnvKeyProvider) {
        Ok(b) => Box::new(b),
        Err(_) => Box::new(UnconfiguredBackend),
    }
}

/// A backend with no usable key: every encrypt/decrypt fails closed. Used when the production vault
/// starts without a configured master key — the vault holds and returns nothing in the clear.
struct UnconfiguredBackend;
impl StoreBackend for UnconfiguredBackend {
    fn encrypt(&self, _plaintext: &str) -> Result<EncryptedValue, String> {
        Err("no master key configured".into())
    }
    fn decrypt(&self, _value: &EncryptedValue) -> Result<String, String> {
        Err("no master key configured".into())
    }
}

pub fn parse_mode(v: &Value) -> Option<Mode> {
    v.as_str().and_then(Mode::parse)
}

fn err(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message, "retryable": false } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::InMemoryKeyProvider;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// Test clock: a shared atomic the test can read and advance with no real sleeping (TC-005).
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Build a deterministic fixed-key AES-256-GCM backend for tests (the key is injected via the
    /// key-provider seam — REQ-003 — so construction never depends on the process environment).
    fn test_backend() -> Box<dyn StoreBackend> {
        Box::new(AesGcmBackend::new(&InMemoryKeyProvider([42u8; 32])).expect("fixed-key backend"))
    }

    /// A test vault with the production system clock and a fixed-key AES backend.
    fn test_vault() -> Vault {
        Vault::with_clock_and_backend(Box::new(SystemClock), test_backend())
    }

    /// A vault wired to a controllable clock; returns the shared time handle alongside it.
    fn seeded_at(now: u64) -> (Vault, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(now));
        let mut v = Vault::with_clock_and_backend(Box::new(TestClock(t.clone())), test_backend());
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            Binding {
                host: "api.example.com".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        (v, t)
    }

    fn seeded() -> Vault {
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            Binding {
                host: "api.example.com".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        v
    }

    #[test]
    fn resolve_hides_value_and_inject_delivers_proxy() {
        let mut v = seeded();
        let r = v.resolve("vault://test/api_key", 300);
        assert!(r.get("handle").is_some());
        assert_eq!(r["injection_mode"], "proxy");
        assert!(
            r.to_string().find("SK-SECRET").is_none(),
            "value must not be in resolve"
        );

        let handle = r["handle"].as_str().unwrap().to_string();
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["delivery"], "proxy");
        assert_eq!(inj["credential"], "SK-SECRET");
        assert_eq!(inj["binding"]["host"], "api.example.com");
    }

    #[test]
    fn replay_is_rejected() {
        let mut v = seeded();
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(v
            .inject(&handle, "sbx-1", Some(Mode::Proxy))
            .get("ok")
            .is_some());
        let second = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(second["error"]["code"], "handle_consumed");
    }

    #[test]
    fn floor_cannot_be_lowered() {
        // secret floor is proxy; a request for env must NOT lower it.
        let mut v = seeded();
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Env));
        assert_eq!(
            inj["delivery"], "proxy",
            "env request must not lower a proxy floor"
        );
    }

    // --- Task 002: TTL auto-wipe (TC-001..TC-006) ---

    /// TC-001 (REQ-001): resolve records expires_at = now + ttl; response stays value-free.
    #[test]
    fn tc001_resolve_records_expiry_from_ttl() {
        let (mut v, _t) = seeded_at(1000);
        let r = v.resolve("vault://test/api_key", 300);
        let handle = r["handle"].as_str().unwrap().to_string();
        // Resolve response is unchanged: handle, ttl, mode, and no value.
        assert_eq!(r["ttl"], 300);
        assert_eq!(r["injection_mode"], "proxy");
        assert!(
            r.to_string().find("SK-SECRET").is_none(),
            "value must not be in resolve"
        );
        // Internal: expiry is exactly t + ttl.
        assert_eq!(v.handles.get(&handle).unwrap().expires_at, 1300);
    }

    /// TC-001 edge: ttl=0 ⇒ expires immediately; any inject (even at the same instant) fails.
    #[test]
    fn tc001_ttl_zero_expires_immediately() {
        let (mut v, _t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 0)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(v.handles.get(&handle).unwrap().expires_at, 1000);
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["error"]["code"], "handle_expired");
        assert!(inj.get("credential").is_none(), "no credential on expiry");
    }

    /// TC-002 (REQ-002, REQ-005): inject after expiry → handle_expired, no credential.
    #[test]
    fn tc002_inject_after_expiry_is_rejected() {
        let (mut v, t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1400, Ordering::SeqCst); // advance past expiry (no sleeping)
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["error"]["code"], "handle_expired");
        assert!(
            inj.get("credential").is_none(),
            "no credential field on expiry"
        );
        assert!(inj.get("ok").is_none());
    }

    /// TC-002 boundary (REQ-002): exactly-at-expiry (now == expires_at) is expired.
    #[test]
    fn tc002_exactly_at_expiry_is_expired() {
        let (mut v, t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1300, Ordering::SeqCst); // now == expires_at
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(
            inj["error"]["code"], "handle_expired",
            "now >= expires_at ⇒ expired"
        );
        assert!(inj.get("credential").is_none());
    }

    /// TC-003 (REQ-003): inject within the window delivers normally (v0 happy path unchanged).
    #[test]
    fn tc003_inject_before_expiry_delivers() {
        let (mut v, t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1200, Ordering::SeqCst); // still inside the window
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["ok"], true);
        assert_eq!(inj["delivery"], "proxy");
        assert_eq!(inj["credential"], "SK-SECRET");
        assert_eq!(inj["binding"]["host"], "api.example.com");
    }

    /// TC-003 edge: raise-only floor still applies within the TTL window.
    #[test]
    fn tc003_floor_still_raise_only_within_window() {
        let (mut v, t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1100, Ordering::SeqCst);
        // proxy floor, env requested ⇒ stays proxy (never lowered).
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Env));
        assert_eq!(inj["delivery"], "proxy");
    }

    /// TC-004 (REQ-004): env-mode wiped_at is a real, non-zero timestamp = inject time.
    #[test]
    fn tc004_env_wiped_at_is_real_timestamp() {
        let t = Arc::new(AtomicU64::new(1000));
        let mut v = Vault::with_clock_and_backend(Box::new(TestClock(t.clone())), test_backend());
        // env floor secret so delivery is env mode.
        v.put(
            "vault://test/env_key",
            "SK-ENV",
            Mode::Env,
            Binding {
                host: String::new(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        let handle = v.resolve("vault://test/env_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1200, Ordering::SeqCst);
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Env));
        assert_eq!(inj["delivery"], "env");
        assert_eq!(
            inj["wiped_at"], 1200,
            "wiped_at = inject-time clock, not the 0 placeholder"
        );
        assert_ne!(inj["wiped_at"], 0);
    }

    /// TC-004 edge: proxy-mode delivery does NOT carry a spurious wiped_at.
    #[test]
    fn tc004_proxy_has_no_wiped_at() {
        let (mut v, t) = seeded_at(1000);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(1100, Ordering::SeqCst);
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["delivery"], "proxy");
        assert!(inj.get("wiped_at").is_none(), "proxy mode has no wiped_at");
    }

    /// TC-005 (REQ-005): the default (production) clock is the system clock — smoke wiring check.
    #[test]
    fn tc005_default_clock_is_system_clock() {
        // SystemClock returns a plausible recent wall-clock value (> 2020-01-01).
        let now = SystemClock.now_unix();
        assert!(
            now > 1_577_836_800,
            "SystemClock must return real wall time"
        );
        // Vault::new() wires a working clock: resolve gives a future expiry vs that clock.
        let mut v = seeded();
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(v.handles.get(&handle).unwrap().expires_at >= now + 300 - 5);
    }

    /// TC-006 (REQ-006): precedence — consumed-before-expired.
    #[test]
    fn tc006_precedence_expired_vs_consumed() {
        // (a) expired-but-unconsumed ⇒ handle_expired.
        let (mut v, t) = seeded_at(1000);
        let h_a = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t.store(2000, Ordering::SeqCst); // expired, never injected
        assert_eq!(
            v.inject(&h_a, "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "handle_expired"
        );

        // (b) consumed within TTL, then replayed within TTL ⇒ handle_consumed.
        let (mut v2, t2) = seeded_at(1000);
        let h_b = v2.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t2.store(1100, Ordering::SeqCst);
        assert_eq!(v2.inject(&h_b, "sbx-1", Some(Mode::Proxy))["ok"], true);
        assert_eq!(
            v2.inject(&h_b, "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "handle_consumed"
        );

        // (c) both consumed AND expired ⇒ handle_consumed wins (consumption is the prior fact).
        let (mut v3, t3) = seeded_at(1000);
        let h_c = v3.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        t3.store(1100, Ordering::SeqCst);
        assert_eq!(v3.inject(&h_c, "sbx-1", Some(Mode::Proxy))["ok"], true);
        t3.store(2000, Ordering::SeqCst); // now also expired
        assert_eq!(
            v3.inject(&h_c, "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "handle_consumed",
            "consumed-before-expired precedence (ADR-003)"
        );
    }

    // --- Task 003: get / list / rotate admin verbs (TC-001..TC-007) ---

    /// TC-001 (REQ-001): get returns floor + binding, never the value.
    #[test]
    fn tc001_get_returns_metadata_not_value() {
        let v = seeded();
        let r = v.get("vault://test/api_key");
        assert_eq!(r["exists"], true);
        assert_eq!(r["injection_floor"], "proxy");
        assert_eq!(r["binding"]["host"], "api.example.com");
        // binding defaults are reflected.
        assert_eq!(r["binding"]["header"], "Authorization");
        assert_eq!(r["binding"]["scheme"], "Bearer");
        assert_eq!(r["binding"]["env_var"], "API_KEY");
        assert!(
            r.to_string().find("SK-SECRET").is_none(),
            "value must never appear in get response"
        );
    }

    /// TC-002 (REQ-001): get on an unknown ref is fail-closed (no_such_secret), no metadata/value.
    #[test]
    fn tc002_get_unknown_ref_is_fail_closed() {
        let v = seeded();
        let r = v.get("vault://nope/x");
        assert_eq!(r["error"]["code"], "no_such_secret");
        assert!(r.get("exists").is_none(), "no metadata on unknown ref");
        // Edge: empty secret_ref → fail-closed error, not a panic.
        let e = v.get("");
        assert_eq!(e["error"]["code"], "no_such_secret");
    }

    /// TC-003 (REQ-002): list returns the stored refs with floors and no values; empty store ⇒ [].
    #[test]
    fn tc003_list_returns_refs_no_values() {
        let mut v = seeded();
        v.put(
            "vault://test/second",
            "SK-SECOND",
            Mode::Env,
            Binding {
                host: String::new(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        let r = v.list();
        let refs: Vec<&str> = r["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["secret_ref"].as_str().unwrap())
            .collect();
        assert!(refs.contains(&"vault://test/api_key"));
        assert!(refs.contains(&"vault://test/second"));
        let s = r.to_string();
        assert!(s.find("SK-SECRET").is_none(), "no value in list");
        assert!(s.find("SK-SECOND").is_none(), "no value in list");

        // Edge: empty store ⇒ empty list, not an error.
        let empty = test_vault();
        let er = empty.list();
        assert!(er.get("error").is_none(), "empty store is not an error");
        assert_eq!(er["secrets"].as_array().unwrap().len(), 0);
    }

    /// TC-004 (REQ-003): rotate swaps the value, keeps floor + binding, echoes no value; a later
    /// resolve→inject delivers the new value. Unknown ref ⇒ no_such_secret.
    #[test]
    fn tc004_rotate_swaps_value_preserves_metadata_no_echo() {
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-OLD",
            Mode::Proxy,
            Binding {
                host: "api.example.com".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        let r = v.rotate("vault://test/api_key", "SK-NEW");
        assert_eq!(r["ok"], true);
        assert_eq!(r["injection_floor"], "proxy", "floor preserved");
        assert_eq!(r["binding"]["host"], "api.example.com", "binding preserved");
        let s = r.to_string();
        assert!(s.find("SK-NEW").is_none(), "rotate must not echo new value");
        assert!(s.find("SK-OLD").is_none(), "rotate must not echo old value");

        // A handle resolved AFTER rotation delivers the new value normally.
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let inj = v.inject(&handle, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["credential"], "SK-NEW");

        // Edge: rotate an unknown ref ⇒ no_such_secret, fail-closed.
        let e = v.rotate("vault://nope/x", "whatever");
        assert_eq!(e["error"]["code"], "no_such_secret");
    }

    /// TC-005 (REQ-004): rotation invalidates a pre-rotation handle — it cannot inject the new
    /// value (handle_invalidated, ADR-004). A handle resolved after rotation works normally.
    #[test]
    fn tc005_rotate_invalidates_pre_rotation_handle() {
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-OLD",
            Mode::Proxy,
            Binding {
                host: "api.example.com".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        // Resolve a handle against the OLD value.
        let pre = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        // Rotate to a NEW value.
        v.rotate("vault://test/api_key", "SK-NEW");
        // The pre-rotation handle must NOT deliver SK-NEW — it is invalidated.
        let inj = v.inject(&pre, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["error"]["code"], "handle_invalidated");
        assert!(
            inj.get("credential").is_none(),
            "no credential on an invalidated handle"
        );
        assert!(
            inj.to_string().find("SK-NEW").is_none(),
            "pre-rotation handle must never see the new value"
        );

        // A handle resolved after rotation injects the new value normally.
        let post = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            v.inject(&post, "sbx-2", Some(Mode::Proxy))["credential"],
            "SK-NEW"
        );
    }

    /// TC-006 (REQ-005): unknown op still surfaces unknown_op at the dispatch layer is covered in
    /// main.rs; here we assert the in-process verbs round-trip (get/list/rotate) coexist with the
    /// existing resolve/inject path on one Vault instance.
    #[test]
    fn tc006_verbs_coexist_in_process() {
        let mut v = seeded();
        assert_eq!(v.get("vault://test/api_key")["exists"], true);
        assert_eq!(
            v.list()["secrets"].as_array().unwrap().len(),
            1,
            "one seeded secret"
        );
        assert_eq!(v.rotate("vault://test/api_key", "SK-ROT")["ok"], true);
        let handle = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            v.inject(&handle, "sbx-1", Some(Mode::Proxy))["credential"],
            "SK-ROT"
        );
    }

    /// TC-007 (cross-cutting): no get/list/rotate response contains the value, even when the value
    /// carries JSON-special characters.
    #[test]
    fn tc007_no_admin_verb_leaks_value() {
        let tricky = r#"SK-"quote"\and{brace}:colon"#;
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            tricky,
            Mode::Proxy,
            Binding {
                host: "api.example.com".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        // Match on the raw inner substring that would survive JSON escaping.
        let needle = "quote";
        assert!(
            v.get("vault://test/api_key")
                .to_string()
                .find(needle)
                .is_none(),
            "get must not leak the value"
        );
        assert!(
            v.list().to_string().find(needle).is_none(),
            "list must not leak the value"
        );
        assert!(
            v.rotate("vault://test/api_key", tricky)
                .to_string()
                .find(needle)
                .is_none(),
            "rotate must not echo the value"
        );
    }

    // --- Task 004: encrypted-at-rest store (TC-001..TC-007) ---

    /// A proxy binding used by the encryption tests.
    fn proxy_binding() -> Binding {
        Binding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            env_var: "API_KEY".into(),
        }
    }

    /// Return every byte held at rest for a ref: ciphertext bytes followed by the nonce. The
    /// cleartext must never appear within this (REQ-006). Reaches into the private `Secret` (same
    /// module) deliberately — the at-rest representation is exactly what an attacker with a memory
    /// dump of the store would see.
    fn at_rest_bytes(v: &Vault, secret_ref: &str) -> Vec<u8> {
        let s = v.store.get(secret_ref).expect("secret present");
        let mut bytes = s.enc.ciphertext.clone();
        bytes.extend_from_slice(&s.enc.nonce);
        bytes
    }

    /// TC-001 (REQ-001): put stores ciphertext, not plaintext. The cleartext is absent from the
    /// at-rest bytes; empty and long values both round-trip.
    #[test]
    fn tc001_put_stores_ciphertext_not_plaintext() {
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        let rest = at_rest_bytes(&v, "vault://test/api_key");
        assert!(
            !contains_subslice(&rest, b"SK-SECRET"),
            "cleartext must not appear in the at-rest ciphertext"
        );
        // The stored representation is non-empty ciphertext (value + 16-byte GCM tag).
        assert!(!rest.is_empty(), "ciphertext present");

        // Edge: empty value and a >1-block (>16 byte) value both encrypt and round-trip.
        for val in ["", &"A".repeat(64)] {
            let mut vv = test_vault();
            vv.put("vault://test/x", val, Mode::Proxy, proxy_binding());
            let h = vv.resolve("vault://test/x", 300)["handle"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(
                vv.inject(&h, "sbx-1", Some(Mode::Proxy))["credential"],
                val,
                "empty/long value round-trips"
            );
        }
    }

    /// TC-002 (REQ-002): resolve→inject round-trips the exact plaintext, decrypting only at the
    /// injection edge; resolve still carries no value. Env-mode delivery also round-trips.
    #[test]
    fn tc002_resolve_inject_round_trips_plaintext() {
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        let r = v.resolve("vault://test/api_key", 300);
        assert!(
            r.to_string().find("SK-SECRET").is_none(),
            "resolve carries no value"
        );
        let h = r["handle"].as_str().unwrap().to_string();
        let inj = v.inject(&h, "sbx-1", Some(Mode::Proxy));
        assert_eq!(
            inj["credential"], "SK-SECRET",
            "decrypt at edge yields exact plaintext"
        );

        // Env-mode delivery round-trips too.
        let mut ev = test_vault();
        ev.put("vault://test/env", "SK-ENV", Mode::Env, proxy_binding());
        let eh = ev.resolve("vault://test/env", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let einj = ev.inject(&eh, "sbx-1", Some(Mode::Env));
        assert_eq!(einj["delivery"], "env");
        assert_eq!(einj["credential"], "SK-ENV");
    }

    /// TC-003 (REQ-003): the key comes from the provider seam, not stored beside the ciphertext; the
    /// same key decrypts, a different key fails, and a missing key fails closed (never plaintext).
    #[test]
    fn tc003_key_from_provider_seam_not_embedded() {
        // The fixed key [42;32] is never serialized into the store: scan the at-rest bytes for it.
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        let rest = at_rest_bytes(&v, "vault://test/api_key");
        assert!(
            !contains_subslice(&rest, &[42u8; 32]),
            "key bytes must not appear beside the ciphertext"
        );

        // Same provider decrypts; a different key cannot (proves the key is external — see the
        // crypto-module tests `different_key_cannot_decrypt`). Here: an unconfigured vault fails
        // closed rather than ever returning plaintext.
        let mut nokey = Vault::with_clock_and_backend(
            Box::new(SystemClock),
            Box::new(super::UnconfiguredBackend),
        );
        nokey.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        // put fail-closed: nothing stored without a key → resolve sees no secret.
        let r = nokey.resolve("vault://test/api_key", 300);
        assert_eq!(
            r["error"]["code"], "no_such_secret",
            "missing key ⇒ fail closed, no plaintext fallback"
        );
    }

    /// TC-004 (REQ-004): unique nonce per put/rotation — identical plaintexts produce different
    /// ciphertexts, and rotation draws a fresh nonce (no reuse with the prior value).
    #[test]
    fn tc004_unique_nonces_no_reuse() {
        let mut v = test_vault();
        v.put("vault://a", "SK-SAME", Mode::Proxy, proxy_binding());
        v.put("vault://b", "SK-SAME", Mode::Proxy, proxy_binding());
        let na = v.store.get("vault://a").unwrap().enc.nonce;
        let nb = v.store.get("vault://b").unwrap().enc.nonce;
        let ca = v.store.get("vault://a").unwrap().enc.ciphertext.clone();
        let cb = v.store.get("vault://b").unwrap().enc.ciphertext.clone();
        assert_ne!(
            na, nb,
            "two puts of identical plaintext use different nonces"
        );
        assert_ne!(ca, cb, "identical plaintext ⇒ different ciphertext");

        // Rotation draws a fresh nonce (distinct from the pre-rotation one).
        let before = v.store.get("vault://a").unwrap().enc.nonce;
        v.rotate("vault://a", "SK-SAME");
        let after = v.store.get("vault://a").unwrap().enc.nonce;
        assert_ne!(before, after, "rotation uses a fresh nonce");
    }

    /// TC-005 (REQ-004): tampered/truncated ciphertext fails closed with `decrypt_failed` — never a
    /// silent wrong value, never a panic.
    #[test]
    fn tc005_tampered_ciphertext_fails_closed() {
        // Tamper: flip a ciphertext byte in the store, then resolve→inject.
        let mut v = test_vault();
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        v.store
            .get_mut("vault://test/api_key")
            .unwrap()
            .enc
            .ciphertext[0] ^= 0xff;
        let h = v.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        let inj = v.inject(&h, "sbx-1", Some(Mode::Proxy));
        assert_eq!(
            inj["error"]["code"], "decrypt_failed",
            "bad tag ⇒ fail closed"
        );
        assert!(
            inj.get("credential").is_none(),
            "no value on decrypt failure"
        );
        assert!(inj.get("ok").is_none());

        // Truncation also fails closed.
        let mut v2 = test_vault();
        v2.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        v2.store
            .get_mut("vault://test/api_key")
            .unwrap()
            .enc
            .ciphertext
            .truncate(1);
        let h2 = v2.resolve("vault://test/api_key", 300)["handle"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            v2.inject(&h2, "sbx-1", Some(Mode::Proxy))["error"]["code"],
            "decrypt_failed",
            "truncated ciphertext ⇒ fail closed"
        );
    }

    /// TC-006 (REQ-001, REQ-006): at-rest negative — the cleartext does not appear anywhere in the
    /// stored representation (here, the demo placeholder used in `main::demo`).
    #[test]
    fn tc006_at_rest_negative_cleartext_absent() {
        let mut v = test_vault();
        v.put(
            "vault://demo/key",
            "SK-DEMO-DO-NOT-LEAK",
            Mode::Proxy,
            proxy_binding(),
        );
        // Scan ALL at-rest bytes across the whole store for the cleartext.
        let mut all = Vec::new();
        for (_ref, s) in v.store.iter() {
            all.extend_from_slice(&s.enc.ciphertext);
            all.extend_from_slice(&s.enc.nonce);
        }
        assert!(
            !contains_subslice(&all, b"SK-DEMO-DO-NOT-LEAK"),
            "cleartext must be absent from the entire at-rest store"
        );
        // And a second cleartext used elsewhere in tests, for good measure.
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        let rest = at_rest_bytes(&v, "vault://test/api_key");
        assert!(!contains_subslice(&rest, b"SK-SECRET"));
    }

    /// TC-007 (REQ-005): the backend is swappable behind the trait. A non-AES (plaintext-in-memory)
    /// test backend substitutes behind the seam; `resolve`/`inject` signatures and the contract
    /// responses are unchanged, and no AEAD type leaks into the response.
    #[test]
    fn tc007_backend_is_swappable() {
        // A second backend used only here: it stores the value bytes verbatim in the `ciphertext`
        // field (no encryption). It proves the seam — resolve/inject don't know which backend runs.
        struct PlaintextBackend;
        impl StoreBackend for PlaintextBackend {
            fn encrypt(&self, plaintext: &str) -> Result<EncryptedValue, String> {
                Ok(EncryptedValue {
                    ciphertext: plaintext.as_bytes().to_vec(),
                    nonce: [0u8; 12],
                })
            }
            fn decrypt(&self, value: &EncryptedValue) -> Result<String, String> {
                String::from_utf8(value.ciphertext.clone()).map_err(|_| "decrypt_failed".into())
            }
        }

        let mut v =
            Vault::with_clock_and_backend(Box::new(SystemClock), Box::new(PlaintextBackend));
        v.put(
            "vault://test/api_key",
            "SK-SECRET",
            Mode::Proxy,
            proxy_binding(),
        );
        // Unchanged contract response shape on resolve…
        let r = v.resolve("vault://test/api_key", 300);
        assert_eq!(r["injection_mode"], "proxy");
        assert!(
            r.to_string().find("SK-SECRET").is_none(),
            "resolve value-free"
        );
        // …and on inject — exact same fields as the AES backend.
        let h = r["handle"].as_str().unwrap().to_string();
        let inj = v.inject(&h, "sbx-1", Some(Mode::Proxy));
        assert_eq!(inj["ok"], true);
        assert_eq!(inj["delivery"], "proxy");
        assert_eq!(inj["credential"], "SK-SECRET");
        assert_eq!(inj["binding"]["host"], "api.example.com");
    }

    /// Naive substring search over bytes (no external crate) for the at-rest negative tests.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
