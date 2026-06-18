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
    value: String,
    injection_floor: Mode,
    binding: Binding,
}

struct HandleRec {
    secret_ref: String,
    mode: Mode, // the secret's floor at resolve time
    // Absolute expiry: now_unix() at resolve time + ttl. A handle is expired IFF
    // now_unix() >= expires_at (exactly-at-expiry counts as expired). ttl=0 ⇒ expires immediately.
    expires_at: u64,
    consumed: bool,
    bound_sandbox: Option<String>,
}

pub struct Vault {
    store: HashMap<String, Secret>,
    handles: HashMap<String, HandleRec>,
    clock: Box<dyn Clock>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault::new()
    }
}

impl Vault {
    /// Production constructor — wall-clock TTL enforcement.
    pub fn new() -> Self {
        Vault::with_clock(Box::new(SystemClock))
    }

    /// Construct with an explicit clock. Tests inject a controllable clock to cross expiry
    /// boundaries deterministically without sleeping (REQ-005 / TC-005).
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Vault {
            store: HashMap::new(),
            handles: HashMap::new(),
            clock,
        }
    }

    /// Admin: store a secret with its injection floor + binding.
    pub fn put(&mut self, secret_ref: &str, value: &str, floor: Mode, binding: Binding) {
        self.store.insert(
            secret_ref.to_string(),
            Secret {
                value: value.to_string(),
                injection_floor: floor,
                binding,
            },
        );
    }

    /// Agent-facing: mint an opaque single-use handle. Never returns the value.
    pub fn resolve(&mut self, secret_ref: &str, ttl: u64) -> Value {
        let Some(secret) = self.store.get(secret_ref) else {
            return err("no_such_secret", secret_ref);
        };
        let floor = secret.injection_floor;
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
            },
        );
        json!({ "handle": handle, "ttl": ttl, "injection_mode": floor.as_str() })
    }

    /// exec-sandbox-facing: pull-triggered push. Validates the handle↔sandbox binding,
    /// enforces single-use, then delivers the credential to the injection edge.
    pub fn inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>) -> Value {
        // Read the clock before borrowing the handle record (avoids overlapping borrows of self).
        let now = self.clock.now_unix();
        let Some(rec) = self.handles.get_mut(handle) else {
            return err("unknown_handle", "no such handle");
        };
        // Precedence (ADR-003): unknown_handle → consumed → expired → binding → deliver.
        // Consumption is checked BEFORE expiry: a handle that is both consumed and expired
        // returns handle_consumed (the use already happened — single-use is the prior fact).
        if rec.consumed {
            return err("handle_consumed", "handle already used (replay rejected)");
        }
        // Expired IFF now >= expires_at (exactly-at-expiry is expired; ttl=0 ⇒ immediate).
        // No credential is delivered and the handle is left unconsumed.
        if now >= rec.expires_at {
            return err("handle_expired", "handle TTL has elapsed");
        }
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
        rec.bound_sandbox = Some(sandbox_id.to_string());
        rec.consumed = true;
        let secret_ref = rec.secret_ref.clone();
        // env-mode auto-wipe timestamp: the moment the credential is handed to the env-setter.
        // It is the inject-time / scheduled-wipe instant per the injectable clock — proxy mode
        // does not carry a wiped_at (it has no in-sandbox value to wipe).
        let wiped_at = now;

        let secret = self.store.get(&secret_ref).expect("secret present");
        match effective {
            Mode::Proxy => json!({
                "ok": true, "delivery": "proxy",
                "credential": secret.value,
                "binding": secret.binding,
            }),
            Mode::Env => json!({
                "ok": true, "delivery": "env",
                "credential": secret.value,
                "var_name": secret.binding.env_var,
                "wiped_at": wiped_at,
            }),
        }
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// Test clock: a shared atomic the test can read and advance with no real sleeping (TC-005).
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// A vault wired to a controllable clock; returns the shared time handle alongside it.
    fn seeded_at(now: u64) -> (Vault, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(now));
        let mut v = Vault::with_clock(Box::new(TestClock(t.clone())));
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
        let mut v = Vault::new();
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
        let mut v = Vault::with_clock(Box::new(TestClock(t.clone())));
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
}
