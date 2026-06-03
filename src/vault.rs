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

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::handle::new_handle;

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
fn default_header() -> String { "Authorization".into() }
fn default_scheme() -> String { "Bearer".into() }
fn default_env_var() -> String { "API_KEY".into() }

struct Secret {
    value: String,
    injection_floor: Mode,
    binding: Binding,
}

struct HandleRec {
    secret_ref: String,
    mode: Mode, // the secret's floor at resolve time
    #[allow(dead_code)] // TTL enforcement (auto-expire/wipe) is v1; stored now for the clock
    ttl: u64,
    consumed: bool,
    bound_sandbox: Option<String>,
}

#[derive(Default)]
pub struct Vault {
    store: HashMap<String, Secret>,
    handles: HashMap<String, HandleRec>,
}

impl Vault {
    pub fn new() -> Self {
        Vault::default()
    }

    /// Admin: store a secret with its injection floor + binding.
    pub fn put(&mut self, secret_ref: &str, value: &str, floor: Mode, binding: Binding) {
        self.store.insert(
            secret_ref.to_string(),
            Secret { value: value.to_string(), injection_floor: floor, binding },
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
        self.handles.insert(
            handle.clone(),
            HandleRec {
                secret_ref: secret_ref.to_string(),
                mode: floor,
                ttl,
                consumed: false,
                bound_sandbox: None,
            },
        );
        json!({ "handle": handle, "ttl": ttl, "injection_mode": floor.as_str() })
    }

    /// exec-sandbox-facing: pull-triggered push. Validates the handle↔sandbox binding,
    /// enforces single-use, then delivers the credential to the injection edge.
    pub fn inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>) -> Value {
        let Some(rec) = self.handles.get_mut(handle) else {
            return err("unknown_handle", "no such handle");
        };
        if rec.consumed {
            return err("handle_consumed", "handle already used (replay rejected)");
        }
        match &rec.bound_sandbox {
            Some(s) if s != sandbox_id => {
                return err("handle_bound_to_other_sandbox", "bound to a different sandbox");
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
        let wiped_at = 0; // env-mode auto-wipe timestamp (filled in by a real TTL clock)

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
        assert!(r.to_string().find("SK-SECRET").is_none(), "value must not be in resolve");

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
        assert!(v.inject(&handle, "sbx-1", Some(Mode::Proxy)).get("ok").is_some());
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
        assert_eq!(inj["delivery"], "proxy", "env request must not lower a proxy floor");
    }
}
