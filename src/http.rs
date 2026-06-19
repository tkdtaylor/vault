// SPDX-License-Identifier: Apache-2.0
//! vault HTTP read surface — opt-in, loopback-only, read-only, zero-knowledge (ADR-006).
//!
//! Exposes exactly two endpoints in the HashiCorp Vault / OpenBao KV-v2 API shape:
//!
//! ```text
//! GET /v1/sys/health        -> 200 {"initialized":true,"sealed":false}      (liveness; no store access)
//! GET /v1/secret/data/:path -> 200 KV-v2 envelope carrying the HANDLE       (never the value)
//! ```
//!
//! A `GET /v1/secret/data/:path` maps the path tail to a `vault://:path` `secret_ref`, calls the
//! existing `Vault::resolve`, and packs the **value-free** `{handle, ttl, injection_mode}` into the
//! Vault envelope. `resolve` is value-free by construction (ADR-001 §1), so no plaintext crosses the
//! TCP boundary — an HTTP reader gets a capability token in a Vault-shaped response, never a secret.
//!
//! Everything else is fail-closed: non-GET → 405, unroutable path → 404, malformed/over-long
//! request → 400, unknown secret → 404 `{"errors":[]}`. `inject`/`put`/`rotate`/`get`/`list` are
//! **not routed** here — there is no path/method that reaches them (the value delivery edge stays on
//! the `SO_PEERCRED`-gated Unix socket, ADR-002/005). The listener binds **loopback only**
//! (`127.0.0.1`); a non-loopback bind address is refused fail-closed (ADR-006 §3).
//!
//! The core logic is factored into pure, unit-testable functions (`http_route`, `http_secret_ref`,
//! `kv2_envelope`, `loopback_only`, `http_response_for`) mirroring task 001's `peer_uid_allowed` and
//! task 003's `handle_line` — no live TCP is needed to assert routing / mapping / envelope / bind /
//! value-absence.

use std::io::Read;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::vault::Vault;

/// Default TTL (seconds) minted for an HTTP read. The HTTP surface has no per-request TTL knob (it
/// is read-only and unauthenticated); this matches the IPC `resolve` default (`main::dispatch`).
const HTTP_RESOLVE_TTL: u64 = 300;

/// Maximum bytes vault will read for a single HTTP request body before refusing it as over-long
/// (REQ-007). A request whose body exceeds this is rejected `400` rather than buffered unbounded —
/// the read surface takes no body, so any sizeable body is already anomalous. `tiny_http` itself
/// bounds the request line + headers; this guards the body read we perform.
const MAX_REQUEST_BODY: usize = 8 * 1024;

/// The route a `(method, path)` pair resolves to. The table is **closed**: anything not explicitly
/// `Health` or `Read` is `NotFound` (or `MethodNotAllowed` for a non-GET) — there is no fall-through
/// to `inject`/`put`/`rotate`/`get`/`list` (REQ-006).
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET /v1/sys/health` — liveness only, no store access.
    Health,
    /// `GET /v1/secret/data/:path` — maps to `Vault::resolve(secret_ref)`; carries the `vault://` ref.
    Read(String),
    /// A non-GET method to any path → `405`.
    MethodNotAllowed,
    /// A GET to an unroutable path (or an empty `secret/data` tail) → `404`.
    NotFound,
}

/// Map a `/v1/secret/data/:path` URL path to a `vault://:path` `secret_ref` (REQ-004).
///
/// The tail after `/v1/secret/data/` becomes the `vault://`-scheme ref verbatim — nested segments
/// are preserved (`/v1/secret/data/team/prod/db` → `vault://team/prod/db`). An empty tail
/// (`/v1/secret/data` or `/v1/secret/data/`) is **not routable** → `None` (it maps to a 404, never a
/// `vault://` with an empty path). Pure and total over the input string.
pub fn http_secret_ref(path: &str) -> Option<String> {
    let tail = path.strip_prefix("/v1/secret/data/")?;
    if tail.is_empty() {
        return None;
    }
    Some(format!("vault://{tail}"))
}

/// The pure method/route decision (REQ-006). Method is decided **before** path read semantics: a
/// non-GET to any path is `MethodNotAllowed`, even to a path that would be a valid GET read. Only
/// `GET /v1/sys/health` and `GET /v1/secret/data/:path` (non-empty tail) are routable; everything
/// else is `NotFound`. No input maps to a mutation/inject verb.
pub fn http_route(method: &str, path: &str) -> Route {
    if method != "GET" {
        return Route::MethodNotAllowed;
    }
    if path == "/v1/sys/health" {
        return Route::Health;
    }
    match http_secret_ref(path) {
        Some(secret_ref) => Route::Read(secret_ref),
        None => Route::NotFound,
    }
}

/// Pack a value-free `resolve` response into the Vault KV-v2 envelope (REQ-004):
///
/// ```json
/// {"data":{"data":{"handle":"<hex>","injection_mode":"proxy"},"metadata":{"ttl":300}}}
/// ```
///
/// `data.data` carries the handle + injection_mode; `data.metadata` carries the ttl. The input is a
/// `Vault::resolve` result (`{handle, ttl, injection_mode}`) which is value-free by construction —
/// so the envelope carries no secret value, only the capability token. Pure.
pub fn kv2_envelope(resolved: &Value) -> Value {
    json!({
        "data": {
            "data": {
                "handle": resolved.get("handle").cloned().unwrap_or(Value::Null),
                "injection_mode": resolved.get("injection_mode").cloned().unwrap_or(Value::Null),
            },
            "metadata": {
                "ttl": resolved.get("ttl").cloned().unwrap_or(Value::Null),
            }
        }
    })
}

/// Bind-address validation (REQ-002): true IFF the host is the literal `127.0.0.1` loopback.
///
/// Fail-closed: a non-loopback address (`0.0.0.0`, a LAN IP, `::`, the bare wildcard) or an
/// unparseable address is `false` — the listener never binds a non-loopback interface. `localhost`
/// hostname forms and IPv6 loopback are out of scope for ADR-006 (literal `127.0.0.1` only); the
/// optional `:port` suffix is permitted (`127.0.0.1:8200`, `127.0.0.1:0`). Pure.
pub fn loopback_only(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host == "127.0.0.1"
}

/// Map a route + the shared vault state to the `(status, body)` pair the live handler emits
/// (REQ-003/004/005/006). This is the single source of the HTTP status/body mapping, so unit tests
/// assert status / body / value-absence without binding a socket.
///
/// - `Health` → `200 {"initialized":true,"sealed":false}` (no store access).
/// - `Read(ref)` → `Vault::resolve(ref)`; success → `200` KV-v2 envelope (the handle, never the
///   value); `no_such_secret` → `404 {"errors":[]}`; an RNG/mint failure → `500
///   {"errors":["internal error"]}`.
/// - `MethodNotAllowed` → `405 {"errors":["method not allowed"]}`.
/// - `NotFound` → `404 {"errors":[]}`.
pub fn http_response_for(route: &Route, v: &Arc<Mutex<Vault>>) -> (u16, Value) {
    match route {
        Route::Health => (200, json!({ "initialized": true, "sealed": false })),
        Route::Read(secret_ref) => {
            let resolved = v.lock().unwrap().resolve(secret_ref, HTTP_RESOLVE_TTL);
            match resolved.get("error").and_then(|e| e["code"].as_str()) {
                Some("no_such_secret") => (404, json!({ "errors": [] })),
                Some(_) => (500, json!({ "errors": ["internal error"] })),
                None => (200, kv2_envelope(&resolved)),
            }
        }
        Route::MethodNotAllowed => (405, json!({ "errors": ["method not allowed"] })),
        Route::NotFound => (404, json!({ "errors": [] })),
    }
}

/// The `400` bad-request shape — a request that cannot be safely parsed / is over-long (REQ-007).
fn bad_request() -> (u16, Value) {
    (400, json!({ "errors": ["bad request"] }))
}

/// Start the loopback-only HTTP read listener on `addr`, sharing `v` with the Unix socket.
///
/// Fail-closed bind (REQ-002): if `addr` is not the literal `127.0.0.1` loopback the listener does
/// **not** start — it logs a refusal and returns without binding, never a wildcard bind. On a
/// successful bind, each incoming request is handled on its own thread (thread-per-connection,
/// mirroring `handle_conn` on the Unix socket). This never returns while serving; call it on its own
/// thread so the Unix socket continues to serve in parallel.
pub fn serve_http(addr: &str, v: Arc<Mutex<Vault>>) {
    if !loopback_only(addr) {
        eprintln!(
            "vault: refusing --http-addr {addr} — HTTP read surface binds 127.0.0.1 loopback only \
             (ADR-006); no listener started"
        );
        return;
    }
    let server = match Server::http(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vault: failed to bind HTTP listener on {addr}: {e}");
            return;
        }
    };
    eprintln!("vault HTTP read surface serving on http://{addr} (loopback, read-only)");
    for request in server.incoming_requests() {
        let v = Arc::clone(&v);
        std::thread::spawn(move || handle_http(request, v));
    }
}

/// Handle one HTTP request: enforce the request-size bound, decide the route, and write the
/// `(status, body)` from `http_response_for`. Fail-closed: an over-long body → `400`; any I/O fault
/// is dropped without delivering anything. Never logs a secret (the only secret-derived datum that
/// can cross is the opaque handle on a successful read).
fn handle_http(mut request: Request, v: Arc<Mutex<Vault>>) {
    // Enforce the request-size bound (REQ-007). The read surface takes no body; a body over the
    // bound is anomalous and rejected `400` rather than buffered unbounded. We read at most
    // MAX_REQUEST_BODY + 1 bytes — if the +1 byte is present, the body exceeded the bound.
    let over_long = match request.body_length() {
        Some(len) if len > MAX_REQUEST_BODY => true,
        _ => {
            let mut buf = Vec::new();
            let mut limited = request.as_reader().take((MAX_REQUEST_BODY + 1) as u64);
            // A read error is treated as a malformed request (fail-closed → 400 below).
            match limited.read_to_end(&mut buf) {
                Ok(_) => buf.len() > MAX_REQUEST_BODY,
                Err(_) => {
                    respond(request, bad_request());
                    return;
                }
            }
        }
    };
    if over_long {
        respond(request, bad_request());
        return;
    }

    let method = method_str(request.method());
    let path = request.url().to_string();
    let route = http_route(method, &path);
    let result = http_response_for(&route, &v);
    respond(request, result);
}

/// `tiny_http::Method` → the uppercase HTTP method string `http_route` decides on.
fn method_str(method: &Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Head => "HEAD",
        Method::Patch => "PATCH",
        Method::Options => "OPTIONS",
        Method::Connect => "CONNECT",
        Method::Trace => "TRACE",
        Method::NonStandard(_) => "OTHER",
    }
}

/// Write a `(status, JSON body)` response with `Content-Type: application/json`. Best-effort: an I/O
/// failure on the write is dropped (the connection is gone) — never panics, never leaks.
fn respond(request: Request, (status, body): (u16, Value)) {
    let bytes = body.to_string().into_bytes();
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header is valid");
    let response = Response::from_data(bytes)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AesGcmBackend, InMemoryKeyProvider, StoreBackend};
    use crate::vault::{Binding, Mode, SystemClock};

    // Test-spec coverage map (docs/tasks/test-specs/005-vault-http-api-read-surface-test-spec.md):
    //   TC-001 (--http-addr opt-in / shared Arc) — the opt-in wiring lives in main::serve; the
    //          shared-Arc read path is exercised by `tc004_*` (a put on the shared vault is readable
    //          as a handle through `http_response_for`) and the live L6 smoke in the task report.
    //   TC-002 (loopback-only bind)              — `tc002_loopback_only_*`.
    //   TC-003 (health)                          — `tc003_health_*`.
    //   TC-004 (read → handle envelope, value absent) — `tc004_read_returns_handle_value_absent`.
    //   TC-005 (path → vault:// mapping)         — `tc005_secret_ref_mapping`.
    //   TC-006 (unknown secret → 404)            — `tc006_unknown_secret_is_404`.
    //   TC-007 (non-GET → 405; mutation unreachable) — `tc007_non_get_is_405_*`.
    //   TC-008 (unroutable GET → 404; admin unreachable) — `tc008_unroutable_get_is_404_*`.
    //   TC-009 (request-size bound named constant) — `tc009_request_size_bound_is_named`.
    //   TC-010 (value-absence across all paths)  — `tc010_no_path_leaks_value`.
    //   TC-011 (tiny_http pinned + dep-scan)     — Cargo.toml pin + the blocking dep-scan gate
    //          recorded in the task report (not a unit assertion).

    /// A fixed-key AES backend so the at-rest store works under `cargo test` (no env master key).
    fn test_backend() -> Box<dyn StoreBackend> {
        Box::new(AesGcmBackend::new(&InMemoryKeyProvider([42u8; 32])).expect("fixed-key backend"))
    }

    /// A shared vault (behind `Arc<Mutex>`, exactly as `serve` shares it between the two listeners),
    /// seeded with `vault://test/api_key = SK-SECRET`.
    fn seeded_shared() -> Arc<Mutex<Vault>> {
        let mut v = Vault::with_clock_and_backend(Box::new(SystemClock), test_backend());
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
        Arc::new(Mutex::new(v))
    }

    /// TC-002 (REQ-002): `loopback_only` is true only for literal `127.0.0.1` (with or without a
    /// port); a non-loopback / wildcard / unparseable address is refused fail-closed.
    #[test]
    fn tc002_loopback_only_accepts_only_127() {
        assert!(loopback_only("127.0.0.1:8200"));
        assert!(loopback_only("127.0.0.1:0"));
        assert!(loopback_only("127.0.0.1"));
        // Non-loopback / wildcard / IPv6 / LAN / unparseable → all refused.
        assert!(!loopback_only("0.0.0.0:8200"));
        assert!(!loopback_only("0.0.0.0"));
        assert!(!loopback_only("::"));
        assert!(!loopback_only("192.168.1.10:8200"));
        assert!(!loopback_only("localhost:8200"));
        assert!(!loopback_only("not an address"));
    }

    /// TC-003 (REQ-003): `GET /v1/sys/health` → `200 {"initialized":true,"sealed":false}` exactly,
    /// with no store access (it routes to `Health`, which never touches the vault).
    #[test]
    fn tc003_health_is_200_liveness_json() {
        assert_eq!(http_route("GET", "/v1/sys/health"), Route::Health);
        let v = seeded_shared();
        let (status, body) = http_response_for(&Route::Health, &v);
        assert_eq!(status, 200);
        assert_eq!(body, json!({ "initialized": true, "sealed": false }));
        // Liveness even on an empty store.
        let empty = Arc::new(Mutex::new(Vault::with_clock_and_backend(
            Box::new(SystemClock),
            test_backend(),
        )));
        assert_eq!(http_response_for(&Route::Health, &empty).0, 200);
    }

    /// TC-004 (REQ-004): a seeded read → `200` KV-v2 envelope carrying the handle + injection_mode +
    /// ttl; the plaintext `SK-SECRET` is absent from the whole serialized body (negative scan).
    #[test]
    fn tc004_read_returns_handle_value_absent() {
        let v = seeded_shared();
        let route = http_route("GET", "/v1/secret/data/test/api_key");
        assert_eq!(route, Route::Read("vault://test/api_key".into()));
        let (status, body) = http_response_for(&route, &v);
        assert_eq!(status, 200);
        // KV-v2 envelope shape: data.data.{handle,injection_mode} + data.metadata.ttl.
        let handle = body["data"]["data"]["handle"]
            .as_str()
            .expect("handle present");
        assert!(!handle.is_empty(), "handle is the hex capability token");
        assert_eq!(body["data"]["data"]["injection_mode"], "proxy");
        assert_eq!(body["data"]["metadata"]["ttl"], HTTP_RESOLVE_TTL);
        // Load-bearing negative assertion: the value never crosses the HTTP boundary.
        assert!(
            !body.to_string().contains("SK-SECRET"),
            "the secret value must not appear in the read envelope"
        );
    }

    /// TC-005 (REQ-004): path → `vault://` mapping is verbatim, nested segments preserved; an empty
    /// tail is unroutable (`None`).
    #[test]
    fn tc005_secret_ref_mapping() {
        assert_eq!(
            http_secret_ref("/v1/secret/data/test/api_key").as_deref(),
            Some("vault://test/api_key")
        );
        assert_eq!(
            http_secret_ref("/v1/secret/data/team/prod/db/password").as_deref(),
            Some("vault://team/prod/db/password")
        );
        assert_eq!(
            http_secret_ref("/v1/secret/data/single").as_deref(),
            Some("vault://single")
        );
        // Empty tail → None (unroutable; 404 by TC-008), never a vault:// with an empty path.
        assert_eq!(http_secret_ref("/v1/secret/data/"), None);
        assert_eq!(http_secret_ref("/v1/secret/data"), None);
    }

    /// TC-006 (REQ-005): an unknown secret → `404 {"errors":[]}`; no handle minted, no value.
    #[test]
    fn tc006_unknown_secret_is_404() {
        let v = seeded_shared();
        let route = http_route("GET", "/v1/secret/data/nope/missing");
        assert_eq!(route, Route::Read("vault://nope/missing".into()));
        let (status, body) = http_response_for(&route, &v);
        assert_eq!(status, 404);
        assert_eq!(body, json!({ "errors": [] }));
        assert!(
            body.get("data").is_none(),
            "no handle/envelope for a missing secret"
        );
    }

    /// TC-007 (REQ-006): any non-GET method to any path → `MethodNotAllowed` → `405`; no route from
    /// a non-GET reaches `put`/`rotate`. Method is decided before path read semantics.
    #[test]
    fn tc007_non_get_is_405_mutation_unreachable() {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            // Even to a path that WOULD be a valid GET read, a non-GET is 405.
            assert_eq!(
                http_route(method, "/v1/secret/data/test/api_key"),
                Route::MethodNotAllowed,
                "{method} must be 405, never a mutation"
            );
            assert_eq!(
                http_route(method, "/v1/sys/health"),
                Route::MethodNotAllowed
            );
        }
        let v = seeded_shared();
        let (status, body) = http_response_for(&Route::MethodNotAllowed, &v);
        assert_eq!(status, 405);
        assert_eq!(body, json!({ "errors": ["method not allowed"] }));
    }

    /// TC-008 (REQ-006): an unroutable GET → `NotFound` → `404 {"errors":[]}`; the route table is
    /// closed — nothing maps to `inject`/`get`/`list`/`rotate`. Only `Health` and `Read` are routable.
    #[test]
    fn tc008_unroutable_get_is_404_admin_unreachable() {
        for path in [
            "/v1/auth/login",
            "/v1/secret/metadata/x",
            "/",
            "/v1/sys/inject",
            "/v1/secret/data/", // empty tail
            "/v1/secret/data",  // no trailing slash, no tail
            "/v1/sys/seal",
        ] {
            assert_eq!(
                http_route("GET", path),
                Route::NotFound,
                "{path} must be 404 — no admin/inject route exists"
            );
        }
        let v = seeded_shared();
        let (status, body) = http_response_for(&Route::NotFound, &v);
        assert_eq!(status, 404);
        assert_eq!(body, json!({ "errors": [] }));
        // The route table is closed: GET only ever yields Health, Read, or NotFound — never a verb.
        // Read maps ONLY to value-free resolve (asserted by tc004/tc006: a handle or a 404).
    }

    /// TC-009 (REQ-007): the request-size bound is a named constant and is a sane positive value.
    /// (The live over-long → 400 path is exercised by the L6 smoke; the bound itself is asserted
    /// here, and `bad_request` is the fail-closed shape the handler emits.)
    #[test]
    fn tc009_request_size_bound_is_named() {
        // The bound is a named constant set to a sane page-ish size — the read surface takes no
        // body, so a small bound is correct; a request over it is rejected `400` (live L6 smoke).
        assert_eq!(
            MAX_REQUEST_BODY,
            8 * 1024,
            "request-size bound is a named constant"
        );
        let (status, body) = bad_request();
        assert_eq!(status, 400);
        assert_eq!(body, json!({ "errors": ["bad request"] }));
    }

    /// TC-010 (REQ-007, REQ-006): the plaintext `SK-SECRET` appears in NONE of the response bodies
    /// across every HTTP path — health, successful read, unknown-secret, 405, 404, and 400. The only
    /// secret-derived datum that ever crosses is the opaque handle (on the success read).
    #[test]
    fn tc010_no_path_leaks_value() {
        let v = seeded_shared();
        let bodies = vec![
            http_response_for(&Route::Health, &v).1,
            http_response_for(&http_route("GET", "/v1/secret/data/test/api_key"), &v).1,
            http_response_for(&http_route("GET", "/v1/secret/data/nope"), &v).1,
            http_response_for(&Route::MethodNotAllowed, &v).1,
            http_response_for(&Route::NotFound, &v).1,
            bad_request().1,
        ];
        for body in bodies {
            assert!(
                !body.to_string().contains("SK-SECRET"),
                "no HTTP path may leak the value; offending body: {body}"
            );
        }
    }

    /// Cross-check (TC-001 / TC-004): the HTTP read uses the SAME shared `Arc<Mutex<Vault>>` as the
    /// Unix socket — a secret `put` on the shared vault is immediately readable as a handle over the
    /// HTTP read path (no separate store).
    #[test]
    fn shared_vault_put_is_readable_over_http() {
        let v = seeded_shared();
        // A fresh put on the shared handle is visible to the HTTP read path.
        v.lock().unwrap().put(
            "vault://team/db",
            "SK-DB-SECRET",
            Mode::Env,
            Binding {
                host: String::new(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                env_var: "API_KEY".into(),
            },
        );
        let (status, body) = http_response_for(&http_route("GET", "/v1/secret/data/team/db"), &v);
        assert_eq!(status, 200);
        assert_eq!(body["data"]["data"]["injection_mode"], "env");
        assert!(!body["data"]["data"]["handle"].as_str().unwrap().is_empty());
        assert!(!body.to_string().contains("SK-DB-SECRET"), "value absent");
    }
}
