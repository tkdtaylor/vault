// SPDX-License-Identifier: Apache-2.0
//! vault — JIT zero-knowledge secret store + credential broker.
//!
//! The agent core only ever holds an opaque handle; the plaintext is delivered to
//! exec-sandbox's egress proxy (proxy mode) or env-setter (env mode) at inject time, then
//! wiped. See README.md.
//!
//! Usage:
//!   vault serve --socket /run/vault.sock                                  # IPC daemon (resolve/inject/put/ping)
//!   vault serve --socket /run/vault.sock --http-addr 127.0.0.1:8200       # + opt-in loopback HTTP read surface
//!   vault serve --socket /run/vault.sock --store-path /var/lib/vault.store # + opt-in persistent encrypted store
//!   vault demo                                                            # run put->resolve->inject in-process

mod attest;
mod crypto;
mod handle;
mod http;
mod store_file;
mod vault;
mod zeroize;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use serde_json::{json, Value};

use attest::{AttestError, AttestationVerifier, Ed25519Verifier, PassthroughVerifier};
use vault::{parse_mode, Binding, Mode, Vault};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve(&args[2..]),
        Some("demo") => demo(),
        _ => {
            eprintln!("usage: vault <serve --socket PATH | demo>");
            std::process::exit(2);
        }
    }
}

fn serve(args: &[String]) {
    let socket = flag(args, "--socket").unwrap_or_else(|| {
        eprintln!("serve: --socket is required");
        std::process::exit(2);
    });
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind unix socket");
    // uid-restricted local channel: 0600 limits callers to the same uid (the credential
    // handoff travels this socket). The SO_PEERCRED peer-uid check in handle_conn is the
    // kernel-verified half of the same D5 restriction — see ADR-002.
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).ok();
    eprintln!("vault serving on {socket}");

    // Opt-in persistent encrypted store (ADR-008). Source precedence: `--store-path` flag wins over
    // the `VAULT_STORE_PATH` env fallback (mirrors VAULT_MASTER_KEY_FILE/VAULT_MASTER_KEY). Unset ⇒
    // in-memory only, today's behavior byte-for-byte (no file read/written). Set ⇒ load on startup
    // and write-through every put/rotate. A corrupt store file refuses to start (non-zero exit, no
    // panic) — never start with a silently-emptied store.
    let store_path = resolve_store_path(
        flag(args, "--store-path").as_deref(),
        std::env::var("VAULT_STORE_PATH").ok().as_deref(),
    );
    let vault = match store_path {
        Some(path) => {
            // SEC-003 (defense-in-depth): the 0600 file protects its contents, but a
            // group/world-writable PARENT directory lets a local attacker play temp-path games.
            // FIX 1's O_EXCL + O_NOFOLLOW + random suffix already closes the active vector; this is
            // a non-fatal startup WARNING (never refuse to start, never log a secret) so operators
            // can tighten the directory posture.
            warn_if_store_dir_writable(&path);
            match Vault::new_persistent(path.clone()) {
                Ok(v) => {
                    eprintln!("vault persistent store: {}", path.display());
                    v
                }
                Err(e) => {
                    eprintln!(
                        "vault: refusing to start — corrupt store file {}: {e}",
                        path.display()
                    );
                    std::process::exit(1);
                }
            }
        }
        None => Vault::new(),
    };
    let v = Arc::new(Mutex::new(vault));

    // Opt-in Ed25519 attestation verification at the inject edge (ADR-010, task 010). Source
    // precedence mirrors --store-path exactly: `--attest-trust-root-file` flag wins over the
    // `VAULT_ATTEST_TRUST_ROOT_FILE` env fallback. Set ⇒ verify every inject's signed sandbox
    // attestation against this 32-byte trust root and fail closed on a missing/invalid one; a
    // configured-but-unusable root (unreadable / wrong length / not hex-or-base64) refuses to start
    // (non-zero exit, no panic), same posture as a corrupt --store-path. Unset ⇒ PassthroughVerifier:
    // today's opaque, caller-asserted first-use binding, byte-for-byte (transitional, the gap stays
    // open, see ADR-010 Decision 4).
    let verifier: Arc<dyn AttestationVerifier> = match resolve_trust_root_path(
        flag(args, "--attest-trust-root-file").as_deref(),
        std::env::var("VAULT_ATTEST_TRUST_ROOT_FILE")
            .ok()
            .as_deref(),
    ) {
        Some(path) => match load_trust_root(&path) {
            Ok(root) => {
                eprintln!(
                    "vault attestation verification: ENABLED (trust root {})",
                    path.display()
                );
                Arc::new(Ed25519Verifier::new(root))
            }
            Err(e) => {
                eprintln!(
                    "vault: refusing to start, unusable attestation trust root {}: {e}",
                    path.display()
                );
                std::process::exit(1);
            }
        },
        None => {
            eprintln!(
                "vault attestation verification: DISABLED (transitional passthrough, no trust root configured)"
            );
            Arc::new(PassthroughVerifier)
        }
    };

    // Opt-in HTTP read surface (ADR-006). Absent → no TCP listener starts and the Unix socket
    // serves exactly as before (default posture unchanged). Present → a loopback-only, read-only
    // HTTP listener runs on its own thread, sharing the SAME Arc<Mutex<Vault>> as the Unix socket;
    // a non-loopback --http-addr is refused fail-closed inside serve_http (no wildcard bind ever).
    if let Some(http_addr) = flag(args, "--http-addr") {
        let http_v = Arc::clone(&v);
        std::thread::spawn(move || http::serve_http(&http_addr, http_v));
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let v = Arc::clone(&v);
        let verifier = Arc::clone(&verifier);
        std::thread::spawn(move || handle_conn(stream, v, verifier));
    }
}

fn handle_conn(
    mut stream: UnixStream,
    v: Arc<Mutex<Vault>>,
    verifier: Arc<dyn AttestationVerifier>,
) {
    // D5 kernel-verified peer-uid gate (ADR-002). Read the connecting process's uid via
    // SO_PEERCRED and admit it ONLY if it equals this server's own effective uid. Fail-closed:
    // an unreadable credential is a denial, never an admission — and no op is dispatched until
    // the gate passes, so resolve/inject/put never run for a rejected peer.
    let server_uid = geteuid().as_raw();
    match read_peer_uid(&stream) {
        Some(peer_uid) if peer_uid_allowed(peer_uid, server_uid) => {}
        _ => {
            let _ = writeln!(
                stream,
                "{}",
                err("peer_uid_denied", "peer uid not permitted")
            );
            return;
        }
    }

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let resp = handle_line(&line, &v, verifier.as_ref());
    let _ = writeln!(stream, "{resp}");
}

/// Parse one newline-delimited JSON request line and route it to `dispatch`.
///
/// Fail-closed ingress (TC-006): a line that is not well-formed JSON yields a structured
/// `bad_request` error rather than a panic or a dropped connection — `handle_conn` writes the
/// response back and the connection survives. Behaviour is identical to the inlined match it
/// replaced; this is a pure extraction so the parse→dispatch step is unit-testable without a
/// live socket. The SO_PEERCRED peer-uid gate stays upstream in `handle_conn`, unchanged.
fn handle_line(line: &str, v: &Arc<Mutex<Vault>>, verifier: &dyn AttestationVerifier) -> Value {
    match serde_json::from_str::<Value>(line) {
        Ok(req) => dispatch(&req, v, verifier),
        Err(e) => err("bad_request", &e.to_string()),
    }
}

/// Read the connecting peer's uid from the kernel via `SO_PEERCRED`.
///
/// Returns `None` on any read failure — the caller treats `None` as a **denial** (fail-closed,
/// REQ-004). This is the I/O half of the gate; the pure equality decision is `peer_uid_allowed`.
fn read_peer_uid(stream: &UnixStream) -> Option<u32> {
    getsockopt(stream, PeerCredentials)
        .ok()
        .map(|cred| cred.uid())
}

/// Pure peer-uid admission decision (REQ-005): admit IFF the peer uid equals the server uid.
///
/// Equality, **not** privilege — uid 0 (root) connecting to a non-root server is denied unless it
/// is the server's own uid. No I/O, total over the two uids, unit-testable without a live socket.
fn peer_uid_allowed(peer_uid: u32, server_uid: u32) -> bool {
    peer_uid == server_uid
}

fn dispatch(req: &Value, v: &Arc<Mutex<Vault>>, verifier: &dyn AttestationVerifier) -> Value {
    match req["op"].as_str() {
        Some("ping") => json!({ "ok": true }),
        Some("put") => {
            let binding: Binding =
                serde_json::from_value(req["binding"].clone()).unwrap_or_else(|_| Binding {
                    host: String::new(),
                    header: "Authorization".into(),
                    scheme: "Bearer".into(),
                    env_var: "API_KEY".into(),
                });
            let floor = parse_mode(&req["injection_floor"]).unwrap_or(Mode::Env);
            // `put` now returns a structured result: `{ok:true}` on success, or a fail-closed error
            // (`encrypt_failed` with no key, `store_persist_failed` if the disk write fails — ADR-008
            // §4). Surface it directly rather than always claiming success.
            v.lock().unwrap().put(
                req["secret_ref"].as_str().unwrap_or(""),
                req["value"].as_str().unwrap_or(""),
                floor,
                binding,
            )
        }
        Some("get") => v
            .lock()
            .unwrap()
            .get(req["secret_ref"].as_str().unwrap_or("")),
        Some("list") => v.lock().unwrap().list(),
        Some("rotate") => v.lock().unwrap().rotate(
            req["secret_ref"].as_str().unwrap_or(""),
            req["value"].as_str().unwrap_or(""),
        ),
        Some("resolve") => {
            let ttl = req["ttl"].as_u64().unwrap_or(300);
            v.lock()
                .unwrap()
                .resolve(req["secret_ref"].as_str().unwrap_or(""), ttl)
        }
        Some("inject") => {
            let mode = parse_mode(&req["mode"]);
            // Attestation verification precedes the Vault call (ADR-010, same layering as the
            // SO_PEERCRED gate): a rejected attestation returns the mapped error and `Vault::inject`
            // is NEVER called, so a failed verification can never consume, bind, or expire-check a
            // handle. On success the VERIFIED id (from the signed payload in Ed25519 mode; the
            // caller-asserted id in transitional passthrough mode) is the binding key.
            match verifier.verify(&req["sandbox_identity"]) {
                Ok(verified_id) => v.lock().unwrap().inject(
                    req["handle"].as_str().unwrap_or(""),
                    &verified_id,
                    mode,
                ),
                Err(AttestError::Missing) => err(
                    "attestation_missing",
                    "sandbox attestation required but not present",
                ),
                Err(AttestError::Invalid(reason)) => err("attestation_invalid", &reason),
            }
        }
        _ => err("unknown_op", "unsupported op"),
    }
}

fn demo() {
    // Self-contained encrypted-at-rest demo: an ephemeral AES-256-GCM key generated for this
    // process (no operator key needed). The stored value is ciphertext; `inject` decrypts at the
    // edge. The demo's placeholder value is an obvious non-secret.
    let mut v = Vault::with_ephemeral_key();
    v.put(
        "vault://test/api_key",
        "SK-DEMO-DO-NOT-LEAK",
        Mode::Proxy,
        Binding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            env_var: "API_KEY".into(),
        },
    );
    let resolved = v.resolve("vault://test/api_key", 300);
    println!("resolve -> {resolved}");
    let handle = resolved["handle"].as_str().unwrap().to_string();
    let injected = v.inject(&handle, "sbx-demo", Some(Mode::Proxy));
    println!("inject  -> {injected}");
    let replay = v.inject(&handle, "sbx-demo", Some(Mode::Proxy));
    println!("replay  -> {replay}  (rejected: single-use handle, D5)");
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Resolve the opt-in persistent store path: `--store-path` flag wins over the `VAULT_STORE_PATH`
/// env fallback; neither set ⇒ `None` (in-memory only). Mirrors the
/// `VAULT_MASTER_KEY_FILE`/`VAULT_MASTER_KEY` precedence (TC-009, REQ-008). Pure — no env reads, no
/// I/O — so the precedence is unit-testable without a live `serve`.
fn resolve_store_path(flag: Option<&str>, env: Option<&str>) -> Option<std::path::PathBuf> {
    flag.or(env).map(std::path::PathBuf::from)
}

/// Resolve the opt-in attestation trust-root path: `--attest-trust-root-file` flag wins over the
/// `VAULT_ATTEST_TRUST_ROOT_FILE` env fallback; neither set ⇒ `None` (transitional passthrough, no
/// verifier constructed). Mirrors `resolve_store_path` exactly (ADR-010, REQ-001). Pure, so the
/// precedence is unit-testable without a live `serve` (TC-001).
fn resolve_trust_root_path(flag: Option<&str>, env: Option<&str>) -> Option<std::path::PathBuf> {
    flag.or(env).map(std::path::PathBuf::from)
}

/// Decode a 32-byte Ed25519 trust-root **public** key from a hex (64 chars) or base64 string,
/// hex-first then base64, exactly the accept-rules `crypto::decode_key` uses for the master key
/// (ADR-010, REQ-001). Any other length or a non-hex/non-base64 string ⇒ `Err(String)` (never a
/// panic, never a default/zero key). Pure and unit-testable (TC-001).
fn parse_trust_root(s: &str) -> Result<[u8; 32], String> {
    let bytes = if let Some(b) = crypto::decode_hex(s) {
        b
    } else if let Some(b) = crypto::decode_base64(s) {
        b
    } else {
        return Err("trust root is not valid hex or base64".into());
    };
    if bytes.len() != 32 {
        return Err(format!("trust root must be 32 bytes, got {}", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Read + decode the trust-root file: read the file, trim surrounding whitespace/newlines (mirrors
/// `EnvKeyProvider`'s `raw.trim()`), then `parse_trust_root`. Any I/O or decode failure ⇒
/// `Err(String)` so `serve` refuses to start (ADR-010, REQ-001) rather than running with an
/// unusable or absent verifier. The public key is not secret; it is not zeroized.
fn load_trust_root(path: &std::path::Path) -> Result<[u8; 32], String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("unreadable: {e}"))?;
    parse_trust_root(raw.trim())
}

/// SEC-003 defense-in-depth: if the store file's PARENT directory is group- or world-writable, log
/// a non-fatal stderr WARNING. We do **not** refuse to start (that could surprise operators, and
/// FIX 1's O_EXCL/O_NOFOLLOW already closes the active temp-path vector) and we never log a secret —
/// only the directory path and its mode. A missing/unreadable directory is silently skipped (the
/// load step surfaces any real problem).
#[cfg(unix)]
fn warn_if_store_dir_writable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    if let Ok(meta) = std::fs::metadata(parent) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            eprintln!(
                "vault: WARNING — store directory {} is group/world-writable (mode {:o}); \
                 it SHOULD be owned by the vault uid and not group/world-writable (SEC-003)",
                parent.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_store_dir_writable(_path: &std::path::Path) {}

fn err(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message, "retryable": false } })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-spec coverage map (docs/tasks/test-specs/001-socket-peercred-check-test-spec.md):
    //   TC-001 (peer uid read on accept)      — exercised live by the same-uid `serve` round-trip
    //                                            (ping/put/resolve over a real socket); the read is
    //                                            `read_peer_uid` via SO_PEERCRED on every accept.
    //   TC-002 (different uid rejected)        — the deny half of `peer_uid_allowed` below; a genuine
    //                                            different-uid client needs a 2nd uid (root/sudo) and
    //                                            is proven at the unit level per the spec's Notes.
    //   TC-003 (same uid round-trips unchanged)— exercised live by the same-uid `serve` round-trip.
    //   TC-004 (unreadable cred -> deny)       — `unreadable_peer_cred_is_denied` (fail-closed).
    //   TC-005 (pure decision function)        — `peer_uid_allowed_is_equality_not_privilege`.

    // TC-005 / REQ-002, REQ-005: the pure decision function admits IFF the uids are equal.
    #[test]
    fn peer_uid_allowed_is_equality_not_privilege() {
        assert!(peer_uid_allowed(1000, 1000), "(1000,1000) must be allowed");
        assert!(!peer_uid_allowed(1000, 1001), "(1000,1001) must be denied");
        // root (uid 0) against a non-root server is denied — equality, not privilege.
        assert!(!peer_uid_allowed(0, 1000), "(0,1000) must be denied");
        assert!(
            peer_uid_allowed(0, 0),
            "(0,0) — root server, root peer — allowed by equality"
        );
    }

    // --- Task 003: get / list / rotate dispatch (TC-006, TC-007) ---

    // TC-006 / REQ-005: get/list/rotate round-trip through dispatch; unknown op → unknown_op.
    #[test]
    fn admin_verbs_dispatch_and_unknown_op() {
        // Ephemeral-key vault so the at-rest store has a working AES backend in the test process
        // (no operator master key configured under `cargo test`); assertions are unchanged.
        let v = Arc::new(Mutex::new(Vault::with_ephemeral_key()));
        // put → get → list → rotate, then an unknown op.
        let put = dispatch(
            &json!({
                "op":"put","secret_ref":"vault://test/api_key","value":"SK-OLD",
                "injection_floor":"proxy",
                "binding":{"host":"api.example.com","header":"Authorization","scheme":"Bearer","env_var":"API_KEY"}
            }),
            &v,
            &PassthroughVerifier,
        );
        assert_eq!(put["ok"], true);

        let got = dispatch(
            &json!({"op":"get","secret_ref":"vault://test/api_key"}),
            &v,
            &PassthroughVerifier,
        );
        assert_eq!(got["exists"], true);
        assert_eq!(got["injection_floor"], "proxy");
        assert!(
            got.to_string().find("SK-OLD").is_none(),
            "get leaks no value"
        );

        let listed = dispatch(&json!({"op":"list"}), &v, &PassthroughVerifier);
        assert_eq!(listed["secrets"].as_array().unwrap().len(), 1);
        assert!(
            listed.to_string().find("SK-OLD").is_none(),
            "list leaks no value"
        );

        let rotated = dispatch(
            &json!({"op":"rotate","secret_ref":"vault://test/api_key","value":"SK-NEW"}),
            &v,
            &PassthroughVerifier,
        );
        assert_eq!(rotated["ok"], true);
        assert!(
            rotated.to_string().find("SK-NEW").is_none(),
            "rotate echoes no value"
        );

        // Unknown op still → unknown_op.
        let unknown = dispatch(&json!({"op":"frobnicate"}), &v, &PassthroughVerifier);
        assert_eq!(unknown["error"]["code"], "unknown_op");

        // TC-007 edge: rotate-unknown-ref → no_such_secret.
        let bad = dispatch(
            &json!({"op":"rotate","secret_ref":"vault://nope/x","value":"y"}),
            &v,
            &PassthroughVerifier,
        );
        assert_eq!(bad["error"]["code"], "no_such_secret");
    }

    // TC-006 edge: a malformed JSON request line → structured `bad_request`, and a well-formed
    // line still routes normally — so the fail-closed ingress path is exercised and "connection
    // survives" (the helper returns a response Value rather than closing/panicking).
    #[test]
    fn malformed_json_line_is_bad_request() {
        let v = Arc::new(Mutex::new(Vault::new()));
        let bad = handle_line("not valid json{", &v, &PassthroughVerifier);
        assert_eq!(bad["error"]["code"], "bad_request");
        // A well-formed line still works through the same helper — connection survives.
        let ok = handle_line("{\"op\":\"ping\"}", &v, &PassthroughVerifier);
        assert_eq!(ok["ok"], true);
    }

    // TC-009 / REQ-008: store-path source precedence — the `--store-path` flag wins over the
    // `VAULT_STORE_PATH` env fallback; only-env uses the env; neither set ⇒ None (in-memory only).
    #[test]
    fn store_path_flag_wins_over_env() {
        use std::path::PathBuf;
        // Both set → flag wins.
        assert_eq!(
            resolve_store_path(Some("/flag/store.json"), Some("/env/store.json")),
            Some(PathBuf::from("/flag/store.json")),
            "flag must win when both --store-path and VAULT_STORE_PATH are set"
        );
        // Only env set → env used.
        assert_eq!(
            resolve_store_path(None, Some("/env/store.json")),
            Some(PathBuf::from("/env/store.json")),
            "env is the fallback when the flag is absent"
        );
        // Only flag set → flag used.
        assert_eq!(
            resolve_store_path(Some("/flag/store.json"), None),
            Some(PathBuf::from("/flag/store.json")),
            "flag alone resolves to the flag path"
        );
        // Neither set → None (in-memory only, opt-in default).
        assert_eq!(
            resolve_store_path(None, None),
            None,
            "neither set ⇒ None (in-memory only)"
        );
    }

    // TC-004 / REQ-004: at the gate, an unreadable peer credential is modeled as `None`, and the
    // gate's match treats `None` as a denial (fail-closed) — never "allow because we couldn't
    // tell". This proves the decision-boundary semantics without a live SO_PEERCRED socket.
    #[test]
    fn unreadable_peer_cred_is_denied() {
        let server_uid = 1000u32;
        // Mirror the exact admission pattern used in handle_conn against a None (read failure).
        let admit = |peer: Option<u32>| matches!(peer, Some(p) if peer_uid_allowed(p, server_uid));
        assert!(!admit(None), "unreadable credential (None) must be denied");
        assert!(
            admit(Some(1000)),
            "same-uid readable credential is admitted"
        );
        assert!(
            !admit(Some(1001)),
            "different-uid readable credential is denied"
        );
    }

    // ===================================================================================
    // Task 010: Ed25519 attestation verification at the inject dispatch edge (ADR-010).
    // TCs drive `dispatch(&req, &v, &verifier)` — the live path minus the socket — so a
    // verifier that exists but is not wired must fail (the dead-wire retro).
    // ===================================================================================

    use ed25519_compact::{KeyPair, Seed};

    /// The fixture keypair, derived deterministically from a fixed 32-byte seed — no `rand`, no OS
    /// entropy. The public half is the test's trust root.
    fn fixture_keypair(seed: u8) -> KeyPair {
        KeyPair::from_seed(Seed::new([seed; 32]))
    }

    /// Build the provisional wire-shape attestation for `sandbox_id`, signed by `kp`. The payload
    /// (base64 of canonical JSON `{"sandbox_id":"<id>"}`) is the ONE provisional constant, mirroring
    /// `attested_sandbox_id` — every TC builds requests through this helper so the shape lives in one
    /// place. The signature is over the RAW decoded payload bytes.
    fn fixture_attestation(sandbox_id: &str, kp: &KeyPair) -> Value {
        let payload = serde_json::to_vec(&json!({ "sandbox_id": sandbox_id })).unwrap();
        let sig = kp.sk.sign(&payload, None);
        json!({
            "alg": "ed25519",
            "payload": crypto::encode_base64(&payload),
            "signature": crypto::encode_base64(&*sig),
        })
    }

    /// A vault seeded with "SK-SECRET" under an ephemeral AES key (round-trips in-process).
    fn attest_vault() -> Arc<Mutex<Vault>> {
        let v = Arc::new(Mutex::new(Vault::with_ephemeral_key()));
        v.lock().unwrap().put(
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

    fn resolve_one(v: &Arc<Mutex<Vault>>) -> String {
        let r = v.lock().unwrap().resolve("vault://test/api_key", 300);
        r["handle"].as_str().unwrap().to_string()
    }

    /// Build an inject request; `attestation` = `None` omits the member (today's plain shape).
    fn inject_req(handle: &str, sandbox_id: &str, attestation: Option<Value>) -> Value {
        let mut sid = json!({ "sandbox_id": sandbox_id });
        if let Some(a) = attestation {
            sid["attestation"] = a;
        }
        json!({ "op": "inject", "handle": handle, "mode": "proxy", "sandbox_identity": sid })
    }

    // TC-001 / REQ-001: trust-root config — precedence, hex/base64 decode + trim, fail-closed.
    #[test]
    fn tc001_trust_root_config_precedence_decode_and_reject() {
        use std::path::PathBuf;
        // Precedence: flag > env > none (mirrors resolve_store_path exactly).
        assert_eq!(
            resolve_trust_root_path(Some("/flag.root"), Some("/env.root")),
            Some(PathBuf::from("/flag.root")),
            "flag wins when both set"
        );
        assert_eq!(
            resolve_trust_root_path(None, Some("/env.root")),
            Some(PathBuf::from("/env.root")),
            "env is the fallback"
        );
        assert_eq!(
            resolve_trust_root_path(Some("/flag.root"), None),
            Some(PathBuf::from("/flag.root"))
        );
        assert_eq!(
            resolve_trust_root_path(None, None),
            None,
            "neither set ⇒ None (transitional passthrough)"
        );

        // Decode: the same 32-byte key in hex and base64 yields byte-for-byte identical bytes.
        let raw: [u8; 32] = *fixture_keypair(7).pk;
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let b64 = crypto::encode_base64(&raw);
        let from_hex = parse_trust_root(&hex).expect("hex decodes");
        let from_b64 = parse_trust_root(&b64).expect("base64 decodes");
        assert_eq!(from_hex, raw, "hex form decodes to the exact 32 bytes");
        assert_eq!(
            from_hex, from_b64,
            "hex and base64 forms are byte-for-byte equal"
        );
        // Surrounding whitespace/newline in the key file is trimmed by load_trust_root (mirrors
        // EnvKeyProvider's raw.trim()) — asserted at the loader layer where the read happens.
        let tf = std::env::temp_dir().join(format!("vault-attest-root-{}.hex", std::process::id()));
        std::fs::write(&tf, format!("  {hex}\n")).unwrap();
        assert_eq!(
            load_trust_root(&tf).unwrap(),
            raw,
            "whitespace/newline trimmed on file read"
        );
        let _ = std::fs::remove_file(&tf);

        // Malformed ⇒ Err(String), never a panic, never a default/zero key.
        assert!(
            parse_trust_root(&"aa".repeat(31)).is_err(),
            "31 bytes rejected"
        );
        assert!(
            parse_trust_root(&"aa".repeat(33)).is_err(),
            "33 bytes rejected"
        );
        assert!(parse_trust_root("").is_err(), "empty rejected");
        assert!(
            parse_trust_root("not a key ###").is_err(),
            "non-hex/non-base64 rejected"
        );
        // A configured-but-unreadable file ⇒ Err so `serve` refuses to start (the live
        // refuse-to-start is the L6 observation).
        assert!(
            load_trust_root(std::path::Path::new("/nonexistent/vault-attest-root-xyz")).is_err(),
            "unreadable trust-root file is an Err (refuse to start)"
        );
    }

    // TC-002 / REQ-002, REQ-004: valid signed attestation → verified id, inject delivers the exact
    // contract response, handle binds to the ATTESTED id, replay is single-use.
    #[test]
    fn tc002_valid_attestation_delivers_and_binds_verified_id() {
        let kp = fixture_keypair(7);
        let verifier = Ed25519Verifier::new(*kp.pk);
        let v = attest_vault();
        let h = resolve_one(&v);

        let resp = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &kp))),
            &v,
            &verifier,
        );
        // Byte-for-byte the existing contract response; no attestation type leaks in.
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["delivery"], "proxy");
        assert_eq!(resp["credential"], "SK-SECRET");
        assert_eq!(resp["binding"]["host"], "api.example.com");
        assert!(
            resp.get("attestation").is_none(),
            "no attestation type leaks into the response"
        );

        // Single-use over the verified path: replay of the same handle → handle_consumed.
        let replay = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &kp))),
            &v,
            &verifier,
        );
        assert_eq!(replay["error"]["code"], "handle_consumed");

        // The verified id comes from the SIGNED payload, not trusted from the outer field.
        let sid =
            json!({ "sandbox_id": "sbx-1", "attestation": fixture_attestation("sbx-1", &kp) });
        assert!(
            matches!(verifier.verify(&sid), Ok(ref id) if id == "sbx-1"),
            "verify returns the signed-payload id"
        );
    }

    // TC-003 / REQ-003: tampered signature and tampered payload rejected fail-closed; a valid control
    // on the SAME handle succeeds afterward (proves rejection is attributable to the tamper AND that a
    // failed verify neither consumes nor binds the handle).
    #[test]
    fn tc003_tampered_sig_and_payload_rejected_handle_not_burned() {
        let kp = fixture_keypair(7);
        let verifier = Ed25519Verifier::new(*kp.pk);
        let v = attest_vault();
        let h = resolve_one(&v);

        // (b) tampered signature — flip one decoded byte, re-encode. Run FIRST.
        let mut att_b = fixture_attestation("sbx-1", &kp);
        let mut sig = crypto::decode_base64(att_b["signature"].as_str().unwrap()).unwrap();
        sig[0] ^= 0x01;
        att_b["signature"] = json!(crypto::encode_base64(&sig));
        let resp_b = dispatch(&inject_req(&h, "sbx-1", Some(att_b)), &v, &verifier);
        assert_eq!(resp_b["error"]["code"], "attestation_invalid");
        assert!(resp_b.get("ok").is_none(), "no ok on a rejection");
        assert!(
            resp_b.get("credential").is_none(),
            "no credential on a rejection"
        );
        assert!(resp_b.get("binding").is_none(), "no binding on a rejection");
        assert!(
            resp_b.to_string().find("SK-SECRET").is_none(),
            "the secret appears nowhere in the rejection"
        );
        assert_eq!(resp_b["error"]["retryable"], false);

        // (c) tampered payload — flip a byte inside the decoded payload, keep the original signature.
        let mut att_c = fixture_attestation("sbx-1", &kp);
        let mut payload = crypto::decode_base64(att_c["payload"].as_str().unwrap()).unwrap();
        let last = payload.len() - 2;
        payload[last] ^= 0x01;
        att_c["payload"] = json!(crypto::encode_base64(&payload));
        let resp_c = dispatch(&inject_req(&h, "sbx-1", Some(att_c)), &v, &verifier);
        assert_eq!(resp_c["error"]["code"], "attestation_invalid");

        // (a) valid control on the SAME handle → succeeds, so the rejections did not burn it.
        let resp_a = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &kp))),
            &v,
            &verifier,
        );
        assert_eq!(resp_a["credential"], "SK-SECRET");
    }

    // TC-004 / REQ-003: attestation signed by the WRONG key is rejected; correct-key control on the
    // same handle succeeds; and a correct-key attestation verified against the WRONG configured root
    // also fails (verification is against the configured root, not any key material in the request).
    #[test]
    fn tc004_wrong_key_rejected_correct_key_control() {
        let good = fixture_keypair(7);
        let wrong = fixture_keypair(8);
        let verifier = Ed25519Verifier::new(*good.pk); // trust root = good
        let v = attest_vault();
        let h = resolve_one(&v);

        // Structurally perfect attestation for sbx-1 signed by the WRONG key → invalid.
        let resp = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &wrong))),
            &v,
            &verifier,
        );
        assert_eq!(resp["error"]["code"], "attestation_invalid");
        assert!(resp.to_string().find("SK-SECRET").is_none());

        // Control: identical request signed by the CORRECT key succeeds on the same handle.
        let ok = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &good))),
            &v,
            &verifier,
        );
        assert_eq!(ok["credential"], "SK-SECRET");

        // Edge: correct-key attestation but verifier configured with the WRONG root → fails.
        let wrong_root = Ed25519Verifier::new(*wrong.pk);
        let v2 = attest_vault();
        let h2 = resolve_one(&v2);
        let resp2 = dispatch(
            &inject_req(&h2, "sbx-1", Some(fixture_attestation("sbx-1", &good))),
            &v2,
            &wrong_root,
        );
        assert_eq!(resp2["error"]["code"], "attestation_invalid");
    }

    // TC-005 / REQ-003: missing / malformed attestation and sandbox_id mismatch rejected; the valid
    // control after all rejections proves the handle was never consumed or bound.
    #[test]
    fn tc005_missing_malformed_mismatch_rejected() {
        let kp = fixture_keypair(7);
        let verifier = Ed25519Verifier::new(*kp.pk);
        let v = attest_vault();
        let h = resolve_one(&v);

        // (a) today's plain request — no attestation member → attestation_missing.
        let miss = dispatch(&inject_req(&h, "sbx-1", None), &v, &verifier);
        assert_eq!(miss["error"]["code"], "attestation_missing");

        // sandbox_identity missing entirely → attestation_missing (never a bind to "").
        let no_sid = dispatch(
            &json!({ "op": "inject", "handle": h, "mode": "proxy" }),
            &v,
            &verifier,
        );
        assert_eq!(no_sid["error"]["code"], "attestation_missing");

        // (b) signature not valid base64.
        let mut b = fixture_attestation("sbx-1", &kp);
        b["signature"] = json!("!!!not base64!!!");
        assert_eq!(
            dispatch(&inject_req(&h, "sbx-1", Some(b)), &v, &verifier)["error"]["code"],
            "attestation_invalid"
        );

        // (c) decoded signature is 63 bytes.
        let mut c = fixture_attestation("sbx-1", &kp);
        c["signature"] = json!(crypto::encode_base64(&[0u8; 63]));
        assert_eq!(
            dispatch(&inject_req(&h, "sbx-1", Some(c)), &v, &verifier)["error"]["code"],
            "attestation_invalid"
        );

        // (d) payload is valid base64 of NON-JSON bytes — signed with the correct key so the
        // signature verifies and the failure is genuinely the non-JSON payload path.
        let nonjson = b"not json at all".to_vec();
        let sig_d = kp.sk.sign(&nonjson, None);
        let d = json!({
            "alg": "ed25519",
            "payload": crypto::encode_base64(&nonjson),
            "signature": crypto::encode_base64(&*sig_d),
        });
        assert_eq!(
            dispatch(&inject_req(&h, "sbx-1", Some(d)), &v, &verifier)["error"]["code"],
            "attestation_invalid"
        );

        // (e) valid signature over {"sandbox_id":"sbx-EVIL"} presented with outer sbx-1 → invalid.
        let evil = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-EVIL", &kp))),
            &v,
            &verifier,
        );
        assert_eq!(evil["error"]["code"], "attestation_invalid");

        // alg other than "ed25519" → invalid.
        let mut wrong_alg = fixture_attestation("sbx-1", &kp);
        wrong_alg["alg"] = json!("rsa");
        assert_eq!(
            dispatch(&inject_req(&h, "sbx-1", Some(wrong_alg)), &v, &verifier)["error"]["code"],
            "attestation_invalid"
        );

        // empty sandbox_id, valid signature over {"sandbox_id":""} → fail-closed (never bind to "").
        let empty = dispatch(
            &inject_req(&h, "", Some(fixture_attestation("", &kp))),
            &v,
            &verifier,
        );
        assert_eq!(empty["error"]["code"], "attestation_invalid");

        // Control: after every rejection, a valid inject on the SAME handle delivers — nothing
        // above consumed or bound it.
        let ok = dispatch(
            &inject_req(&h, "sbx-1", Some(fixture_attestation("sbx-1", &kp))),
            &v,
            &verifier,
        );
        assert_eq!(ok["credential"], "SK-SECRET");
    }

    // TC-006 / REQ-004, REQ-005 boundary: no trust root ⇒ passthrough is byte-for-byte today's
    // behavior; an attestation member, if present, is ignored; single-use precedence unchanged.
    #[test]
    fn tc006_passthrough_no_trust_root_is_todays_behavior() {
        let v = attest_vault();
        let h1 = resolve_one(&v);

        // Today's exact request shape, no attestation → delivers (opaque first-use binding).
        let resp = dispatch(&inject_req(&h1, "sbx-1", None), &v, &PassthroughVerifier);
        assert_eq!(resp["credential"], "SK-SECRET");
        assert_eq!(resp["delivery"], "proxy");

        // The same request WITH a garbage attestation → still delivers (ignored, not validated).
        let h2 = resolve_one(&v);
        let garbage = json!({ "alg": "nonsense", "payload": "@@@", "signature": "@@@" });
        let resp2 = dispatch(
            &inject_req(&h2, "sbx-1", Some(garbage)),
            &v,
            &PassthroughVerifier,
        );
        assert_eq!(resp2["credential"], "SK-SECRET");

        // Replay → handle_consumed (single-use not regressed in passthrough mode).
        let replay = dispatch(&inject_req(&h1, "sbx-1", None), &v, &PassthroughVerifier);
        assert_eq!(replay["error"]["code"], "handle_consumed");
    }

    // TC-007 / REQ-005: the transitional opt-in + provisional payload shape are documented, not
    // silent — asserted against the actual spec + ADR files (run from the crate root).
    #[test]
    fn tc007_transitional_opt_in_is_documented() {
        let config = std::fs::read_to_string("docs/spec/configuration.md").unwrap();
        assert!(
            config.contains("--attest-trust-root-file")
                && config.contains("VAULT_ATTEST_TRUST_ROOT_FILE"),
            "configuration.md documents the flag + env"
        );
        assert!(
            config.to_lowercase().contains("transitional"),
            "configuration.md marks the no-trust-root mode transitional"
        );
        let interfaces = std::fs::read_to_string("docs/spec/interfaces.md").unwrap();
        assert!(
            interfaces.contains("attestation_missing")
                && interfaces.contains("attestation_invalid"),
            "interfaces.md documents the two new error codes"
        );
        let adr = std::fs::read_to_string(
            "docs/architecture/decisions/010-verify-sandbox-attestation-binding.md",
        )
        .unwrap();
        assert!(
            adr.contains("attested_sandbox_id") && adr.to_lowercase().contains("transitional"),
            "ADR-010 records the single-function seam + the transitional decision"
        );
    }

    // TC-008 / REQ-006: dependency gate — zeroize + literal rand absent, no getrandom 0.4, the chosen
    // ed25519-compact crate present. Greps the actual Cargo.lock (run from the crate root).
    #[test]
    fn tc008_dependency_gate_zeroize_absent_ed25519_compact_pinned() {
        let lock = std::fs::read_to_string("Cargo.lock").unwrap();
        assert!(
            !lock.contains("name = \"zeroize\""),
            "zeroize must be ABSENT from Cargo.lock (dep-scan BLOCKED, ADR-009; dalek would pull it)"
        );
        assert!(
            !lock.contains("name = \"rand\"\n"),
            "the literal `rand` crate must be absent"
        );
        assert!(
            !lock.contains("name = \"getrandom\"\nversion = \"0.4"),
            "no getrandom 0.4 — ed25519-compact's random/getrandom default features are off"
        );
        assert!(
            lock.contains("name = \"ed25519-compact\""),
            "the chosen Ed25519 verify crate is pinned in the lock"
        );
    }

    // Fixture emitter (ignored): prints the fixture trust root (hex) and a ready-to-send valid
    // attestation object for sandbox_id "sbx-1", for the L6 live-socket observation. Run with:
    //   cargo test print_fixture_inject -- --ignored --nocapture
    #[test]
    #[ignore]
    fn print_fixture_inject() {
        let kp = fixture_keypair(7);
        let root_hex: String = kp.pk.iter().map(|b| format!("{b:02x}")).collect();
        let att = fixture_attestation("sbx-1", &kp);
        println!("ATTEST_ROOT_HEX={root_hex}");
        println!("ATTEST_SBX1={att}");
    }
}
