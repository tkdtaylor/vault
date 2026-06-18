//! vault — JIT zero-knowledge secret store + credential broker.
//!
//! The agent core only ever holds an opaque handle; the plaintext is delivered to
//! exec-sandbox's egress proxy (proxy mode) or env-setter (env mode) at inject time, then
//! wiped. See README.md.
//!
//! Usage:
//!   vault serve --socket /run/vault.sock                                  # IPC daemon (resolve/inject/put/ping)
//!   vault serve --socket /run/vault.sock --http-addr 127.0.0.1:8200       # + opt-in loopback HTTP read surface
//!   vault demo                                                            # run put->resolve->inject in-process

mod crypto;
mod handle;
mod http;
mod vault;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use serde_json::{json, Value};

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

    let v = Arc::new(Mutex::new(Vault::new()));

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
        std::thread::spawn(move || handle_conn(stream, v));
    }
}

fn handle_conn(mut stream: UnixStream, v: Arc<Mutex<Vault>>) {
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
    let resp = handle_line(&line, &v);
    let _ = writeln!(stream, "{resp}");
}

/// Parse one newline-delimited JSON request line and route it to `dispatch`.
///
/// Fail-closed ingress (TC-006): a line that is not well-formed JSON yields a structured
/// `bad_request` error rather than a panic or a dropped connection — `handle_conn` writes the
/// response back and the connection survives. Behaviour is identical to the inlined match it
/// replaced; this is a pure extraction so the parse→dispatch step is unit-testable without a
/// live socket. The SO_PEERCRED peer-uid gate stays upstream in `handle_conn`, unchanged.
fn handle_line(line: &str, v: &Arc<Mutex<Vault>>) -> Value {
    match serde_json::from_str::<Value>(line) {
        Ok(req) => dispatch(&req, v),
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

fn dispatch(req: &Value, v: &Arc<Mutex<Vault>>) -> Value {
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
            v.lock().unwrap().put(
                req["secret_ref"].as_str().unwrap_or(""),
                req["value"].as_str().unwrap_or(""),
                floor,
                binding,
            );
            json!({ "ok": true })
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
            let sandbox_id = req["sandbox_identity"]["sandbox_id"].as_str().unwrap_or("");
            let mode = parse_mode(&req["mode"]);
            v.lock()
                .unwrap()
                .inject(req["handle"].as_str().unwrap_or(""), sandbox_id, mode)
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
        );
        assert_eq!(put["ok"], true);

        let got = dispatch(&json!({"op":"get","secret_ref":"vault://test/api_key"}), &v);
        assert_eq!(got["exists"], true);
        assert_eq!(got["injection_floor"], "proxy");
        assert!(
            got.to_string().find("SK-OLD").is_none(),
            "get leaks no value"
        );

        let listed = dispatch(&json!({"op":"list"}), &v);
        assert_eq!(listed["secrets"].as_array().unwrap().len(), 1);
        assert!(
            listed.to_string().find("SK-OLD").is_none(),
            "list leaks no value"
        );

        let rotated = dispatch(
            &json!({"op":"rotate","secret_ref":"vault://test/api_key","value":"SK-NEW"}),
            &v,
        );
        assert_eq!(rotated["ok"], true);
        assert!(
            rotated.to_string().find("SK-NEW").is_none(),
            "rotate echoes no value"
        );

        // Unknown op still → unknown_op.
        let unknown = dispatch(&json!({"op":"frobnicate"}), &v);
        assert_eq!(unknown["error"]["code"], "unknown_op");

        // TC-007 edge: rotate-unknown-ref → no_such_secret.
        let bad = dispatch(
            &json!({"op":"rotate","secret_ref":"vault://nope/x","value":"y"}),
            &v,
        );
        assert_eq!(bad["error"]["code"], "no_such_secret");
    }

    // TC-006 edge: a malformed JSON request line → structured `bad_request`, and a well-formed
    // line still routes normally — so the fail-closed ingress path is exercised and "connection
    // survives" (the helper returns a response Value rather than closing/panicking).
    #[test]
    fn malformed_json_line_is_bad_request() {
        let v = Arc::new(Mutex::new(Vault::new()));
        let bad = handle_line("not valid json{", &v);
        assert_eq!(bad["error"]["code"], "bad_request");
        // A well-formed line still works through the same helper — connection survives.
        let ok = handle_line("{\"op\":\"ping\"}", &v);
        assert_eq!(ok["ok"], true);
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
}
