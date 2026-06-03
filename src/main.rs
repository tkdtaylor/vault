//! vault — JIT zero-knowledge secret store + credential broker.
//!
//! The agent core only ever holds an opaque handle; the plaintext is delivered to
//! exec-sandbox's egress proxy (proxy mode) or env-setter (env mode) at inject time, then
//! wiped. See README.md.
//!
//! Usage:
//!   vault serve --socket /run/vault.sock          # IPC daemon (resolve/inject/put/ping)
//!   vault demo                                     # run put->resolve->inject in-process

mod handle;
mod vault;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

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
    // handoff travels this socket). NOTE v1 hardening: add an SO_PEERCRED peer-uid check
    // (needs the `nix` crate) to match the tracer's full D5 scheme.
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).ok();
    eprintln!("vault serving on {socket}");

    let v = Arc::new(Mutex::new(Vault::new()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let v = Arc::clone(&v);
        std::thread::spawn(move || handle_conn(stream, v));
    }
}

fn handle_conn(mut stream: UnixStream, v: Arc<Mutex<Vault>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let resp = match serde_json::from_str::<Value>(&line) {
        Ok(req) => dispatch(&req, &v),
        Err(e) => err("bad_request", &e.to_string()),
    };
    let _ = writeln!(stream, "{resp}");
}

fn dispatch(req: &Value, v: &Arc<Mutex<Vault>>) -> Value {
    match req["op"].as_str() {
        Some("ping") => json!({ "ok": true }),
        Some("put") => {
            let binding: Binding = serde_json::from_value(req["binding"].clone())
                .unwrap_or_else(|_| Binding {
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
    let mut v = Vault::new();
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
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn err(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message, "retryable": false } })
}
