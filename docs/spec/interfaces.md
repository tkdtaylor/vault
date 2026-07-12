# Interfaces

**Project:** vault
**Last updated:** 2026-06-18

The system's contact surface — what calls in, what it calls out to, and the internal public
boundary. Each is a stable contract; changes here are breaking changes.

Not here: what they *do* ([behaviors.md](behaviors.md)), what data flows
([data-model.md](data-model.md)), how they're configured ([configuration.md](configuration.md)).

---

## Inbound interfaces

### CLI

```
vault <serve|demo> [flags]

Subcommands:
  serve     run the newline-delimited-JSON-over-Unix-socket IPC daemon
            (+ an opt-in loopback-only read-only HTTP read surface, ADR-006)
  demo      run put -> resolve -> inject -> replay-rejected in-process and print each step
```

| Subcommand / flag | Type | Default | Effect |
|-------------------|------|---------|--------|
| `serve` | subcommand | — | Start the IPC daemon (long-running) |
| `serve --socket` | string (path) | — (required) | Unix socket path to bind; a stale socket is removed first; bound `0600`. Missing → usage error |
| `serve --http-addr` | string (`HOST:PORT`) | — (absent → no HTTP listener) | **Opt-in** loopback HTTP read surface (ADR-006). Present → bind a thread-per-connection HTTP listener sharing the same `Vault` as the Unix socket — but **only if** the host is the literal `127.0.0.1`; a non-loopback host (`0.0.0.0`, a LAN IP, `::`) is **refused fail-closed** (logged, no bind). Absent → the Unix socket serves exactly as before |
| `serve --attest-trust-root-file` | string (path) | — (absent → transitional passthrough) | **Opt-in** Ed25519 attestation verification at the inject edge (ADR-010). Present → load a 32-byte Ed25519 public key (hex/base64, trimmed) and verify every `inject`'s signed `sandbox_identity.attestation`, binding to the **verified** id and failing closed; an unusable file refuses to start. Falls back to `VAULT_ATTEST_TRUST_ROOT_FILE` (**flag wins**). Absent → opaque caller-asserted binding, byte-for-byte today's behavior (transitional) |
| `serve --identity-binding` | `sandbox` \| `spiffe` | `sandbox` | **Opt-in** identity-binding mode (ADR-011). `spiffe` → the handle's first-use binding key is the verified `sandbox_identity.principal.spiffe_id`; `sandbox` (default) → the opaque `sandbox_id`, byte-for-byte today's behavior. Falls back to `VAULT_IDENTITY_BINDING` (**flag wins**); any other value refuses to start. **Contract note:** `handle_bound_to_other_sandbox` keeps its name in spiffe mode, where "sandbox" reads as "workload identity" |
| `serve --secret-backend` | `mock` \| `alt-mock` | — (absent → AES/persistent store) | **Opt-in** cloud secret-manager store backend core (ADR-007). Selects a `SecretManagerClient` behind the `StoreBackend` seam via the `secret_manager::make_client` drop-in registry; the value re-materialises via the client at `inject`, fail-closed `backend_unavailable` on a remote error. L2 core ships the **mock** adapters only; real per-cloud adapters are task 012. Unknown name refuses to start; supersedes `--store-path` |
| `demo` | subcommand | — | One-shot in-process demonstration; stdout only |

**Exit codes:**
- `0` — normal exit
- `2` — usage error (missing/unknown subcommand, or `serve` without `--socket`)
- non-zero (panic) — a socket bind failure (`expect("bind unix socket")`)

### IPC protocol (Unix socket)

The agent + exec-sandbox surface. Newline-delimited JSON over the Unix socket bound by
`serve --socket`. One request object per connection (read up to the first `\n`); the connection
closes after the response.

| Op | Request | Response |
|----|---------|----------|
| `ping` | `{"op":"ping"}` | `{"ok":true}` |
| `put` | `{"op":"put","secret_ref":…,"value":…,"injection_floor":"env\|proxy","binding":{…}}` | `{"ok":true}` |
| `get` | `{"op":"get","secret_ref":…}` | `{"exists":true,"injection_floor":"env\|proxy","binding":{…}}` — **metadata only, never the value**; unknown ref → `{"error":{"code":"no_such_secret",…}}` |
| `list` | `{"op":"list"}` | `{"secrets":[{"secret_ref":…,"injection_floor":…},…]}` — **never any value**; empty store → `{"secrets":[]}` |
| `rotate` | `{"op":"rotate","secret_ref":…,"value":…}` | `{"ok":true,"rotated":true,"injection_floor":…,"binding":{…}}` — **value never echoed**; preserves floor+binding; unknown ref → `no_such_secret`. Invalidates outstanding handles for that ref (ADR-004) |
| `resolve` | `{"op":"resolve","secret_ref":…,"ttl":<sec>}` | `{"handle":…,"ttl":…,"injection_mode":…}` — **never the value** |
| `inject` | `{"op":"inject","handle":…,"sandbox_identity":{"sandbox_id":…,"attestation":{"alg":"ed25519","payload":…,"signature":…}?,"principal":{"spiffe_id":…,"trust_tier":…}?},"mode":"env\|proxy"}` | proxy: `{"ok":true,"delivery":"proxy","credential":…,"binding":{…}}` · env: `{"ok":true,"delivery":"env","credential":…,"var_name":…,"wiped_at":<unix_secs>}` · expired: `{"error":{"code":"handle_expired",...}}` · rotated: `{"error":{"code":"handle_invalidated",...}}` (secret rotated after resolve — ADR-004) · tampered ciphertext: `{"error":{"code":"decrypt_failed",...}}` (AES-256-GCM tag check — ADR-005) · remote fetch failure (only under `--secret-backend`, ADR-007): `{"error":{"code":"backend_unavailable",...}}` (denied/unavailable/not-found remote get; fetched **before** the handle is consumed, so a transient failure does not burn it) · attestation (only when a trust root is configured, ADR-010): missing member → `{"error":{"code":"attestation_missing",...}}`, bad/tampered/wrong-key/id-mismatch → `{"error":{"code":"attestation_invalid",...}}` — verified **before** any handle mutation, so a rejected attestation never consumes or binds the handle · principal (only in **spiffe** mode, ADR-011): missing member → `{"error":{"code":"principal_missing",...}}`, malformed `spiffe_id` / empty `trust_tier` → `{"error":{"code":"principal_invalid",...}}` |
| *(peer-uid denied)* | any request from a peer whose uid ≠ the server's | `{"error":{"code":"peer_uid_denied",...}}` — no op dispatched |
| *(other / malformed)* | any unparseable / unknown op | `{"error":{"code","message","retryable":false}}` (`bad_request` / `unknown_op`) |

- Socket permissions are `0600` (owner-only). On every accepted connection vault additionally reads
  the peer credential via **`SO_PEERCRED`** and admits it **only if** the peer uid equals the
  server's own effective uid (`geteuid`) — kernel-verified, equality not privilege. A mismatched or
  unreadable peer credential is rejected fail-closed with `peer_uid_denied` and **no op runs**. The
  `0600` mode and the peer-uid assertion are the two halves of the D5 uid restriction (ADR-002).
- Error codes and the structured error shape are in [data-model.md](data-model.md).

### HTTP read surface (TCP) — opt-in, loopback-only, read-only, zero-knowledge

A **second** inbound listener, started **only** when `serve --http-addr 127.0.0.1:PORT` is passed
(ADR-006). It speaks the HashiCorp Vault / OpenBao **KV-v2 API shape** so existing Vault tooling can
interoperate through the seam — but it is **zero-knowledge**: a read returns the **handle** in a
Vault-shaped envelope, **never the value**. It is **read-only** — `inject`/`put`/`rotate`/`get`/`list`
are **not routed** here (no method+path reaches them). Its trust model is deliberately **different**
from the Unix socket: the Unix socket is `SO_PEERCRED`-gated with the full verb set; the HTTP surface
is **unauthenticated** (vault has no token model yet) and so is loopback-only + read-only.

| Method + path | Maps to | Response |
|---------------|---------|----------|
| `GET /v1/sys/health` | (no store access) | `200 {"initialized":true,"sealed":false}` — liveness only |
| `GET /v1/secret/data/:path` | `Vault::resolve("vault://:path", 300)` | `200 {"data":{"data":{"handle":…,"injection_mode":…},"metadata":{"ttl":…}}}` — KV-v2 envelope carrying the **handle**, **never the value** |

The path tail after `/v1/secret/data/` becomes the `vault://`-scheme `secret_ref` verbatim, nested
segments preserved (`/v1/secret/data/team/prod/db` → `vault://team/prod/db`). The read mints a
single-use handle with a fixed TTL of `300`s (the HTTP surface has no per-request TTL knob).

**Error → HTTP status mapping** (Vault's shapes, so existing clients see familiar responses):

| Condition | Status | Body |
|-----------|--------|------|
| unknown secret (`no_such_secret`) | `404` | `{"errors":[]}` |
| unroutable path / empty `secret/data` tail | `404` | `{"errors":[]}` |
| non-GET method (POST/PUT/DELETE/…) | `405` | `{"errors":["method not allowed"]}` |
| malformed / over-long request (body > 8 KiB) | `400` | `{"errors":["bad request"]}` |
| handle-mint failure (`rng_error`) | `500` | `{"errors":["internal error"]}` |

- **No value crosses the TCP boundary** — `resolve` is value-free by construction, so the envelope
  carries only the opaque handle. The plaintext continues to re-materialise **only** at `inject` over
  the `SO_PEERCRED`-gated Unix socket. There is no HTTP path, success or error, on which a cleartext
  value leaves the process.
- **Loopback-only, fail-closed bind** — the listener binds `127.0.0.1` only; a non-loopback
  `--http-addr` is refused (logged, no bind), never a wildcard. Remote/`0.0.0.0` exposure waits on
  the auth model (roadmap row 6).
- The pure decision functions are `http_route(method, path)`, `http_secret_ref(path)`,
  `kv2_envelope(resolved)`, `loopback_only(addr)`, and `http_response_for(route, vault)` in
  `src/http.rs` (the same precedent as `peer_uid_allowed` / `handle_line`).

### Contract verbs — all four admin verbs wired

The v1 contract (`docs/CONTRACT.md`, the ecosystem's v1 interface contract) defines the admin verbs
`put | get | list | rotate`. **All four are dispatched** in `src/main.rs::dispatch` and exposed on
the in-process `Vault` API. `get`/`list`/`rotate` return **metadata only, never the value**;
`rotate` additionally invalidates outstanding handles for the rotated ref (ADR-004). The remaining
admin surface (e.g. delete) is not part of the v1 contract.

---

## Outbound interfaces

vault makes **no outbound network calls** in v0. Its only outbound action is the credential
**delivery on `inject`**, which crosses the uid-restricted socket back to the caller
(exec-sandbox), which routes it to the injection edge:

| Target (via inject response) | Mode | Contract | Notes |
|------------------------------|------|----------|-------|
| exec-sandbox egress proxy | `proxy` | receives `{credential, binding{host,header,scheme,env_var}}` | the value never enters the sandbox itself |
| exec-sandbox env-setter | `env` | receives `{credential, var_name, wiped_at}` | the value is set as `var_name` inside the sandbox; `wiped_at` is the inject-time clock (Unix secs) |

vault does not call exec-sandbox proactively — `inject` is **pull-triggered**: exec-sandbox
presents `{handle, sandbox_identity}` at spawn, and vault responds.

---

## Internal public surface

### Type: `Vault` — the broker core (the backend seam)

```rust
impl Vault {
    pub fn new() -> Self                                                            // SystemClock + AES-256-GCM backend keyed from env (EnvKeyProvider); no key → fail-closed store
    pub fn with_clock(clock: Box<dyn Clock>) -> Self                                // inject a clock; env-keyed backend
    pub fn with_ephemeral_key() -> Self                                             // SystemClock + AES-256-GCM with a fresh random in-process key (the `demo` subcommand)
    pub fn with_clock_and_backend(clock: Box<dyn Clock>, backend: Box<dyn StoreBackend>) -> Self  // inject clock + store backend (the seam tests use a fixed-key / non-AES backend)
    pub fn put(&mut self, secret_ref: &str, value: &str, floor: Mode, binding: Binding)  // ENCRYPTS the value (fresh nonce); cleartext not retained; encrypt failure → nothing stored (fail-closed)
    pub fn get(&self, secret_ref: &str) -> serde_json::Value                        // { exists, injection_floor, binding } — NOT the value; never decrypts; unknown ref → no_such_secret
    pub fn list(&self) -> serde_json::Value                                         // { secrets:[{secret_ref, injection_floor},…] } — NOT any value; never decrypts; empty store → []
    pub fn rotate(&mut self, secret_ref: &str, value: &str) -> serde_json::Value    // RE-ENCRYPTS (fresh nonce) in place, preserves floor+binding, no value echoed; bumps generation; encrypt failure → encrypt_failed
    pub fn resolve(&mut self, secret_ref: &str, ttl: u64) -> serde_json::Value     // { handle, ttl, injection_mode } — NOT the value; records expires_at = now + ttl
    pub fn inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>) -> serde_json::Value  // handle_consumed → handle_expired → handle_invalidated → binding → DECRYPT (decrypt_failed on bad tag) → deliver
}

// Injectable clock seam — SystemClock in production, a test clock for deterministic expiry.
pub trait Clock: Send + Sync { fn now_unix(&self) -> u64; }
pub struct SystemClock;   // wall time via std::time::SystemTime

// At-rest crypto seams (src/crypto.rs) — see data-model.md for the type shapes.
pub trait KeyProvider: Send + Sync { fn key(&self) -> Result<[u8; 32], String>; }   // master key, off the ciphertext
pub struct EnvKeyProvider;  // VAULT_MASTER_KEY / VAULT_MASTER_KEY_FILE (hex/base64 → 32 bytes); missing → error (fail-closed)
pub trait StoreBackend: Send + Sync {                                               // the store-encryption seam (no AEAD type leaks to callers)
    fn encrypt(&self, plaintext: &str) -> Result<EncryptedValue, String>;
    fn decrypt(&self, value: &EncryptedValue) -> Result<String, String>;           // fails closed on a bad tag
}
pub struct AesGcmBackend;   // production AES-256-GCM backend, key from a KeyProvider
```

- **The seam is the `Vault` core** (`src/vault.rs`) plus the `StoreBackend` store-encryption seam
  (`src/crypto.rs`). The store holds AES-256-GCM ciphertext; the cleartext re-materialises only at
  `inject`. A future backend (OpenBao, HashiCorp Vault, cloud KMS, PKCS#11 HSM) replaces the
  `StoreBackend` internals **behind these method signatures and the `vault://` scheme** — callers
  (`main.rs`'s IPC dispatch, `demo`) do not change.
- **`resolve` never returns the value** — it returns `{handle, ttl, injection_mode}` or a
  `no_such_secret` / `rng_error` error.
- **`inject` is fail-closed** — an unknown / consumed / wrong-sandbox handle returns a structured
  error; a valid one delivers at `max(secret_floor, requested)` (raise-only) and consumes + binds
  the handle.
- **Stability:** the argument and return shapes are the contract. Changing them is an ADR-level
  decision. No store-backend-specific type appears in the signatures — the boundary stays
  `vault://`-shaped JSON.

### Free functions

```rust
pub fn parse_mode(v: &serde_json::Value) -> Option<Mode>     // src/vault.rs — JSON string -> Mode
pub fn new_handle() -> std::io::Result<String>               // src/handle.rs — 32 bytes /dev/urandom, hex
```

---

## Extension points

The single extension point is the **`Vault` store backend behind the `vault://<scope>/<key>`
scheme + Vault HTTP API path semantics**. A new backend is adopted by replacing the store internals
of the `Vault` core while preserving the `put`/`resolve`/`inject` signatures — never by changing
callers or the wire contract. There is no plugin registry in v0; extension is by source
modification behind the seam.

**Remote-store drop-in (ADR-007).** The `SecretManagerBackend` (a `StoreBackend`) delegates to the
**`SecretManagerClient` trait** (`get_value` / `put_value` / `rotate_value`) — the documented
pluggability seam. Adopting a different secret store means **one new `SecretManagerClient` impl plus
one `secret_manager::make_client` selection arm** (surfaced as `--secret-backend <name>`); nothing in
`SecretManagerBackend`, `Vault`, the contract, or any caller changes. The L2 core ships the `mock` /
`alt-mock` adapters as the ≥2-adapter proof; the real AWS/GCP/Azure adapters (their SDK/REST trees,
feature-gated + dep-scan-gated) are task 012.
