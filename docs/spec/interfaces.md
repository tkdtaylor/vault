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
  demo      run put -> resolve -> inject -> replay-rejected in-process and print each step
```

| Subcommand / flag | Type | Default | Effect |
|-------------------|------|---------|--------|
| `serve` | subcommand | — | Start the IPC daemon (long-running) |
| `serve --socket` | string (path) | — (required) | Unix socket path to bind; a stale socket is removed first; bound `0600`. Missing → usage error |
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
| `resolve` | `{"op":"resolve","secret_ref":…,"ttl":<sec>}` | `{"handle":…,"ttl":…,"injection_mode":…}` — **never the value** |
| `inject` | `{"op":"inject","handle":…,"sandbox_identity":{"sandbox_id":…},"mode":"env\|proxy"}` | proxy: `{"ok":true,"delivery":"proxy","credential":…,"binding":{…}}` · env: `{"ok":true,"delivery":"env","credential":…,"var_name":…,"wiped_at":0}` |
| *(other / malformed)* | any unparseable / unknown op | `{"error":{"code","message","retryable":false}}` (`bad_request` / `unknown_op`) |

- Socket permissions are `0600` (owner-only) — the uid-restriction half of the D5 handoff.
- Error codes and the structured error shape are in [data-model.md](data-model.md).

> TODO: a **SO_PEERCRED peer-uid check** on accepted connections is part of the full D5 scheme but
> is **not yet** implemented (`src/main.rs::serve` sets `0600` only; needs the `nix` crate).

### Contract verbs not yet wired

The v1 contract (`docs/CONTRACT.md`, the ecosystem's v1 interface contract) defines the admin
verbs `get | list | rotate` alongside `put`. **As of 2026-06-18 only `put` is dispatched** in
`src/main.rs::dispatch`:

> TODO: `get` / `list` / `rotate` are v1 contract verbs **not yet implemented** in the IPC
> dispatch. When wired, they must return **metadata only, never the value** (per the contract).

---

## Outbound interfaces

vault makes **no outbound network calls** in v0. Its only outbound action is the credential
**delivery on `inject`**, which crosses the uid-restricted socket back to the caller
(exec-sandbox), which routes it to the injection edge:

| Target (via inject response) | Mode | Contract | Notes |
|------------------------------|------|----------|-------|
| exec-sandbox egress proxy | `proxy` | receives `{credential, binding{host,header,scheme,env_var}}` | the value never enters the sandbox itself |
| exec-sandbox env-setter | `env` | receives `{credential, var_name, wiped_at}` | the value is set as `var_name` inside the sandbox |

vault does not call exec-sandbox proactively — `inject` is **pull-triggered**: exec-sandbox
presents `{handle, sandbox_identity}` at spawn, and vault responds.

---

## Internal public surface

### Type: `Vault` — the broker core (the backend seam)

```rust
impl Vault {
    pub fn new() -> Self
    pub fn put(&mut self, secret_ref: &str, value: &str, floor: Mode, binding: Binding)
    pub fn resolve(&mut self, secret_ref: &str, ttl: u64) -> serde_json::Value     // { handle, ttl, injection_mode } — NOT the value
    pub fn inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>) -> serde_json::Value
}
```

- **The seam is the `Vault` core** (`src/vault.rs`). The v0 implementation holds an in-memory store
  and handle table. A future backend (encrypted local store, OpenBao, HashiCorp Vault, cloud KMS,
  PKCS#11 HSM) replaces the store internals **behind these method signatures and the `vault://`
  scheme** — callers (`main.rs`'s IPC dispatch, `demo`) do not change.
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
