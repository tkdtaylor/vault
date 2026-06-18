# Data Model

**Project:** vault
**Last updated:** 2026-06-18

What data exists, how it's structured, and the wire formats crossing the process boundary. vault
has **no persistent store** in v0 — all state is in-memory or on the wire.

Not here: operations ([behaviors.md](behaviors.md)), how data is accessed
([interfaces.md](interfaces.md)), tunables ([configuration.md](configuration.md)).

---

## Persistent state

**None (v0).** vault holds no database and no files beyond the transient Unix socket it binds. The
store is in-memory and lost on restart.

> TODO: encrypted-at-rest persistence (AES-256-GCM + age / client-side encryption for store-level
> zero-knowledge) is a v0 limitation, not yet built (ADR-001 §2 open questions). Today the store is
> in-memory plaintext.

---

## In-memory state

### State: `Vault.store` — the secret store

- **Shape:** `HashMap<String, Secret>` keyed by `secret_ref` (a `vault://<scope>/<key>` string).
  `Secret { value: String, injection_floor: Mode, binding: Binding }` (`src/vault.rs`).
- **Owner:** the `Vault` value (`src/vault.rs`), behind an `Arc<Mutex<Vault>>` in the server.
- **Lifetime:** process lifetime; populated by `put`. Not persisted.
- **Concurrency rules:** the whole `Vault` is guarded by a `Mutex` in `serve`; each connection
  locks it for the duration of its op.
- **Bounds:** bounded by the number of secrets `put`.

### State: `Vault.handles` — the handle table

- **Shape:** `HashMap<String, HandleRec>` keyed by the hex handle string.
  `HandleRec { secret_ref: String, mode: Mode (the secret's floor at resolve time), expires_at: u64,
  consumed: bool, bound_sandbox: Option<String> }` (`src/vault.rs`). `expires_at` is the absolute
  Unix-seconds expiry, computed at `resolve` as `clock.now_unix() + ttl` (saturating add).
- **Owner:** the `Vault` value; same `Arc<Mutex<Vault>>`. `Vault` also holds a `Box<dyn Clock>` —
  `SystemClock` in production (`Vault::new`), an injectable test clock via `Vault::with_clock`.
- **Lifetime:** process lifetime; a record is inserted by `resolve` and mutated (consumed + bound)
  by `inject`. Records are not removed (no reaper) — an expired record stays in the table but is
  un-injectable (`handle_expired`).
- **Concurrency rules:** guarded by the same `Mutex`.
- **Invariant:** a record is **single-use** — `consumed` flips to `true` on the first successful
  `inject` and is never reset; `bound_sandbox` is set on first inject and never re-bound. A record
  is **expired** once `clock.now_unix() >= expires_at` (exactly-at-expiry is expired; `ttl=0` ⇒
  immediate). On `inject`, the consumed check precedes the expiry check.

---

## Types

### Type: `Mode` (injection mode)

```
enum Mode { Env, Proxy }     // serde: lowercase "env" | "proxy"
```

- **Rank / ordering:** `Env = 0`, `Proxy = 1` — **`env < proxy`** (`proxy` is stronger: the value
  never enters the sandbox).
- **Reconciliation:** `inject` delivers at `max(secret_floor, requested)` — raise-only.
- **Parsing:** `parse_mode(Value) -> Option<Mode>` reads the JSON string; an unknown / absent value
  yields `None` (treated as "no requested mode" → deliver the floor unchanged).

### Type: `Binding` (proxy/env injection target)

```
struct Binding {
  host:    String,                        // egress host the proxy injects for
  header:  String,  // default "Authorization"
  scheme:  String,  // default "Bearer"
  env_var: String,  // default "API_KEY"   (the var name in env mode)
}
```

- **Defaults:** `header="Authorization"`, `scheme="Bearer"`, `env_var="API_KEY"` (serde `default`
  fns in `src/vault.rs`). `host` has no default (empty string if absent).
- **Use:** returned in full on a `proxy` inject (`binding`); `env_var` is returned as `var_name` on
  an `env` inject.

---

## Wire / interchange formats

All IPC is **newline-delimited JSON over a Unix socket** — one request object per connection, one
response line back.

### Format: `put` request

```json
{ "op":"put", "secret_ref":"vault://test/api_key", "value":"SK-…",
  "injection_floor":"proxy",
  "binding":{ "host":"api.example.com", "header":"Authorization", "scheme":"Bearer", "env_var":"API_KEY" } }
```

→ `{ "ok": true }`. Absent `injection_floor` defaults to `env`; absent/invalid `binding` defaults
as above.

### Format: `resolve` request / response

```json
{ "op":"resolve", "secret_ref":"vault://test/api_key", "ttl":300 }
```

→ `{ "handle":"<64-hex-chars>", "ttl":300, "injection_mode":"proxy" }` — **never the value**. `ttl`
defaults to `300` if absent. `injection_mode` is the secret's stored floor.

### Format: `inject` request / response

```json
{ "op":"inject", "handle":"<hex>", "sandbox_identity":{"sandbox_id":"sbx-1"}, "mode":"proxy" }
```

→ proxy delivery:

```json
{ "ok":true, "delivery":"proxy", "credential":"SK-…",
  "binding":{ "host":"api.example.com", "header":"Authorization", "scheme":"Bearer", "env_var":"API_KEY" } }
```

→ env delivery:

```json
{ "ok":true, "delivery":"env", "credential":"SK-…", "var_name":"API_KEY", "wiped_at":1718600000 }
```

The effective mode is `max(secret_floor, mode)`. `wiped_at` (env mode only) is the inject-time clock
value in Unix seconds — the moment the credential is handed to the env-setter; proxy deliveries carry
no `wiped_at`. An inject after the handle's TTL has elapsed (`now >= expires_at`) returns
`{error:{code:"handle_expired",…}}` with **no** credential. The `credential` crosses only the
uid-restricted socket to the injection edge.

### Format: `ping` request

```json
{ "op":"ping" }   →   { "ok": true }
```

### Format: error shape

```
{ "error": { "code": string, "message": string, "retryable": bool } }
```

All current errors are `retryable:false`. Codes:

| `code` | `retryable` | Trigger |
|--------|-------------|---------|
| `peer_uid_denied` | `false` | accepted connection whose `SO_PEERCRED` peer uid ≠ the server's effective uid, or whose peer credential cannot be read (fail-closed) — no op dispatched |
| `bad_request` | `false` | unparseable request JSON |
| `unknown_op` | `false` | an unsupported IPC op |
| `no_such_secret` | `false` | `resolve` of a `secret_ref` not in the store |
| `unknown_handle` | `false` | `inject` of a handle not in the handle table |
| `handle_consumed` | `false` | `inject` of an already-used handle (replay); checked before expiry |
| `handle_expired` | `false` | `inject` of an unconsumed handle past its TTL (`now >= expires_at`) |
| `handle_bound_to_other_sandbox` | `false` | `inject` from a sandbox other than the bound one |
| `rng_error` | `false` | `/dev/urandom` read failure while minting a handle |

---

## Data invariants

- **The secret value never appears in a `resolve` response or any error.** It appears only on the
  `inject` delivery (proxy `credential` / env `credential`), which crosses to the injection edge.
- **A handle is 64 hex characters** (32 bytes from `/dev/urandom`), opaque and unguessable.
- **The injection floor only moves up.** The delivered mode is `max(secret_floor, requested)` under
  `env < proxy`; a weaker requested mode never lowers a stronger stored floor.
- **A handle is consumed once and bound to one sandbox.** `consumed` never resets; `bound_sandbox`
  never re-binds.
- **A handle has an absolute expiry.** `expires_at = resolve_time + ttl`; once `now >= expires_at`
  an unconsumed handle is un-injectable (`handle_expired`). The consumed check precedes the expiry
  check, so a consumed+expired handle reports `handle_consumed`.
- **No engine/backend-specific type crosses the wire** — the contract is plain `vault://`-shaped
  JSON, so a future store backend (encrypted / OpenBao / KMS / HSM) slots in behind it unchanged.
