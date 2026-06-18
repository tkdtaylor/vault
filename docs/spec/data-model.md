# Data Model

**Project:** vault
**Last updated:** 2026-06-18

What data exists, how it's structured, and the wire formats crossing the process boundary. The
in-memory store holds each secret value as **AES-256-GCM ciphertext** (encrypted at rest in process
memory), never plaintext; the cleartext re-materialises only at the injection edge (ADR-005). With
the **opt-in** `--store-path` set, that encrypted store is also persisted to a single `0600` JSON
file — **ciphertext + non-secret metadata only**; the master key and the cleartext are never
written, and handles never persist (ADR-008).

Not here: operations ([behaviors.md](behaviors.md)), how data is accessed
([interfaces.md](interfaces.md)), tunables ([configuration.md](configuration.md)).

---

## Persistent state

**Opt-in, off by default.** With no `--store-path` / `VAULT_STORE_PATH`, vault holds no database
and no files beyond the transient Unix socket it binds — the store is in-memory and lost on restart
(today's default posture, byte-for-byte). With `--store-path PATH` set, the encrypted store is
persisted to a single JSON file at `PATH` and reloaded on startup (ADR-008).

### State: the store file (`--store-path PATH`)

- **Format:** a single plain-text JSON file. Shape:

  ```json
  {
    "version": 1,
    "records": {
      "vault://test/api_key": {
        "ciphertext_b64": "…",
        "nonce_b64": "…",
        "injection_floor": "proxy",
        "binding": { "host": "api.example.com", "header": "Authorization", "scheme": "Bearer", "env_var": "API_KEY" },
        "generation": 3
      }
    }
  }
  ```

  Records are serialized through a dedicated `StoredRecord` DTO (`src/store_file.rs`) so the internal
  `Secret` / `EncryptedValue` stay serde-free. `ciphertext` and `nonce` are base64-encoded JSON
  strings (hand-rolled `encode_base64` / `decode_base64` in `src/crypto.rs`, no base64 crate).
- **Contents:** AEAD **ciphertext** + the (non-secret) **nonce** + cleartext metadata
  (`injection_floor`, `binding`, `generation`). The 32-byte master **key is never written**, and the
  **cleartext value is never written** (ADR-008 §6). **Handles never persist** — only `store` is
  serialized, so a restart starts with an empty handle table and every outstanding handle is dead
  (`unknown_handle`) (ADR-008 §5).
- **Load (startup):** parse JSON → check `version == 1` → base64-decode each record into an
  `EncryptedValue` (nonce validated as exactly 12 bytes) → build the in-memory `store`. **No
  decryption at load** — decrypt stays at the `inject` edge; a wrong key surfaces there as
  `decrypt_failed`, not at load (ADR-008 §7). A **missing** file is a fresh empty store (first run,
  not an error); a **structurally corrupt** file (bad JSON / unknown version / invalid base64 /
  wrong-length nonce) makes `serve` **refuse to start** (non-zero exit, no panic, store never
  silently emptied — ADR-008 §8).
- **Write-through (mutation):** `put` and `rotate` persist the whole file after the in-memory
  mutation, **atomically and `0600`** — temp file `<PATH>.tmp.<pid>` in the same directory, `chmod
  0600` before any bytes, `write_all` + `fsync`, atomic `rename` over `PATH` (ADR-008 §4). A failed
  persist rolls back the in-memory mutation and surfaces `store_persist_failed` — never a silent
  success. `resolve`/`inject`/`get`/`list` never write.
- **Mode:** `0600` (same-uid-only by filesystem ACL — the on-disk analogue of the uid-restricted
  socket). A tampered-but-structurally-valid ciphertext loads fine and fails closed at `inject`
  (`decrypt_failed`); the AEAD tag is the value-integrity check.

---

## In-memory state

### State: `Vault.store` — the secret store (encrypted at rest)

- **Shape:** `HashMap<String, Secret>` keyed by `secret_ref` (a `vault://<scope>/<key>` string).
  `Secret { enc: EncryptedValue, injection_floor: Mode, binding: Binding, generation: u64 }`
  (`src/vault.rs`). The value is held as `EncryptedValue { ciphertext: Vec<u8>, nonce: [u8;12] }` —
  AES-256-GCM ciphertext (value + appended 128-bit tag) and its unique 96-bit nonce; **the cleartext
  is never stored** (ADR-005). `generation` starts at `0` on `put` and is bumped on every `rotate`; a
  handle resolved against generation N is invalidated once the secret advances past N (ADR-004).
- **Owner:** the `Vault` value (`src/vault.rs`), behind an `Arc<Mutex<Vault>>` in the server. The
  `Vault` also holds a `Box<dyn StoreBackend>` — the store-encryption seam, `AesGcmBackend` in
  production — which owns the master key (from the key-provider seam) in its own memory, **never
  beside the ciphertext**.
- **Lifetime:** process lifetime; populated by `put` (which **encrypts** the value with a fresh
  nonce), value replaced in place by `rotate` (which **re-encrypts** with a fresh nonce). Persisted
  to the `--store-path` file (ciphertext + metadata only) on `put`/`rotate` and reloaded on startup
  when persistence is enabled; in-memory only otherwise (ADR-008).
- **Concurrency rules:** the whole `Vault` is guarded by a `Mutex` in `serve`; each connection
  locks it for the duration of its op.
- **Bounds:** bounded by the number of secrets `put`.

### State: `Vault.handles` — the handle table

- **Shape:** `HashMap<String, HandleRec>` keyed by the hex handle string.
  `HandleRec { secret_ref: String, mode: Mode (the secret's floor at resolve time), expires_at: u64,
  consumed: bool, bound_sandbox: Option<String>, generation: u64 }` (`src/vault.rs`). `expires_at`
  is the absolute Unix-seconds expiry, computed at `resolve` as `clock.now_unix() + ttl` (saturating
  add). `generation` is the secret's generation snapshotted at `resolve`; an `inject` whose snapshot
  ≠ the secret's current generation is rejected `handle_invalidated` (rotation invalidation, ADR-004).
- **Owner:** the `Vault` value; same `Arc<Mutex<Vault>>`. `Vault` also holds a `Box<dyn Clock>` —
  `SystemClock` in production (`Vault::new`), an injectable test clock via `Vault::with_clock`.
- **Lifetime:** process lifetime; a record is inserted by `resolve` and mutated (consumed + bound)
  by `inject`. Records are not removed (no reaper) — an expired record stays in the table but is
  un-injectable (`handle_expired`).
- **Concurrency rules:** guarded by the same `Mutex`.
- **Invariant:** a record is **single-use** — `consumed` flips to `true` on the first successful
  `inject` and is never reset; `bound_sandbox` is set on first inject and never re-bound. A record
  is **expired** once `clock.now_unix() >= expires_at` (exactly-at-expiry is expired; `ttl=0` ⇒
  immediate). A record is **invalidated** once its `generation` ≠ the secret's current generation
  (the secret was rotated after this handle was resolved — `handle_invalidated`). On `inject`, the
  check order is consumed → expired → invalidated → binding.

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

### Type: `EncryptedValue` (a secret value at rest)

```
struct EncryptedValue {
  ciphertext: Vec<u8>,   // AES-256-GCM ciphertext: value + appended 128-bit auth tag
  nonce:      [u8; 12],  // the unique 96-bit nonce this value was sealed with
}
```

- **Held in:** `Secret.enc` (`src/crypto.rs`). It is the **only** representation of the value the
  store keeps — the cleartext is never present at rest (ADR-005).
- **Nonce:** fresh random 96 bits per `put`/`rotate`, drawn from `/dev/urandom` (no `rand` crate).
  The nonce is not secret and may be stored/transmitted in the clear; the tag authenticates the
  ciphertext, so tamper/truncation fail closed on decrypt (`decrypt_failed`).
- **No serde derive** — it never crosses the wire and is not serialized into the store file
  directly; the on-disk `StoredRecord` DTO carries the serde derives and maps to/from it, so no AEAD
  type leaks into a contract response and a value-field leak would have to be typed into the DTO.

### Type: `StoredRecord` (on-disk DTO — `src/store_file.rs`)

```
struct StoredRecord {
  ciphertext_b64:  String,   // base64 of EncryptedValue.ciphertext (AES-256-GCM ct + tag)
  nonce_b64:       String,   // base64 of the 12-byte nonce
  injection_floor: Mode,     // "env" | "proxy"  — non-secret metadata
  binding:         Binding,  // non-secret metadata
  generation:      u64,      // rotate counter — persisted so on-disk truth stays correct
}
```

- **Serde derive lives here**, not on `Secret` / `EncryptedValue` (ADR-008 §2). `Vault` maps
  `Secret ⇄ StoredRecord` explicitly, keeping the internal types wire-free and the disk format an
  intentional, reviewable surface. There is **no field for the cleartext value or the key** — only
  ciphertext, nonce, and non-secret metadata are representable.
- **Used only** by the `--store-path` persistence layer; absent from every IPC/HTTP wire response.

### Seam: `KeyProvider` (the master-key source) and `StoreBackend` (the encryption seam)

- **`KeyProvider`** (`src/crypto.rs`): `fn key(&self) -> Result<[u8;32], String>`. The 32-byte
  AES-256 key is sourced through this seam — **never serialized into the store, never logged**. The
  production `EnvKeyProvider` reads `VAULT_MASTER_KEY_FILE` (path) or `VAULT_MASTER_KEY` (inline),
  decoding hex/base64 to exactly 32 bytes; a missing/unreadable key is an error (fail-closed).
- **`StoreBackend`** (`src/crypto.rs`): `encrypt(&str) -> EncryptedValue`,
  `decrypt(&EncryptedValue) -> String`. The production `AesGcmBackend` holds the key (from a
  `KeyProvider`) and does AES-256-GCM. `resolve`/`inject`/callers are unchanged when the backend
  swaps; an unconfigured key yields a backend that fails closed on every op (no plaintext fallback).

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

→ `{ "ok": true }` on success. Absent `injection_floor` defaults to `env`; absent/invalid `binding`
defaults as above. Fail-closed: no key configured → `{error:{code:"encrypt_failed",…}}` (nothing
stored); with `--store-path` set, a failed disk write → `{error:{code:"store_persist_failed",…}}`
(in-memory insert rolled back).

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
| `no_such_secret` | `false` | `resolve`, `get`, or `rotate` of a `secret_ref` not in the store |
| `unknown_handle` | `false` | `inject` of a handle not in the handle table |
| `handle_consumed` | `false` | `inject` of an already-used handle (replay); checked before expiry |
| `handle_expired` | `false` | `inject` of an unconsumed handle past its TTL (`now >= expires_at`) |
| `handle_invalidated` | `false` | `inject` of a handle whose secret was rotated after the handle was resolved (generation mismatch — ADR-004); checked after expiry, before binding |
| `handle_bound_to_other_sandbox` | `false` | `inject` from a sandbox other than the bound one |
| `decrypt_failed` | `false` | `inject` whose stored ciphertext fails the AES-256-GCM tag check (tampered / truncated / wrong key) — no credential, no panic (ADR-005) |
| `encrypt_failed` | `false` | `put`/`rotate` whose encryption fails (e.g. no key configured, nonce-RNG failure); nothing is stored / the prior ciphertext is left untouched (ADR-005) |
| `store_persist_failed` | `false` | `put`/`rotate` whose atomic write to the `--store-path` file failed (disk full, permission, fsync); the in-memory mutation is rolled back, the prior file is left intact — never a silent success (ADR-008 §4) |
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
- **A handle is bound to the secret's value generation.** A `rotate` bumps the secret's
  `generation`; a handle resolved against an older generation is rejected `handle_invalidated` and
  never delivers the post-rotation value (checked after expiry, before binding — ADR-004).
- **The admin verbs `get`/`list`/`rotate` are value-free.** Their responses carry only metadata
  (floor, binding, refs); the secret value never appears, including for JSON-special-char values.
  `get`/`list` never decrypt; `rotate` re-encrypts but never echoes the value.
- **The value is ciphertext at rest.** `Secret.enc` holds AES-256-GCM ciphertext + nonce, never the
  cleartext; the cleartext re-materialises only inside `put`/`rotate` (transiently, before
  encryption) and at `inject` (after decrypt, at the injection edge). A tampered ciphertext fails
  closed (`decrypt_failed`), never a silent wrong value (ADR-005).
- **The master key lives off the ciphertext.** The 32-byte AES key is held only in the backend's
  memory (from the `KeyProvider` seam) — never serialized into the store **or the store file**,
  never logged. A missing key fails the store closed (no plaintext fallback).
- **The store file is ciphertext-only at rest.** With `--store-path` set, the file holds AEAD
  ciphertext + nonce + non-secret metadata only — never the key, never the cleartext. A stolen file
  is inert without the separately-held master key (a reload under a different key fails closed at
  `inject` with `decrypt_failed`). The file is `0600` and written atomically (temp + fsync + rename)
  — ADR-008 §4/§6.
- **Handles never persist.** Only `store` is serialized; the handle table is ephemeral. A restart
  invalidates every outstanding handle (`unknown_handle` on a pre-restart handle) — persisted
  single-use handles would be a replay vector (ADR-008 §5).
- **A corrupt store file refuses to start.** A present-but-unparseable file (bad JSON / unknown
  version / invalid base64 / wrong-length nonce) aborts `serve` with a non-zero exit and no panic —
  the store is never silently emptied (ADR-008 §8). A missing file is the normal first-run path.
- **No engine/backend-specific type crosses the wire** — the contract is plain `vault://`-shaped
  JSON, so a future store backend (encrypted / OpenBao / KMS / HSM) slots in behind it unchanged.
