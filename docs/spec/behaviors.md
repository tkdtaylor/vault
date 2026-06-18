# Behaviors

**Project:** vault
**Last updated:** 2026-06-18

What the system does, observably — triggering condition, response, externally-visible side
effects, failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry
points* ([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Store a secret (admin `put`) — encrypted at rest

- **Trigger:** `{"op":"put","secret_ref":…,"value":…,"injection_floor":"env|proxy","binding":{…}}`
  over IPC, or `Vault::put(secret_ref, value, floor, binding)` in-process.
- **Response:** the value is **AES-256-GCM-encrypted with a fresh 96-bit nonce** and the resulting
  ciphertext + nonce is inserted into the in-memory store keyed by `secret_ref`, carrying its
  `injection_floor` (the minimum mode any later `inject` may deliver) and its `Binding`. The
  **cleartext is not retained** after `put` returns (ADR-005). IPC returns `{"ok":true}`.
- **Side effects:** mutates the in-memory store (with ciphertext); nothing is persisted to disk.
- **Failure modes:** an absent `injection_floor` defaults to `env`; an absent/invalid `binding`
  defaults to `{host:"", header:"Authorization", scheme:"Bearer", env_var:"API_KEY"}`. The value
  is **never** logged or echoed. If encryption fails (no master key configured, nonce-RNG failure)
  the put **fails closed** — nothing is stored for that ref (no plaintext fallback), so a later
  `resolve` of the unstored ref returns `no_such_secret`. *(Tests:
  `tc001_put_stores_ciphertext_not_plaintext`, `tc006_at_rest_negative_cleartext_absent`.)*

### B-012: Read a secret's metadata (admin `get`) — never the value

- **Trigger:** `{"op":"get","secret_ref":…}` over IPC, or `Vault::get(secret_ref)` in-process.
- **Response:** returns `{ "exists":true, "injection_floor":"env|proxy", "binding":{host,header,scheme,env_var} }`
  for a stored secret. **The value is never in the response** — only its floor and binding metadata.
- **Side effects:** none (read-only).
- **Failure modes:** an unknown or empty `secret_ref` → `{error:{code:"no_such_secret",…}}`, no
  metadata and no value. *(Tests: `tc001_get_returns_metadata_not_value`,
  `tc002_get_unknown_ref_is_fail_closed`.)*

### B-013: List stored secret refs (admin `list`) — never any value

- **Trigger:** `{"op":"list"}` over IPC, or `Vault::list()` in-process.
- **Response:** returns `{ "secrets":[ {"secret_ref":…, "injection_floor":…}, … ] }` — one entry per
  stored secret, carrying the ref and its floor. **No value appears.** Ordering is unspecified
  (HashMap iteration).
- **Side effects:** none (read-only).
- **Failure modes:** an empty store returns `{"secrets":[]}` — an empty list, **not** an error.
  *(Test: `tc003_list_returns_refs_no_values`.)*

### B-014: Rotate a secret's value in place (admin `rotate`) — invalidates outstanding handles

- **Trigger:** `{"op":"rotate","secret_ref":…,"value":…}` over IPC, or `Vault::rotate(secret_ref,
  value)` in-process.
- **Response:** **re-encrypts** the new value (AES-256-GCM, **fresh 96-bit nonce** — no reuse with
  the prior value) and replaces the stored ciphertext **in place**, preserving the secret's
  `injection_floor` and `binding`, and returns
  `{ "ok":true, "rotated":true, "injection_floor":…, "binding":{…} }`. **The value is never echoed
  back** (neither the old nor the new). A subsequent resolve→inject delivers the new value normally.
- **Side effects:** replaces the stored ciphertext and **bumps the secret's generation counter**,
  which invalidates every handle resolved against the prior value (B-015 / ADR-004).
- **Failure modes:** an unknown or empty `secret_ref` → `{error:{code:"no_such_secret",…}}`, nothing
  rotated. A re-encryption failure → `{error:{code:"encrypt_failed",…}}`, the prior ciphertext left
  untouched. *(Tests: `tc004_rotate_swaps_value_preserves_metadata_no_echo`,
  `tc005_rotate_invalidates_pre_rotation_handle`, `tc007_no_admin_verb_leaks_value`,
  `tc004_unique_nonces_no_reuse`.)*

### B-015: Rotation invalidates pre-rotation handles (fail-closed capability binding)

- **Trigger:** any `inject` against a handle that was resolved **before** a `rotate` of its secret.
- **Response:** the handle is rejected with `{error:{code:"handle_invalidated",…}}`, **no credential
  delivered** — a pre-rotation handle can never inject the post-rotation value. A handle resolved
  **after** the rotation injects the new value normally. Mechanism: each `Secret` carries a
  monotonic `generation` (bumped on every `rotate`); each handle snapshots that generation at
  `resolve` time; `inject` rejects a handle whose snapshot ≠ the secret's current generation.
- **Precedence:** the invalidation check runs **after** the consumed and expired checks and
  **before** the sandbox-binding check —
  `unknown_handle → handle_consumed → handle_expired → handle_invalidated → handle_bound_to_other_sandbox → deliver`.
- **Side effects:** none on rejection; no state mutation, no credential.
- **Failure modes:** fail-closed — a rotated-out handle is a non-delivery terminal state, no retry.
  *(Test: `tc005_rotate_invalidates_pre_rotation_handle`; ADR-004.)*

### B-002: Resolve a secret to a handle — never the value (zero-knowledge)

- **Trigger:** `{"op":"resolve","secret_ref":…,"ttl":<seconds>}` over IPC, or
  `Vault::resolve(secret_ref, ttl)` in-process. `ttl` defaults to `300` over IPC.
- **Response:** mints an opaque, single-use **handle** (32 random bytes from `/dev/urandom`,
  hex-encoded), records a handle entry bound to the secret with `consumed=false` and no sandbox
  binding yet, and returns `{ "handle": …, "ttl": …, "injection_mode": <secret's floor> }`.
  **The secret value is never in the response** — `injection_mode` is the secret's stored floor.
- **Side effects:** inserts a handle record into the in-memory handle table.
- **Failure modes:** an unknown `secret_ref` → `{error:{code:"no_such_secret",…}}`, no handle
  minted. An RNG read failure → `{error:{code:"rng_error",…}}`. There is no path on which the value
  appears in the response.

### B-003: Inject a credential at the injection edge (`inject`)

- **Trigger:** `{"op":"inject","handle":…,"sandbox_identity":{"sandbox_id":…},"mode":"env|proxy"}`
  over IPC, or `Vault::inject(handle, sandbox_id, requested)` in-process. This is the
  **pull-triggered push** — exec-sandbox presents `{handle, sandbox_identity}` at spawn.
- **Response:** validates the handle, rejects it if consumed (B-004) or if its TTL has elapsed
  (B-011), enforces the handle↔sandbox binding (B-004), computes the **effective mode**
  `max(secret_floor, requested)` (B-005), then **decrypts the stored AES-256-GCM ciphertext** — the
  one and only place the cleartext re-materialises (ADR-005) — marks the handle consumed and bound to
  this sandbox, and delivers the credential **to the injection edge only**:
  - `proxy` → `{ "ok":true, "delivery":"proxy", "credential":…, "binding":{host,header,scheme,env_var} }`
    — the value goes to exec-sandbox's egress proxy, never into the sandbox. No `wiped_at` is
    present (there is no in-sandbox value to wipe).
  - `env` → `{ "ok":true, "delivery":"env", "credential":…, "var_name":…, "wiped_at":<unix_secs> }`
    — the value is set as the named env var in the sandbox; `wiped_at` is the inject-time clock
    value (the moment the credential is handed to the env-setter), not a placeholder.
  Decryption happens **before** the handle is marked consumed, so an integrity fault does not burn
  the single-use handle.
- **Side effects:** mutates the handle record (`consumed=true`, `bound_sandbox=<sandbox_id>`); the
  decrypted credential crosses only the uid-restricted socket to the injection edge.
- **Failure modes:** see B-006 (unknown handle, replay, wrong sandbox, expired, rotated, **tampered
  ciphertext**) — all fail closed with the structured error shape; no credential delivered. A stored
  ciphertext that fails the AES-256-GCM tag check (tampered / truncated / wrong key) →
  `{error:{code:"decrypt_failed",…}}`, **never a silent wrong value, never a panic** (B-016). The
  check order is
  `unknown_handle → handle_consumed → handle_expired → handle_invalidated → handle_bound_to_other_sandbox → decrypt → deliver`
  (B-011, B-015, B-016). *(Test: `tc002_resolve_inject_round_trips_plaintext`.)*

### B-004: Enforce single-use + first-use sandbox binding (D5)

- **Trigger:** any `inject` against a handle that has already been used, or by a different sandbox.
- **Response:** a handle is **consumed on first inject** and **bound to the first sandbox** that
  uses it. A subsequent `inject` with the same handle → `{error:{code:"handle_consumed",…}}`. An
  `inject` with a different `sandbox_id` than the bound one →
  `{error:{code:"handle_bound_to_other_sandbox",…}}`.
- **Side effects:** none on rejection; the rejected request delivers no credential.
- **Failure modes:** rejection is itself the safe terminal state — there is no retry or override.
  *(Test: `replay_is_rejected`.)*

### B-005: Raise-only injection floor (fail-closed reconciliation)

- **Trigger:** any `inject` where the requested `mode` differs from the secret's stored floor.
- **Response:** the effective mode is `max(secret_floor, requested)` under the ordering
  `env (0) < proxy (1)`. A request for a **stronger** mode (env floor, proxy requested) raises to
  proxy. A request for a **weaker** mode (proxy floor, env requested) is **ignored** — the floor
  holds; delivery is proxy. An absent `mode` delivers the floor unchanged.
- **Side effects:** none beyond B-003's delivery at the effective mode.
- **Failure modes:** vault **never lowers** the floor — lowering is the failure mode this invariant
  exists to prevent. *(Test: `floor_cannot_be_lowered` — env requested against a proxy floor still
  delivers proxy.)*

### B-011: Enforce handle TTL — reject expired handles (auto-expire)

- **Trigger:** any `inject` against an **unconsumed** handle whose TTL has elapsed.
- **Response:** at `resolve`, the handle records `expires_at = now + ttl` (clock seconds since the
  Unix epoch; `now` from the injectable clock). At `inject`, the handle is **expired IFF
  `now >= expires_at`** — exactly-at-expiry counts as expired. An expired handle →
  `{error:{code:"handle_expired",…}}`, **no credential delivered**, and the handle is left
  unconsumed. `ttl=0` ⇒ the handle expires immediately (any inject fails).
- **Precedence:** the expiry check runs **after** the consumed check, so a handle that is both
  consumed and expired returns `handle_consumed` (the use already happened); an expired-but-unconsumed
  handle returns `handle_expired`.
- **Side effects:** none on rejection; no state mutation, no credential.
- **Failure modes:** fail-closed — an elapsed TTL is a non-delivery terminal state, no retry. The
  production clock is the wall clock (`SystemClock`); tests inject a controllable clock.
  *(Tests: `tc002_inject_after_expiry_is_rejected`, `tc002_exactly_at_expiry_is_expired`,
  `tc006_precedence_expired_vs_consumed`; ADR-003.)*

### B-016: Decrypt the stored ciphertext at the edge — fail closed on a bad tag

- **Trigger:** any `inject` that passes the handle checks and reaches delivery — and, on the failure
  side, any such `inject` whose stored AES-256-GCM ciphertext fails authentication (tampered,
  truncated, or sealed under a different key).
- **Response:** on success, the ciphertext is decrypted to the exact original plaintext and delivered
  as the `credential` (round-trip integrity). On a tag-check failure → `{error:{code:"decrypt_failed",…}}`,
  **no credential**, **no panic** — never a silent wrong/garbage value. Decryption is the only point
  the cleartext re-materialises, and it happens at the injection edge, not at `resolve`.
- **Side effects:** none on failure (the handle is **not** consumed by a failed decrypt); on success,
  the normal B-003 consume/bind mutation.
- **Failure modes:** fail-closed — a `decrypt_failed` is a non-delivery terminal state. *(Tests:
  `tc005_tampered_ciphertext_fails_closed`, `tc002_resolve_inject_round_trips_plaintext`; ADR-005.)*

### B-006: Reject a malformed, unknown, or unsupported request (fail-closed)

- **Trigger:** a denied peer uid, unparseable JSON, an unknown `op`, an unknown handle, an unknown
  secret, a consumed handle, an expired handle, a wrong sandbox, a tampered ciphertext, or an RNG
  failure.
- **Response:** the structured error shape `{error:{code,message,retryable:false}}`. Codes in use:
  `peer_uid_denied` (peer uid ≠ server uid, or unreadable peer cred — B-010), `bad_request`
  (unparseable JSON), `unknown_op` (unsupported op), `no_such_secret`, `unknown_handle`,
  `handle_consumed`, `handle_expired` (TTL elapsed — B-011), `handle_invalidated` (secret rotated
  after resolve — B-015), `handle_bound_to_other_sandbox`, `decrypt_failed` (tampered ciphertext —
  B-016), `encrypt_failed` (rotate re-encryption failure — B-014), `rng_error`.
- **Side effects:** none; the connection is closed after the single response.
- **Failure modes:** the caller must treat any `error` response as a non-delivery (fail-closed);
  vault never delivers a credential for a malformed, unknown, or unsupported request.

### B-007: Serve over a uid-restricted Unix-socket IPC server (`serve`)

- **Trigger:** `vault serve --socket <path>`.
- **Response:** removes any stale socket at `<path>`, binds a Unix socket, sets permissions to
  `0600` (owner-only — the file-mode half of the D5 uid restriction), logs the listen address to
  stderr, and accepts connections, spawning a thread per connection over a shared
  `Arc<Mutex<Vault>>`. On each accepted connection, **before any op is dispatched**, the server reads
  the peer credential via `SO_PEERCRED` and admits the connection only if the peer uid equals the
  server's own effective uid (B-010). Each admitted connection sends one newline-delimited JSON
  object; ops are `ping` (→ `{"ok":true}`), `put` (B-001), `resolve` (B-002), `inject` (B-003).
- **Side effects:** creates the socket file; spawns one OS thread per connection.
- **Failure modes:** a missing `--socket` exits with usage error (`2`). A bind failure panics
  (`expect("bind unix socket")`) → non-zero exit. A peer-uid mismatch or unreadable peer credential
  is rejected with `peer_uid_denied` and no op runs (B-010). An empty / unreadable first line closes
  the connection with no response.

### B-010: Kernel-verified peer-uid admission on the socket (D5, fail-closed)

- **Trigger:** any connection accepted by `serve`, evaluated before the request is read or
  dispatched.
- **Response:** the server reads the connecting peer's uid from the kernel via `SO_PEERCRED` and
  computes a pure equality decision — admit **iff** `peer_uid == server_uid` (the server's effective
  uid via `geteuid`). This is **equality, not privilege**: root (uid 0) connecting to a non-root
  server is denied unless 0 is the server's own uid. A denied connection receives
  `{"error":{"code":"peer_uid_denied",…}}` and is closed; **no `resolve` / `inject` / `put` runs**.
- **Side effects:** none on denial beyond the error response; an admitted connection proceeds to
  normal dispatch unchanged (no happy-path behavior change).
- **Failure modes:** **fail-closed** — if the peer credential cannot be read, the connection is
  **denied**, never admitted ("can't tell ⇒ deny"). The read failure is not propagated as a panic.
  *(Decision function `src/main.rs::peer_uid_allowed`; tests
  `peer_uid_allowed_is_equality_not_privilege`, `unreadable_peer_cred_is_denied`; ADR-002.)*

### B-008: One-shot in-process demonstration (`demo`)

- **Trigger:** `vault demo`.
- **Response:** runs put → resolve → inject → replay-rejected **in-process** (no socket bound) and
  prints each step's JSON to stdout: a proxy-floor secret is put, resolved to a handle (no value),
  injected once (credential delivered), then injected again with the same handle (rejected with
  `handle_consumed`). This is the operator-facing demonstration of the single-use invariant (D5).
- **Side effects:** stdout only; no socket, no persistence.
- **Failure modes:** none expected on the happy path; the replay step is *expected* to be rejected
  and prints the rejection.

---

## Edge cases and error behaviors

### B-009: Defaults on incomplete `put` input

- **Trigger:** an IPC `put` missing `injection_floor` or `binding`.
- **Response:** `injection_floor` defaults to `env`; `binding` defaults to
  `{host:"", header:"Authorization", scheme:"Bearer", env_var:"API_KEY"}`. The secret is stored
  with those defaults.
- **Side effects:** stores the secret with defaulted fields.
- **Failure modes:** none — defaults are deliberately safe (env floor is the conservative baseline;
  `inject` may still raise it).

---

## Behavioral invariants

- **No path returns the secret value to the agent.** `resolve` returns only `{handle, ttl,
  injection_mode}`; the value appears only on the `inject` response, which crosses the
  uid-restricted socket to the injection edge (exec-sandbox), never to the agent core.
- **The injection floor only ever rises.** `inject` delivers at `max(secret_floor, requested)`; a
  weaker requested mode never lowers a stronger stored floor.
- **A handle is single-use and bound to one sandbox.** Replays (`handle_consumed`) and other
  sandboxes (`handle_bound_to_other_sandbox`) are rejected.
- **A handle expires.** Past its TTL (`now >= expires_at`, set as `resolve_time + ttl`) an unconsumed
  handle is rejected with `handle_expired` and delivers nothing; a consumed handle reports
  `handle_consumed` first (consumed-before-expired precedence).
- **Rotation invalidates outstanding handles.** A handle resolved before a `rotate` of its secret is
  rejected with `handle_invalidated` and never delivers the post-rotation value; a handle resolved
  after the rotation works normally. (Per-secret generation counter — B-015, ADR-004.)
- **The admin read/rotate verbs never expose the value.** `get`, `list`, and `rotate` return only
  metadata (floor, binding, refs) — the secret value appears nowhere in their responses, even for
  values containing JSON-special characters. The value is delivered only on `inject`, to the
  injection edge.
- **The stored value is ciphertext, decrypted only at the edge.** `put`/`rotate` AES-256-GCM-encrypt
  the value with a fresh 96-bit nonce; the cleartext is held nowhere at rest. `inject` decrypts at
  the injection edge — the one point the cleartext re-materialises — and a tampered ciphertext fails
  `decrypt_failed` (never a silent wrong value). The master key comes from a provider seam and is
  never stored beside the ciphertext or logged; a missing key fails the store closed. (B-001, B-014,
  B-016, ADR-005.)
- **Every non-delivery path fails closed.** A denied peer uid, unknown handle/secret/op, expired
  handle, tampered ciphertext, malformed request, or RNG failure → the structured error shape; never
  a delivered credential.
- **The socket admits only the server's own uid.** Every accepted connection is gated by a
  kernel-verified `SO_PEERCRED` check (`peer_uid == server_uid`, equality not privilege) before any
  op is dispatched; an unreadable peer credential is denied (fail-closed). This is the
  kernel-verified half of the D5 uid restriction (the `0600` mode is the file-mode half).
- **The value is never logged.** No `put`, `resolve`, `inject`, or error path emits the credential
  to stderr/stdout (except the `inject` delivery itself, which is the injection edge by design).
