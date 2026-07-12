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
- **Side effects:** mutates the in-memory store (with ciphertext). With `--store-path` set, the
  encrypted store is **written-through to disk** atomically after the insert (B-019); unset → no disk
  I/O.
- **Failure modes:** an absent `injection_floor` defaults to `env`; an absent/invalid `binding`
  defaults to `{host:"", header:"Authorization", scheme:"Bearer", env_var:"API_KEY"}`. The value
  is **never** logged or echoed. If encryption fails (no master key configured, nonce-RNG failure)
  the put **fails closed** with `encrypt_failed` — nothing is stored for that ref (no plaintext
  fallback), so a later `resolve` of the unstored ref returns `no_such_secret`. With `--store-path`
  set, a failed disk write rolls back the in-memory insert and returns `store_persist_failed`
  (B-019) — never a silent success. *(Tests:
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
  which invalidates every handle resolved against the prior value (B-015 / ADR-004). With
  `--store-path` set, the rotated store (fresh nonce + bumped generation) is **written-through to
  disk** atomically (B-019); unset → no disk I/O.
- **Failure modes:** an unknown or empty `secret_ref` → `{error:{code:"no_such_secret",…}}`, nothing
  rotated. A re-encryption failure → `{error:{code:"encrypt_failed",…}}`, the prior ciphertext left
  untouched. With `--store-path` set, a failed disk write rolls the in-memory entry back to its
  pre-rotate state and returns `store_persist_failed` (B-019). *(Tests:
  `tc004_rotate_swaps_value_preserves_metadata_no_echo`,
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
  (B-011, B-015, B-016). When attestation verification is configured (B-020), it runs at the dispatch
  edge **before** this whole sequence, and the binding key is the **verified** sandbox id.
  *(Test: `tc002_resolve_inject_round_trips_plaintext`.)*

### B-020: Verify the sandbox attestation at the dispatch edge (opt-in, transitional)

- **Trigger:** an `inject` request when `--attest-trust-root-file` / `VAULT_ATTEST_TRUST_ROOT_FILE`
  configures a 32-byte Ed25519 trust root (ADR-010). Provisional wire shape (pending exec-sandbox
  tasks 020-021): `sandbox_identity.attestation = {alg:"ed25519", payload:<base64 canonical JSON
  {"sandbox_id":…}>, signature:<base64 64-byte sig over the raw decoded payload>}`.
- **Response:** vault verifies the signature over the decoded payload against the configured trust
  root, requires the signed `sandbox_id` to equal the outer one, and passes the **verified** id into
  `Vault::inject` as the binding key, so the handle now binds to a cryptographically-verified identity
  instead of a caller-asserted string. Verification runs at the dispatch edge **before any `Vault`
  call** (same layering as the SO_PEERCRED gate, B-006), so a rejected attestation never consumes,
  binds, or expire-checks a handle.
- **Failure modes (fail-closed):** no `attestation` member → `{error:{code:"attestation_missing",…}}`;
  bad base64, wrong signature/payload/key, wrong `alg`, wrong/empty `sandbox_id`, or a signed id that
  disagrees with the outer id → `{error:{code:"attestation_invalid",…}}`. `retryable:false`; no
  credential in the response; `Vault::inject` never called.
- **Transitional passthrough:** with **no** trust root configured, the `attestation` member is ignored
  and the handle binds to the opaque, caller-asserted `sandbox_id` byte-for-byte as before; the
  unverifiable-binding gap stays open in this mode (the documented, opt-in transition, ADR-010).
  *(Tests: `tc001_trust_root_config_precedence_decode_and_reject`,
  `tc002_valid_attestation_delivers_and_binds_verified_id`,
  `tc003_tampered_sig_and_payload_rejected_handle_not_burned`,
  `tc004_wrong_key_rejected_correct_key_control`, `tc005_missing_malformed_mismatch_rejected`,
  `tc006_passthrough_no_trust_root_is_todays_behavior`.)*

### B-021: Identity-binding mode — bind the handle to a SPIFFE workload identity (opt-in)

- **Trigger:** an `inject` request when `--identity-binding spiffe` / `VAULT_IDENTITY_BINDING=spiffe`
  is set (ADR-011). The caller propagates the agent-mesh verified-principal block
  `sandbox_identity.principal = {spiffe_id, trust_tier}`.
- **Response:** the mock issuer validates the principal's shape (a well-formed `spiffe_id` per the
  documented subset + a non-empty `trust_tier`) and vault binds the handle's first-use key to the
  **`spiffe_id`** instead of the opaque `sandbox_id`, so a handle first injected by one workload
  identity can never be presented by another (the whole URI is the key, no prefix matching). The
  contract response is byte-for-byte unchanged (no principal type leaks out). Principal resolution
  runs at the dispatch edge **after** attestation verify (B-020) and **before** any `Vault` call.
- **SPIFFE-ID subset (fail-closed):** scheme exactly `spiffe://`; non-empty lowercase `[a-z0-9.-]`
  trust domain; non-empty `/`-prefixed path; no query/fragment; ≤ 2048 bytes. Anything else, or a
  missing/empty `trust_tier`, → `{error:{code:"principal_invalid",…}}`; a missing `principal` member →
  `{error:{code:"principal_missing",…}}`. `retryable:false`; no credential; `Vault::inject` never
  called; the handle is neither consumed nor bound.
- **Default (sandbox) mode:** with no flag/env (or `sandbox`), the binding key is the (B-020 verified,
  else opaque) `sandbox_id` byte-for-byte as before; the `principal` member is ignored. An unknown
  `--identity-binding` value refuses to start (never a silent fallback). *(Tests:
  `tc011_001_binding_mode_config`, `tc011_002_spiffe_binds_to_verified_spiffe_id`,
  `tc011_003_bound_handle_rejects_other_principal`, `tc011_004_fail_closed_missing_and_malformed`,
  `tc011_005_resolver_drop_in_swappable`, `tc011_006_default_sandbox_mode_ignores_principal`,
  and `src/vault.rs::spiffe_id_is_the_discriminating_binding_key`.)*

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
  B-016), `encrypt_failed` (put/rotate encryption failure — B-001/B-014), `store_persist_failed`
  (put/rotate disk write failure with `--store-path` — B-019), `attestation_missing` /
  `attestation_invalid` (inject attestation verification, only when a trust root is configured —
  B-020), `principal_missing` / `principal_invalid` (inject principal resolution, only in spiffe
  identity-binding mode — B-021), `backend_unavailable` (a failed remote store/fetch under
  `--secret-backend` — ADR-007; the fetch precedes handle consumption, so a transient failure does
  not burn the handle), `rng_error`.
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

### B-017: Serve an opt-in, loopback-only, read-only HTTP read surface (`--http-addr`)

- **Trigger:** `vault serve --socket <path> --http-addr 127.0.0.1:<port>`.
- **Response:** **only when `--http-addr` is passed**, the server starts a second listener — a
  thread-per-connection HTTP server (in the HashiCorp Vault / OpenBao KV-v2 API shape) sharing the
  **same** `Arc<Mutex<Vault>>` as the Unix socket — but **only if** the host is the literal
  `127.0.0.1` loopback. Two routes:
  - `GET /v1/sys/health` → `200 {"initialized":true,"sealed":false}` — liveness only, **no store
    access**.
  - `GET /v1/secret/data/:path` → maps the path tail to `vault://:path`, calls `Vault::resolve(…, 300)`,
    and returns the **handle** in the Vault KV-v2 envelope
    `{"data":{"data":{"handle":…,"injection_mode":…},"metadata":{"ttl":…}}}` — **never the value**.
- **Side effects:** binds one loopback TCP port; spawns one OS thread per request. A read mints a
  single-use handle in the shared handle table (exactly as IPC `resolve` does).
- **Failure modes:** a **non-loopback** `--http-addr` (`0.0.0.0`, a LAN IP, `::`, unparseable) is
  **refused fail-closed** — logged to stderr, **no listener bound**, no wildcard exposure; the Unix
  socket keeps serving. **Absent `--http-addr` → no HTTP listener at all** (the default `serve`
  posture is unchanged). `inject`/`put`/`rotate`/`get`/`list` are **not routed** over HTTP — there is
  no method+path that reaches them; value delivery stays on the `SO_PEERCRED`-gated Unix socket.
  *(Pure decisions `http_route` / `loopback_only` / `kv2_envelope` in `src/http.rs`; tests
  `tc002_loopback_only_accepts_only_127`, `tc003_health_is_200_liveness_json`,
  `tc004_read_returns_handle_value_absent`, `shared_vault_put_is_readable_over_http`; ADR-006.)*

### B-018: Fail-closed HTTP read surface — every non-read maps to a Vault error shape

- **Trigger:** any request to the HTTP read surface that is not a routable `GET` read.
- **Response:** mapped to the Vault HTTP status + body so existing clients see familiar shapes:
  unknown secret (`no_such_secret`) → `404 {"errors":[]}`; unroutable path / empty `secret/data` tail
  → `404 {"errors":[]}`; non-GET method (POST/PUT/DELETE/…) → `405 {"errors":["method not allowed"]}`;
  malformed / over-long request (body over the 8 KiB bound) → `400 {"errors":["bad request"]}`; a
  handle-mint failure (`rng_error`) → `500 {"errors":["internal error"]}`.
- **Side effects:** none beyond the response; an over-long body is rejected at/under the bound, never
  buffered unbounded.
- **Failure modes:** fail-closed — **no HTTP path, success or error, delivers a secret value.** The
  only secret-derived datum that crosses the TCP boundary is the opaque handle, on a successful read.
  Method is decided **before** path read semantics (a POST to a valid read path is still `405`).
  *(Tests: `tc006_unknown_secret_is_404`, `tc007_non_get_is_405_mutation_unreachable`,
  `tc008_unroutable_get_is_404_admin_unreachable`, `tc009_request_size_bound_is_named`,
  `tc010_no_path_leaks_value`; ADR-006.)*

### B-019: Write-through the encrypted store on mutation (`--store-path`, atomic + 0600)

- **Trigger:** a successful `put` or `rotate` when `--store-path PATH` is set. (`resolve`/`inject`/
  `get`/`list` never trigger it.)
- **Response:** after the in-memory mutation succeeds, the **whole encrypted store** is serialized to
  `PATH` and written **atomically, `0600`, and safe-by-construction**: a temp file `<PATH>.tmp.<hex>`
  (random `/dev/urandom` suffix) in the same directory is created with `O_CREAT | O_EXCL |
  O_NOFOLLOW` and mode `0o600` set **at creation** (no chmod-after-open window, no predictable or
  follow-able temp path — SEC-001), then `write_all` + `fsync`, then an atomic `rename` over `PATH`,
  then an **`fsync` of the parent directory** so the rename is durable (SEC-002). The file holds the
  `StoredRecord` DTO per ref — base64 `ciphertext` + `nonce` + cleartext
  `injection_floor`/`binding`/`generation` — **never the key, never the cleartext, never any handle**
  (ADR-008 §2/§5/§6).
- **Side effects:** replaces the store file on disk; the prior file is left intact until the atomic
  rename. A crash mid-write leaves either the old complete file or the temp file — never a
  half-written store. A pre-existing temp path (planted symlink or stale temp) makes the write fail
  closed (`O_EXCL`/`O_NOFOLLOW`) rather than overwriting an attacker-chosen target (SEC-001).
- **Failure modes:** a failed write (disk full, permission, fsync error, a squatted/symlinked temp
  path) → the in-memory mutation is **rolled back** to its prior state and the op returns
  `{error:{code:"store_persist_failed",…}}` — never a silent success that diverges from disk. The
  temp file is best-effort removed and `PATH` is left intact. *(Tests: `tc006_store_file_is_0600`,
  `tc007_failed_persist_is_store_persist_failed_and_atomic`,
  `tc008_write_through_on_put_and_rotate_only`, `temp_file_is_created_0600_at_creation`,
  `temp_open_refuses_preexisting_path`, `temp_open_refuses_to_follow_symlink`; ADR-008 §4.)*

### B-020: Load the encrypted store on startup; refuse to start on corruption; handles never persist

- **Trigger:** `serve --store-path PATH` (or `VAULT_STORE_PATH`; the flag wins) at startup.
- **Response:** the store file is read and parsed (JSON → `version == 1` check → base64-decode each
  record into an `EncryptedValue`, nonce validated as 12 bytes) and the in-memory `store` is built as
  **ciphertext** — **no decryption at load**; decrypt stays at the `inject` edge (ADR-008 §7). The
  **handle table starts empty** — handles never persist (ADR-008 §5).
- **Side effects:** populates the in-memory store from disk; opens no decrypt path.
- **Failure modes:** a **missing** file is a fresh empty store (first run, not an error — the first
  `put` creates it). A **structurally corrupt** file (bad JSON / unknown version / invalid base64 /
  wrong-length nonce) makes `serve` **refuse to start** — a logged diagnostic and a non-zero exit
  (`1`), **no panic**, the store never silently emptied (ADR-008 §8). A **wrong master key** does
  *not* surface at load (ciphertext-only load) — it surfaces at the first `inject` as
  `decrypt_failed`; likewise a tampered-but-structurally-valid ciphertext loads fine and fails closed
  at `inject`. A **pre-restart handle** is dead after a restart → `unknown_handle` (handles never
  persist). *(Tests: `tc001_restart_round_trips_plaintext`,
  `tc002_key_never_on_disk_wrong_key_fails_at_inject`, `tc004_handles_do_not_persist`,
  `tc005_tamper_and_corrupt_fail_closed`; ADR-008 §7/§8.)*

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
- **The HTTP read surface is zero-knowledge, read-only, and loopback-only.** When enabled
  (`--http-addr 127.0.0.1:PORT`), a read returns the handle in a Vault KV-v2 envelope, never the
  value; no HTTP route reaches `inject`/`put`/`rotate`/`get`/`list`; a non-loopback bind is refused
  fail-closed; and absent the flag there is no HTTP listener at all. The two listeners are
  asymmetric by design: the Unix socket is `SO_PEERCRED`-gated with the full verb set, the HTTP
  surface is unauthenticated and therefore loopback + read-only (B-017, B-018, ADR-006).
- **On-disk persistence is opt-in, ciphertext-only, key-off-disk, handles-never-persist.** Unset
  `--store-path` ⇒ in-memory only, byte-for-byte today's behavior (no file read/written). Set ⇒ the
  encrypted store loads on startup and writes-through atomically on `put`/`rotate` (`0600`, temp +
  fsync + rename). The file carries AEAD ciphertext + nonce + non-secret metadata only — never the
  master key, never the cleartext, never a handle. A restart invalidates every outstanding handle
  (`unknown_handle`); a corrupt file refuses to start (no panic); a failed write surfaces
  `store_persist_failed` and rolls back (B-019, B-020, ADR-008).
