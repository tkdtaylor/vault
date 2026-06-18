# Behaviors

**Project:** vault
**Last updated:** 2026-06-18

What the system does, observably — triggering condition, response, externally-visible side
effects, failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry
points* ([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Store a secret (admin `put`)

- **Trigger:** `{"op":"put","secret_ref":…,"value":…,"injection_floor":"env|proxy","binding":{…}}`
  over IPC, or `Vault::put(secret_ref, value, floor, binding)` in-process.
- **Response:** the secret is inserted into the in-memory store keyed by `secret_ref`, carrying its
  `injection_floor` (the minimum mode any later `inject` may deliver) and its `Binding`. IPC returns
  `{"ok":true}`.
- **Side effects:** mutates the in-memory store; nothing is persisted (v0 store is in-memory).
- **Failure modes:** an absent `injection_floor` defaults to `env`; an absent/invalid `binding`
  defaults to `{host:"", header:"Authorization", scheme:"Bearer", env_var:"API_KEY"}`. The value
  is **never** logged or echoed.

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
- **Response:** validates the handle, enforces single-use and the handle↔sandbox binding (B-004),
  computes the **effective mode** `max(secret_floor, requested)` (B-005), marks the handle consumed
  and bound to this sandbox, and delivers the credential **to the injection edge only**:
  - `proxy` → `{ "ok":true, "delivery":"proxy", "credential":…, "binding":{host,header,scheme,env_var} }`
    — the value goes to exec-sandbox's egress proxy, never into the sandbox.
  - `env` → `{ "ok":true, "delivery":"env", "credential":…, "var_name":…, "wiped_at":0 }` — the
    value is set as the named env var in the sandbox.
- **Side effects:** mutates the handle record (`consumed=true`, `bound_sandbox=<sandbox_id>`); the
  credential crosses only the uid-restricted socket to the injection edge.
- **Failure modes:** see B-006 (unknown handle, replay, wrong sandbox) — all fail closed with the
  structured error shape; no credential delivered.

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

### B-006: Reject a malformed, unknown, or unsupported request (fail-closed)

- **Trigger:** a denied peer uid, unparseable JSON, an unknown `op`, an unknown handle, an unknown
  secret, a consumed handle, a wrong sandbox, or an RNG failure.
- **Response:** the structured error shape `{error:{code,message,retryable:false}}`. Codes in use:
  `peer_uid_denied` (peer uid ≠ server uid, or unreadable peer cred — B-010), `bad_request`
  (unparseable JSON), `unknown_op` (unsupported op), `no_such_secret`, `unknown_handle`,
  `handle_consumed`, `handle_bound_to_other_sandbox`, `rng_error`.
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
- **Every non-delivery path fails closed.** A denied peer uid, unknown handle/secret/op, malformed
  request, or RNG failure → the structured error shape; never a delivered credential.
- **The socket admits only the server's own uid.** Every accepted connection is gated by a
  kernel-verified `SO_PEERCRED` check (`peer_uid == server_uid`, equality not privilege) before any
  op is dispatched; an unreadable peer credential is denied (fail-closed). This is the
  kernel-verified half of the D5 uid restriction (the `0600` mode is the file-mode half).
- **The value is never logged.** No `put`, `resolve`, `inject`, or error path emits the credential
  to stderr/stdout (except the `inject` delivery itself, which is the injection edge by design).
