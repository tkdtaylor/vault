# Architecture Diagrams — vault

**Last updated:** 2026-06-21 (task 007 — opt-in persistent encrypted-on-disk store via the StoreFile layer, ADR-008)

C4-structured Mermaid diagrams plus the primary runtime sequence. See [overview.md](overview.md)
for prose context, [decisions/](decisions/) for the ADRs referenced here, and
[`../spec/architecture.md`](../spec/architecture.md) for the structured element catalog these
diagrams render.

These diagrams are part of the **authoritative spec**. Code changes that contradict a diagram
either invalidate the change or the diagram; one must be updated to match the other in the same commit.

> vault is a single deployable binary with three external integration classes: the agent core
> (resolve), exec-sandbox (inject, the injection edge), and policy-engine (raise-only floor it
> honors). Container and Component collapse into one diagram.

---

## 1. System Context — who uses it and what it touches

```mermaid
C4Context
    title System Context for vault

    System(agent, "Autonomous agent core", "Asks resolve(secret_ref) — receives a handle, NEVER the value")
    System(vault, "vault", "JIT zero-knowledge secret store + credential broker")
    Person(operator, "Operator", "Runs the daemon / a one-shot demo; puts secrets")

    System_Ext(sandbox, "exec-sandbox", "Presents {handle, sandbox_identity} at spawn; receives the credential at the injection edge")
    System_Ext(policy, "policy-engine", "Emits the raise-only vault_injection_floor obligation")
    System_Ext(audit, "audit-trail", "Records the handle lifecycle — never the value")

    Rel(agent, vault, "resolve(secret_ref)", "JSON / Unix socket — handle only")
    Rel(operator, vault, "serve / demo / put", "CLI")
    Rel(sandbox, vault, "inject(handle, sandbox_identity, mode)", "JSON / Unix socket — pull-triggered push")
    Rel(vault, sandbox, "credential + binding (proxy) | credential + var_name (env)", "injection edge only")
    Rel(policy, vault, "vault_injection_floor (raise-only)", "honored when computing effective mode")
    Rel(vault, audit, "handle lifecycle (no value)", "")
```

Note: the **value** crosses only the vault↔exec-sandbox injection edge. The agent core receives a
handle and nothing more. policy-engine influences vault indirectly via the raise-only floor it
emits; vault honors it as `max(secret_floor, requested)`.

---

## 2. Containers & Components — inside the binary

> One deployable unit (the static Rust binary). The load-bearing components a contributor touches first:

```mermaid
C4Component
    title Component view of vault (single binary)

    System(agent, "Autonomous agent core")
    System_Ext(sandbox, "exec-sandbox")
    Person(operator, "Operator")

    Container_Boundary(boundary, "vault binary") {
        Component(main, "CLI / IPC server", "src/main.rs", "serve & demo subcommands; bind 0600 Unix socket; SO_PEERCRED peer-uid gate (peer_uid_allowed) before dispatch; frame newline-delimited JSON; dispatch ping/put/get/list/rotate/resolve/inject; opt-in --http-addr starts the HTTP read surface; opt-in --store-path / VAULT_STORE_PATH loads the persistent encrypted store (refuse-to-start on corrupt file)")
        Component(http, "HTTP read surface", "src/http.rs", "OPT-IN, loopback-only (loopback_only=127.0.0.1, else fail-closed refuse), read-only Vault KV-v2 API shape; GET /v1/sys/health + GET /v1/secret/data/:path -> resolve -> HANDLE in KV-v2 envelope (NEVER the value); fail-closed 405/404/400; NO inject/put/rotate/get/list route; shares the same Arc<Mutex<Vault>>; pure http_route/http_secret_ref/kv2_envelope/http_response_for")
        Component(core, "Vault broker", "src/vault.rs", "store (ciphertext) + handle table; put/get/list/rotate/resolve/inject; encrypt-on-put / decrypt-at-inject; metadata-only admin verbs (never the value); raise-only floor max(secret_floor, requested); single-use + first-use sandbox binding; TTL expiry (now >= expires_at) via injectable Clock; rotate invalidates outstanding handles (per-secret generation); fail-closed errors")
        Component(crypto, "At-rest crypto", "src/crypto.rs", "StoreBackend seam + AES-256-GCM backend; KeyProvider seam (master key off the ciphertext, never logged); fresh 96-bit nonce per put/rotate from /dev/urandom; decrypt fails closed (decrypt_failed); hand-rolled base64 encode/decode for the store file")
        Component(storefile, "StoreFile (persistence)", "src/store_file.rs", "OPT-IN (--store-path / VAULT_STORE_PATH), ORTHOGONAL to StoreBackend (not a new backend); serializes already-encrypted EncryptedValue + non-secret metadata to a 0600 JSON file via the StoredRecord DTO (base64 ciphertext/nonce); load on startup (ciphertext only, NO decrypt) / write-through on put+rotate (atomic: temp+chmod-0600+fsync+rename); key NEVER on disk, handles NEVER persist; refuse-to-start on corrupt file; store_persist_failed on write error")
        Component(handle, "Handle generator", "src/handle.rs", "32 random bytes from /dev/urandom (OS CSPRNG), hex-encoded; opaque single-use capability token")
    }

    Rel(agent, main, "resolve", "JSON / Unix socket")
    Rel(sandbox, main, "inject", "JSON / Unix socket")
    Rel(operator, main, "serve / demo / put", "CLI")
    Rel(agent, http, "GET /v1/secret/data/:path", "HTTP / loopback TCP — handle only, opt-in")
    Rel(main, http, "spawn loopback listener when --http-addr is passed")
    Rel(main, core, "dispatch op -> put/get/list/rotate/resolve/inject")
    Rel(http, core, "GET read -> resolve (value-free); health = no store access")
    Rel(core, crypto, "encrypt on put/rotate; decrypt on inject (StoreBackend seam)")
    Rel(core, storefile, "load on startup (ciphertext only) / persist on put+rotate (--store-path); never handles, never key")
    Rel(storefile, crypto, "base64 encode/decode the EncryptedValue bytes (no decrypt)")
    Rel(core, handle, "new_handle() on resolve")
    Rel(core, sandbox, "credential delivered at inject (injection edge)")
```

> **Two inbound listeners, asymmetric by design (ADR-006).** The Unix socket is `SO_PEERCRED`-gated
> and carries the full verb set (including value delivery at `inject`). The HTTP read surface is
> **opt-in** (`--http-addr`), **loopback-only**, **read-only**, and **unauthenticated** — it maps a
> Vault KV-v2 read onto value-free `resolve` and returns the **handle**, never the value, and routes
> nothing to `inject`/`put`/`rotate`/`get`/`list`. The value still crosses **only** the
> uid-restricted Unix socket at the injection edge.

**Key contracts**
- `resolve(secret_ref, ttl) -> { handle, ttl, injection_mode }` returns the secret's floor as
  `injection_mode` and **never the value** (`src/vault.rs::resolve`, ADR-001 §1).
- `inject(handle, sandbox_id, requested) -> { credential, … }` is the only path the value crosses,
  and only to the injection edge. Effective mode is `max(secret_floor, requested)` — **raise-only**
  (ADR-001 §5). Single-use + first-use sandbox binding (ADR-001 §6).
- The `vault://<scope>/<key>` scheme is the **backend adapter seam** (ADR-001 §4); inside the binary
  the **`StoreBackend` trait** (ADR-005) is the store-encryption seam — the default AES-256-GCM
  backend can be swapped for an OpenBao / cloud KMS / HSM backend without changing `resolve`/`inject`.
- The stored value is **AES-256-GCM ciphertext at rest** (ADR-005): `put`/`rotate` encrypt with a
  fresh 96-bit nonce, `inject` decrypts at the edge, and the master key comes from a key-provider
  seam — never beside the ciphertext. A tampered ciphertext fails `decrypt_failed` (no value).
- **Persistence is opt-in and orthogonal to the StoreBackend seam** (ADR-008): the `StoreFile` layer
  (`src/store_file.rs`) serializes the *already-encrypted* `EncryptedValue`s + non-secret metadata to
  a `0600` JSON file via the `StoredRecord` DTO — **ciphertext only, key off disk, handles never
  persist**. It loads on startup (no decrypt) and writes-through atomically on `put`/`rotate`; a
  corrupt file refuses to start, a failed write surfaces `store_persist_failed`. Unset `--store-path`
  ⇒ in-memory only, today's behavior unchanged.
- Every unmatched path is **fail-closed** — a structured error, no credential delivered (ADR-001 §8).

---

## 3. Primary runtime flow — resolve → inject → wipe (incl. replay rejection)

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Agent core
    participant Vault as vault (src/vault.rs)
    participant Sandbox as exec-sandbox
    participant Edge as Injection edge (egress proxy / env-setter)

    Note over Agent,Vault: resolve — agent gets a handle, never the value
    Agent->>Vault: {"op":"resolve","secret_ref":"vault://test/api_key","ttl":300}
    alt secret unknown
        Vault-->>Agent: {"error":{"code":"no_such_secret",...}}
    else secret present
        Vault->>Vault: new_handle() (32 bytes /dev/urandom, hex)
        Vault->>Vault: store HandleRec{secret_ref, mode=floor, ttl, consumed=false, bound_sandbox=None}
        Vault-->>Agent: {"handle":"…","ttl":300,"injection_mode":"proxy"}
        Note over Agent: value is NOT in the response (zero-knowledge)
    end

    Note over Sandbox,Vault: inject — pull-triggered push at spawn
    Sandbox->>Vault: {"op":"inject","handle":"…","sandbox_identity":{"sandbox_id":"sbx-1"},"mode":"env"}
    alt unknown handle
        Vault-->>Sandbox: {"error":{"code":"unknown_handle",...}}
    else already consumed (replay)
        Vault-->>Sandbox: {"error":{"code":"handle_consumed",...}}
    else bound to a different sandbox
        Vault-->>Sandbox: {"error":{"code":"handle_bound_to_other_sandbox",...}}
    else valid first use
        Vault->>Vault: effective = max(secret_floor, requested)  (raise-only)
        Vault->>Vault: decrypt AES-256-GCM ciphertext (key from provider seam)
        alt ciphertext fails tag check (tampered/truncated/wrong key)
            Vault-->>Sandbox: {"error":{"code":"decrypt_failed",...}}  (no value, handle NOT consumed)
        else decrypt ok
            Vault->>Vault: bound_sandbox = "sbx-1", consumed = true
            alt effective == proxy
                Vault->>Edge: credential (decrypted) + binding{host,header,scheme}
                Vault-->>Sandbox: {"ok":true,"delivery":"proxy","credential":…,"binding":…}
                Note over Edge: value goes to the egress proxy ONLY — never into the sandbox
            else effective == env
                Vault->>Edge: credential (decrypted) as var_name (e.g. API_KEY)
                Vault-->>Sandbox: {"ok":true,"delivery":"env","credential":…,"var_name":…,"wiped_at":<unix_secs>}
                Note over Edge: wiped_at = inject-time clock (TTL enforced via injectable Clock, ADR-003)
            end
        end
    end

    Note over Sandbox,Vault: replay rejection — the same handle a second time
    Sandbox->>Vault: {"op":"inject","handle":"…",...}  (same handle)
    Vault-->>Sandbox: {"error":{"code":"handle_consumed",...}}  (single-use, D5)
```

The `demo` subcommand exercises this exact flow in-process (put → resolve → inject →
replay-rejected) without binding a socket — operator verification of the single-use handle
invariant.

> The store is **encrypted at rest** (AES-256-GCM, ADR-005): `put`/`rotate` encrypt the value with a
> fresh 96-bit nonce before it enters the store, and the decrypt step above is the only place the
> cleartext re-materialises. The **TTL auto-wipe clock** is enforced (env-mode `wiped_at` is the real
> inject-time clock, ADR-003), and the **SO_PEERCRED** peer-uid check gates every accept before
> dispatch (`peer_uid == server_uid`; socket is `0600` *and* kernel-peer-uid-gated, ADR-002).

ADRs governing this flow: [ADR-001](decisions/001-foundational-stack.md) (zero-knowledge resolve,
raise-only floor, single-use + first-use binding, uid-restricted socket, fail-closed),
[ADR-002](decisions/002-socket-peercred-check.md) (kernel-verified SO_PEERCRED peer-uid gate),
[ADR-003](decisions/003-ttl-auto-wipe-clock.md) (TTL expiry / injectable clock),
[ADR-004](decisions/004-admin-verbs-rotation-invalidation.md) (admin verbs + rotate-invalidation),
and [ADR-005](decisions/005-encrypted-at-rest-store.md) (AES-256-GCM encrypted-at-rest, key off the
ciphertext). Future backend adoptions swap only the store behind the `vault://` / `StoreBackend`
seam — this sequence shape, the IPC framing, and the handle/binding semantics are preserved.

---

## Maintaining these diagrams

- **Trigger to update:** a new actor/container/component appears; a boundary moves; an external
  integration is added or removed; an ADR changes a diagrammed flow. Keep
  [`../spec/architecture.md`](../spec/architecture.md) in sync.
- **Edit existing over adding new.** Duplicates rot independently.
- **Note ADRs that don't change diagrams.** An ADR that swaps the store behind the `vault://` seam
  leaves the System Context and runtime-sequence shape unchanged.
- **Update the date at the top** when you change anything substantive.
