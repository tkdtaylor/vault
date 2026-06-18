# Architecture — C4 Element Catalog

**Project:** vault
**Last updated:** 2026-06-18

The structured catalog of architectural elements that
[`../architecture/diagrams.md`](../architecture/diagrams.md) renders. Tables here are the
machine-readable spec for the structure — a drift audit checks the code against them.

---

## 1. Persons (actors)

| Name | Description | Goals |
|------|-------------|-------|
| Autonomous agent core | The agent runtime that needs a credential to perform an action | Get a `resolve` handle (never the value) it can pass to exec-sandbox |
| Operator | Human running the daemon, seeding secrets, or running the demo | Start `serve`; `put` secrets; run `demo` to verify the single-use invariant |

---

## 2. Systems

| Name | Type | Description | Owner |
|------|------|-------------|-------|
| vault | In-scope | JIT zero-knowledge secret store + credential broker; `resolve`/`inject` | This team |
| exec-sandbox | External | Presents `{handle, sandbox_identity}` at spawn; receives the credential at the injection edge (egress proxy / env-setter) | secure-agent ecosystem |
| policy-engine | External | Emits the raise-only `vault_injection_floor` obligation vault honors | secure-agent ecosystem |
| audit-trail | External | Records the handle lifecycle; **never** the value | secure-agent ecosystem |

Note: the **value** crosses only the vault↔exec-sandbox injection edge. policy-engine influences
vault indirectly via the raise-only floor, honored as `max(secret_floor, requested)`.

---

## 3. Containers

| Name | Technology | Responsibility | Source path | Depends on |
|------|------------|----------------|-------------|------------|
| vault binary | Rust (edition 2021) single static binary | Store secrets **encrypted at rest** (AES-256-GCM), mint single-use handles (`resolve`), and broker credential delivery to the injection edge (`inject`); serve over a uid-restricted Unix socket (full verbs) plus an opt-in loopback-only read-only HTTP read surface (ADR-006), or a one-shot demo | `src/main.rs`, `src/vault.rs`, `src/crypto.rs`, `src/handle.rs`, `src/http.rs` | `serde`, `serde_json`, `nix` (socket+user, for `SO_PEERCRED`/`geteuid`), `aes-gcm` 0.10.3 (AES-256-GCM), `tiny_http` 0.12 (HTTP read surface) |

**Invariants for this table**
- The single container corresponds to the one binary crate `vault` (the single-binary layout,
  ADR-001 §2).
- Runtime dependencies are **`serde` + `serde_json` + `nix` + `aes-gcm` + `tiny_http`** (`nix` pulls
  `SO_PEERCRED`/`geteuid` for the peer-uid gate, ADR-002, minimal `socket`+`user` features;
  `aes-gcm` 0.10.3 supplies the at-rest AEAD, ADR-005, pinned to the stable line — the 0.11 RC was
  rejected — default features only; `tiny_http` 0.12 supplies the opt-in loopback HTTP read surface,
  ADR-006, sync thread-per-connection — no async runtime); randomness/nonces are `/dev/urandom` (no
  `rand` crate). Each added crate makes dep-scan / code-scanner blocking gates — the `nix` tree
  (ADR-002), the `aes-gcm` 0.10.3 tree (ADR-005), and the `tiny_http` 0.12 tree (ADR-006) were each
  dep-scan-cleared on adoption.

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| vault binary | CLI / IPC server | `src/main.rs` | Parse `serve`/`demo` subcommands, `--socket`, and the opt-in `--http-addr`; bind the `0600` Unix socket (remove stale first); gate every accept with the kernel-verified `SO_PEERCRED` peer-uid check (`peer_uid_allowed`, equality not privilege, fail-closed) before dispatch; frame newline-delimited JSON; dispatch `ping`/`put`/`get`/`list`/`rotate`/`resolve`/`inject` over an `Arc<Mutex<Vault>>`; when `--http-addr` is passed, spawn the HTTP read surface on a thread sharing the same `Arc<Mutex<Vault>>`; run the in-process demo | Vault broker, HTTP read surface |
| vault binary | HTTP read surface | `src/http.rs` | **Opt-in** (`--http-addr`), **loopback-only** (`loopback_only` admits only literal `127.0.0.1`, else fail-closed refuse — no wildcard bind), **read-only** HTTP server in the Vault KV-v2 API shape (`tiny_http`, thread-per-connection); `GET /v1/sys/health` → liveness (no store access) and `GET /v1/secret/data/:path` → `http_secret_ref` maps the tail to `vault://:path`, calls value-free `resolve`, packs the **handle** into the KV-v2 envelope (`kv2_envelope`) — **never the value**; fail-closed mapping (`http_route`/`http_response_for`): non-GET → 405, unroutable → 404, over-long → 400, unknown secret → 404; **no route to `inject`/`put`/`rotate`/`get`/`list`** (ADR-006) | Vault broker |
| vault binary | Vault broker | `src/vault.rs` | The in-memory store (ciphertext) + handle table; `put`/`get`/`list`/`rotate`/`resolve`/`inject`; **encrypt-on-put / decrypt-at-inject** via the `StoreBackend` seam; metadata-only admin verbs (`get`/`list`/`rotate` never return the value); the `Mode` (env/proxy, ranked), `Binding`, and `Clock` (injectable, `SystemClock` default) types; raise-only floor `max(secret_floor, requested)`; single-use + first-use sandbox binding; TTL expiry (`now >= expires_at`, `handle_expired`); rotate invalidates outstanding handles via a per-secret generation counter (`handle_invalidated`, ADR-004); fail-closed errors | At-rest crypto, Handle generator |
| vault binary | At-rest crypto | `src/crypto.rs` | The `StoreBackend` seam (store-encryption) + the production `AesGcmBackend` (AES-256-GCM); the `KeyProvider` seam + `EnvKeyProvider` (master key from `VAULT_MASTER_KEY`/`…_FILE`, decoded hex/base64 to 32 bytes, off the ciphertext, never logged); `EncryptedValue { ciphertext, nonce }`; fresh 96-bit nonce per `put`/`rotate` from `/dev/urandom`; decrypt fails closed (`decrypt_failed`) — never a silent wrong value (ADR-005). The store seam every future backend (OpenBao/KMS/HSM) replaces | `aes-gcm` |
| vault binary | Handle generator | `src/handle.rs` | `new_handle()` — 32 random bytes from `/dev/urandom` (OS CSPRNG), hex-encoded; the opaque single-use capability token | — (std only) |

---

## 5. Cross-cutting decisions

- **Zero-knowledge to the agent core** — `resolve` returns a handle, never the value; plaintext
  lives only in vault's memory and at the injection edge.
  ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **Raise-only injection floor** — `inject` delivers at `max(secret_floor, requested)`; never
  lowers. (ADR-001 §5)
- **Single-use handles + first-use sandbox binding (D5)** — consumed once, bound to the first
  sandbox; replays / other sandboxes rejected. (ADR-001 §6)
- **`vault://` backend adapter seam** — the `resolve`/`inject` contract + `vault://<scope>/<key>`
  scheme is backend-agnostic; the in-memory store can be swapped for an encrypted local store /
  OpenBao / cloud KMS / HSM without changing callers. (ADR-001 §4)
- **Fail-closed** — every non-delivery path resolves to a structured error; no credential delivered.
  (ADR-001 §8)
- **Memory-safe language** — Rust for the crown-jewel secret path. (ADR-001 §2)
- **Uid-restricted Unix socket** — the D5 handoff travels a `0600` socket, and every accept is gated
  by a kernel-verified `SO_PEERCRED` peer-uid check (admit iff `peer_uid == server_uid`, fail-closed)
  before dispatch (fitness F-006). (ADR-001 §6, §7; ADR-002)
- **Opt-in, loopback-only, read-only HTTP read surface** — a second listener (off by default; started
  only by `--http-addr 127.0.0.1:PORT`) speaks the Vault KV-v2 read **shape** but maps it onto
  value-free `resolve`, returning the **handle**, never the value. No HTTP route reaches
  `inject`/`put`/`rotate`/`get`/`list`; a non-loopback bind is refused fail-closed. The two listeners
  are asymmetric by design — Unix socket: `SO_PEERCRED`-gated, full verbs; HTTP: unauthenticated,
  loopback, read-only (fitness F-007). (ADR-006)

---

## Maintenance

- Update in the same commit as `../architecture/diagrams.md` when structure changes.
- Supersede in place; never append. The ADR carries the *why*.
- The drift-audit mode of the `architect` agent uses this catalog against the module graph and the
  deployable-artifact list. The dependency set (`serde` + `serde_json` + `nix` + `aes-gcm` +
  `tiny_http`) is recorded in Container §3 `Depends on`; a new crate (e.g. a crypto or HTTP
  dependency) updates that cell in the same commit.
