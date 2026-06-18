# vault — Authoritative Spec

**Project:** vault
**Last updated:** 2026-06-18

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of vault. It answers:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured — output of every task that changes externally-observable behavior, the
data model, an interface, or configuration; and input to onboarding, drift audits, and (in the
limit) regenerating the codebase. The code is one realization of this spec. If they disagree, one
is wrong — fix it in the same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour | Snapshot, human-readable |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

## The seven sub-files

| File | Covers |
|------|--------|
| [behaviors.md](behaviors.md) | What the system does — put, resolve (handle, no value), inject (proxy/env), raise-only floor, single-use binding, fail-closed errors, the IPC server, demo |
| [architecture.md](architecture.md) | C4 element catalog — persons, systems, the binary, its components |
| [data-model.md](data-model.md) | In-memory store + handle table, `Mode`/`Binding`, the resolve/inject wire shapes, error shape |
| [interfaces.md](interfaces.md) | CLI (`serve`/`demo`), the IPC protocol (`ping`/`put`/`resolve`/`inject`), the `Vault` core methods |
| [configuration.md](configuration.md) | `--socket`, socket permissions, injection floor / binding defaults, no secrets in repo |
| [fitness-functions.md](fitness-functions.md) | Proposed executable invariants (zero-knowledge resolve, raise-only floor, single-use, fail-closed, memory-safe path, uid-restricted socket) |

## Project summary

vault is the JIT zero-knowledge secret store + credential broker for the secure-agent ecosystem.
It answers *"does the agent core ever see a credential in plaintext?"* — and the answer is **no**.
The agent holds only an opaque, single-use **handle**; the plaintext is injected at the host
boundary into `exec-sandbox` at execution time, then wiped. vault coordinates with `policy-engine`
(it honors the raise-only `vault_injection_floor`), `exec-sandbox` (the injection edge), and
`audit-trail` (handle lifecycle, never the value). The interface is shaped to the
`vault://<scope>/<key>` scheme + Vault HTTP API path semantics — an adapter seam so a local
encrypted store, OpenBao, HashiCorp Vault, cloud KMS, or PKCS#11 HSM can sit behind it. v0 ships an
in-memory store + a `resolve`/`inject` broker over a uid-restricted Unix-socket IPC server, written
in Rust for memory safety on the secret path.

## Top-level invariants

- **The agent core never receives plaintext.** `resolve` returns `{handle, ttl, injection_mode}` —
  never the value; plaintext lives only in vault's memory and at the injection edge. *(Enforced in
  `src/vault.rs::resolve`; test `resolve_hides_value_and_inject_delivers_proxy`. Proposed fitness rule F-001.)*
- **Raise-only injection floor.** `inject`'s effective mode is `max(secret_floor, requested)` —
  vault raises (env→proxy), never lowers. *(Enforced in `src/vault.rs::inject`; test
  `floor_cannot_be_lowered`. Proposed fitness rule F-002.)*
- **Single-use handles + first-use sandbox binding.** A handle is consumed on first `inject` and
  bound to that sandbox; replays → `handle_consumed`, a different sandbox →
  `handle_bound_to_other_sandbox`. *(Enforced in `src/vault.rs::inject`; test `replay_is_rejected`.
  Proposed fitness rule F-003.)*
- **Fail-closed.** Unknown handle / secret / op, malformed request, or RNG failure → the structured
  error shape; no credential delivered. *(Enforced in the `err()` paths of `src/vault.rs` /
  `src/main.rs`. Proposed fitness rule F-004.)*
- **Memory-safe language for the secret path.** vault is Rust. *(Enforced by the language. Proposed
  fitness rule F-005.)*
- **Plaintext crosses only the uid-restricted socket.** The vault→proxy handoff (D5) travels a
  `0600` Unix socket, and every accepted connection is gated by a kernel-verified `SO_PEERCRED`
  peer-uid check — admit iff `peer_uid == server_uid` (equality, not privilege), fail-closed on an
  unreadable credential, before any op dispatches. *(Enforced in `src/main.rs::handle_conn` /
  `peer_uid_allowed`; ADR-002. Proposed fitness rule F-006.)*
- **Stable error shape.** IPC and core errors are `{error:{code,message,retryable}}`.

## Non-goals (current scope — v0)

These are stated as facts about what vault **is not yet**, not as a roadmap (planned work lives in
`docs/plans/` / `docs/tasks/`):

- **Not encrypted-at-rest.** The v0 store is in-memory plaintext — no AES-256-GCM + age /
  client-side encryption for store-level zero-knowledge yet.
- **Not TTL-enforcing.** `ttl` is stored on the handle but no auto-wipe clock enforces it
  (`#[allow(dead_code)] ttl` in `src/vault.rs`; `wiped_at` is a placeholder `0`).
- **Not fully admin-complete.** Only `put` is wired in the IPC dispatch; `get` / `list` / `rotate`
  are v1 contract verbs not yet implemented (`src/main.rs::dispatch`).
- **Not SPIFFE-bound / not Vault-HTTP-API-compatible / no cloud-KMS / HSM backends.** These sit
  behind the `vault://` seam but are not built.
- **Not an egress proxy.** vault delivers the credential to the injection edge; the egress proxy
  itself lives in `exec-sandbox`, not here.
