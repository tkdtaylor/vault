# Architecture Overview — vault

**Last updated:** 2026-06-18

## System purpose

vault is the **JIT zero-knowledge secret store + credential broker** for the secure-agent
ecosystem. It answers a single question on the agent's hot path:

> Does the agent core ever see a credential in plaintext?

The answer is **no**. The agent core holds only an opaque, single-use **handle**; the plaintext
value is injected **at the host boundary, into `exec-sandbox`, at the moment of execution**, then
wiped. The credential never enters the agent's context, its logs, or `audit-trail`.

vault coordinates with the other ecosystem blocks: `policy-engine` may **raise** vault's
injection floor (env→proxy) via an obligation but never lower it; `exec-sandbox` is the injection
edge that presents `{handle, sandbox_identity}` at spawn and receives the credential; `audit-trail`
records the handle's lifecycle but never the value.

The interface is shaped to the **`vault://<scope>/<key>` scheme + Vault HTTP API path semantics**.
That shape is a deliberate adapter seam: the v0 store is a trivial in-memory map, but a local
encrypted store, OpenBao, HashiCorp Vault, a cloud KMS, or a PKCS#11 HSM can be slotted behind the
same `resolve`/`inject` contract without changing any caller.

## Component map

A single Rust binary crate (`vault`, edition 2021):

| File | Responsibility |
|------|----------------|
| `src/main.rs` | CLI entrypoint. Dispatches the `serve` and `demo` subcommands; binds the uid-restricted Unix socket; frames newline-delimited JSON; dispatches `ping`/`put`/`resolve`/`inject`. |
| `src/vault.rs` | The `Vault` core and its `put` / `resolve` / `inject` methods — the broker. Holds the in-memory store and handle table; defines `Mode` (env/proxy) and `Binding`; enforces the raise-only floor and single-use binding. The single seam every future backend replaces. Inline `#[cfg(test)] mod tests`. |
| `src/handle.rs` | Capability-handle generation: 32 random bytes from `/dev/urandom` (OS CSPRNG), hex-encoded, opaque, single-use. |
| `Cargo.toml` | Crate manifest — `serde` + `serde_json` only. |

## Data flow

```
agent ──resolve(secret_ref)──▶ vault                exec-sandbox ──inject(handle, sandbox_id)──▶ vault
                                 │  mint handle                                                    │  validate binding,
                                 ▼  (NOT the value)                                                ▼  enforce single-use,
                          { handle, ttl, injection_mode }                                   { credential, binding } ──▶ egress proxy (proxy)
                                                                                            { credential, var_name } ─▶ env-setter (env)
```

The agent receives only a handle from `resolve`. At execution time, `exec-sandbox` presents the
handle plus its sandbox identity; vault validates the handle↔sandbox binding, enforces single-use,
computes the effective mode `max(secret_floor, requested)`, and delivers the credential **to the
injection edge only** — the egress proxy (proxy mode, value never enters the sandbox) or the
env-setter (env mode). A replayed handle, an unknown handle, or a different sandbox is rejected
with the structured error shape. The plaintext lives only in vault's memory and at that injection
edge.

The `demo` subcommand runs the same put→resolve→inject→replay-rejected flow in-process for
operator verification, without binding a socket.

## Key dependencies

**Two runtime dependencies only** — `serde` + `serde_json` (JSON over the socket). Randomness
comes from the OS CSPRNG via `/dev/urandom`, deliberately **without a `rand` crate** (no userspace
state to seed, smallest attack surface). vault is written in **Rust** specifically because the
secret-handling path is the crown jewel: memory safety by construction removes the buffer-overrun
class of leaks. The v1 path will introduce a crypto crate for encrypted-at-rest (AES-256-GCM +
age) behind the store seam — a future ADR, not present today.

## Entry points

- `vault serve --socket <path>` — long-running IPC daemon; binds a `0600` Unix socket and serves
  `ping` / `put` / `resolve` / `inject`.
- `vault demo` — one-shot in-process put→resolve→inject→replay-rejected; operator verification of
  the single-use handle invariant (D5). Exit code `2` on a missing/unknown subcommand.

## Key decisions

- **Zero-knowledge to the agent core** is the central architectural commitment — `resolve` returns
  a handle, never the value; the plaintext lives only at the injection edge.
- **Raise-only injection floor** — `inject` computes `max(secret_floor, requested)`; vault can
  tighten credential handling (env→proxy), never loosen it.
- **Single-use handles + first-use sandbox binding** — the secured vault→proxy handoff (D5): an
  unguessable capability token, consumed once, bound to the first sandbox that uses it.
- **Memory-safe language** — Rust for the secret path.
- **`vault://` + Vault HTTP API adapter seam** — the request/response contract is backend-agnostic
  so the store can be swapped (in-memory → encrypted local → OpenBao / cloud KMS / HSM) without
  touching callers.
- **Single-binary Rust layout** — `src/main.rs` + two modules, not a workspace; the broker is small
  and deploys as one static binary alongside the agent.

The full as-built record of these decisions is
[ADR-001 — Foundational stack](decisions/001-foundational-stack.md). Future decisions get their own
sequential ADRs.

## Current limitations (v0)

vault is a **v0 skeleton against the v1 contract**. The following are *not yet* present — stated as
facts, not a roadmap (planned work lives in `docs/plans/` / `docs/tasks/`):

- The store is **in-memory plaintext** — no encryption-at-rest (AES-256-GCM + age / client-side
  encryption for store-level zero-knowledge).
- **TTL is stored but not enforced** — there is no auto-wipe clock (`#[allow(dead_code)] ttl` in
  `src/vault.rs`; `wiped_at` is a placeholder `0`).
- **SO_PEERCRED peer-uid check is missing** — the socket is `0600` but the full D5 scheme also calls
  for a peer-uid check (needs the `nix` crate).
- **`get` / `list` / `rotate` admin verbs are unwired** — only `put` is dispatched in
  `src/main.rs::dispatch`; the others are v1 contract verbs not yet implemented.
- **SPIFFE identity binding, Vault HTTP API compatibility, and cloud-KMS / HSM backends** are
  behind the `vault://` seam but not yet built.

## Design principles

vault follows **Unix philosophy** — composability over monolithic design. The full statement lives
in `CLAUDE.md`; the load-bearing instance here is the `vault://` backend seam: a small,
well-defined contract that lets independently-evolving store implementations plug in without
entanglement. The secret-handling core itself is deliberately cohesive (a monolithic choice for
correctness on the crown-jewel path) — composability lives at the cross-module boundary, not inside
the broker.
