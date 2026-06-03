# vault — project instructions

JIT zero-knowledge secret store + credential broker. The agent core must **never** see a
plaintext credential. Rust. PolyForm Noncommercial 1.0.0.

## The one invariant

The plaintext value may exist only in: vault's own memory/store and the **injection edge**
(vault broker + exec-sandbox's egress proxy). It must never reach the agent core, its
context, its logs, or `audit-trail`. The agent holds only an opaque single-use `handle`.

## Contract (v1 — don't break without a contracts bump)

- `resolve(secret_ref, requester_identity) -> {handle, ttl, injection_mode}` (no value)
- `inject(handle, sandbox_identity, mode) -> {ok, delivery, credential, binding|var_name, …}`
- **Fail-closed:** effective mode = `max(secret_floor, policy_raised)`. vault may RAISE the
  injection floor (env→proxy), **never lower** it.
- **Single-use + first-use binding:** a handle is consumed on first inject and bound to that
  sandbox; replays / other sandboxes are rejected (D5, validated by the tracer-bullet).

Authoritative spec: the project's internal design notes +
`interface-contracts.md` (v1). Validated by the tracer-bullet reference.

## Conventions

- `cargo build` / `cargo test` stay green. Keep dependencies minimal (currently serde +
  serde_json; RNG via `/dev/urandom`, no `rand` crate).
- Never log a secret value. Never return it from `resolve`. Error shape:
  `{error:{code,message,retryable}}`.

## Roadmap (v1+)

Encrypted-at-rest store (AES-256-GCM + age, client-side encryption for store-level
zero-knowledge) · TTL auto-wipe · SO_PEERCRED peer-uid check · SPIFFE identity binding ·
Vault HTTP API compatibility · OpenBao / cloud-KMS / PKCS#11 backends behind the `vault://`
seam.
