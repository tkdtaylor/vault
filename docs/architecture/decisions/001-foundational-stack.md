# ADR-001 — Foundational stack (as-built)

**Status:** Accepted
**Date:** 2026-06-18

## Context

vault predates this ADR process: the v0 skeleton (`src/main.rs`, `src/vault.rs`, `src/handle.rs`,
`Cargo.toml`) was committed before the project adopted the create-project workflow. This bootstrap
ADR consolidates the decisions the codebase **already commits to** as of 2026-06-18, so that
subsequent ADRs have a coherent baseline to amend rather than free-floating in a vacuum.

It does **not** back-number every prior micro-decision into fiction. It records the foundational
stack as observed in the source. Future ADRs (ADR-002, …) supersede or refine individual points.

The authoritative design rationale lives in `vault.md` and
`interface-contracts.md §2 (v1)`, and was validated by the tracer-bullet (A2/A3 + the vault→proxy
handoff micro-test, D5). This ADR records what is *built*, not the full prior-art survey. Prior-art
verdict: **BUILD (clean-room)** — OpenBao / HashiCorp Vault (Vault HTTP API semantics) and
AgentSecrets are reference designs and pluggable backends behind the `vault://` seam.

## Decisions

### 1. Zero-knowledge to the agent core (the central commitment)

The agent core must **never** see a plaintext credential — not in context, not in logs, not in
`audit-trail`. The agent's only reference to a secret is an opaque, single-use **handle**.
`resolve` mints the handle and returns `{ handle, ttl, injection_mode }` — **never the value**
(`src/vault.rs::resolve`). The plaintext is delivered only at the **injection edge** — vault's own
memory plus `inject` → exec-sandbox's egress proxy (proxy mode) or env-setter (env mode). This is
the central security commitment; everything else serves it.

### 2. Language & packaging — Rust single binary crate

- Crate `vault`, edition 2021, a single binary (`src/main.rs` + `src/vault.rs` + `src/handle.rs`),
  **not** a workspace. The broker is small and deploys as one static binary alongside the agent.
- **Rust specifically** because the secret-handling path is the crown jewel: memory safety by
  construction removes the buffer-overrun / use-after-free class of credential leaks.
- **Two runtime dependencies only** — `serde` + `serde_json` (the wire format). The smallest
  possible attack surface for a block that holds secrets.
- Build/test tooling: `cargo build`, `cargo test` (tests inline as `#[cfg(test)] mod tests` in
  `src/vault.rs`). No `make check` / `make fitness` target yet.

### 3. Randomness — `/dev/urandom`, no RNG crate

Capability handles are 32 random bytes read from `/dev/urandom` (the OS CSPRNG), hex-encoded
(`src/handle.rs`). No third-party RNG crate, no userspace state to seed. The handle is unguessable,
opaque, and the agent's only reference to a secret (D4). Avoiding a `rand` crate keeps the
dependency surface minimal on the crown-jewel path.

### 4. Interface contract — `resolve` / `inject` (the v1 contract)

```
resolve(secret_ref, requester_identity) -> { handle, ttl, injection_mode }       # NOT the value
inject(handle, sandbox_identity, mode)  -> proxy: { ok, delivery, credential, binding{host,header,scheme} }
                                           env:   { ok, delivery, credential, var_name, wiped_at }
put | get | list | rotate (admin)
```

The `credential` + `binding` on the `inject` response is the v0→v1 change the tracer-bullet
surfaced (A7): exec-sandbox's proxy needs them to actually inject. They cross only the
uid-restricted vault socket — the injection edge.

The `vault://<scope>/<key>` scheme plus Vault HTTP API path semantics is an **adapter seam**: the
v0 store is an in-memory map, but a local encrypted store, OpenBao, HashiCorp Vault, cloud KMS, or
a PKCS#11 HSM can slot behind the same contract without changing callers. The egress proxy lives in
`exec-sandbox`, not here.

> Note: only `put` is wired in the IPC dispatch (`src/main.rs::dispatch`) as of 2026-06-18.
> `get` / `list` / `rotate` are v1 contract verbs **not yet implemented** — a known gap, not a
> contract change.

### 5. Injection modes & the raise-only floor

Two injection modes (`src/vault.rs`):

| Mode | Rank | Delivery |
|------|------|----------|
| `env` | 0 | credential set as an env var (`var_name`) in the sandbox; `wiped_at` placeholder |
| `proxy` | 1 (stronger) | credential delivered to exec-sandbox's egress proxy with a `binding`; **value never enters the sandbox** |

`proxy` is stronger than `env` (the value never enters the sandbox). `inject` computes the
effective mode as `max(secret_floor, requested)` — vault may **RAISE** the floor (env→proxy),
**never lower** it (fail-closed). This is the raise-only invariant policy-engine's
`vault_injection_floor` obligation relies on. Enforced in `src/vault.rs::inject`; test
`floor_cannot_be_lowered`.

### 6. Single-use handles + first-use sandbox binding (D5)

A handle is **single-use**: consumed on first `inject`. It is **bound to the first sandbox** that
injects it. A replayed handle → `error.code = handle_consumed`; a different sandbox →
`handle_bound_to_other_sandbox`. Enforced in `src/vault.rs::inject`; test `replay_is_rejected`.

The **vault→proxy handoff (D5)** is secured by three properties together: a **uid-restricted Unix
socket** (`0600`) + an **unguessable single-use capability handle** + **first-use sandbox binding**.
The plaintext lives only at the injection edge.

> Note: a **SO_PEERCRED peer-uid check** on the socket is part of the full D5 scheme but is **not
> yet** wired (needs the `nix` crate) — `src/main.rs::serve` sets `0600` only. Tracked as fitness
> rule F-006 and stated as a limitation in the spec.

### 7. IPC transport — newline-delimited JSON over a uid-restricted Unix socket

`serve --socket <path>` removes any stale socket, binds a Unix socket, and `chmod 0600`
(`src/main.rs::serve`). Each connection sends one newline-delimited JSON object `{op, …}`; ops are
`ping`, `put`, `resolve`, `inject`. Responses are newline-delimited JSON: the verb's result, or a
structured error `{error:{code,message,retryable}}` for bad/unknown requests. The server spawns a
thread per connection over an `Arc<Mutex<Vault>>`.

### 8. Fail-closed posture

Denial is the default. An unknown handle (`unknown_handle`), an unknown secret (`no_such_secret`),
a consumed handle (`handle_consumed`), a wrong sandbox (`handle_bound_to_other_sandbox`), an RNG
failure (`rng_error`), a malformed request (`bad_request`), or an unknown op (`unknown_op`) all
resolve to the structured error shape — nothing is delivered. Delivering a credential is the
justified exception, never the fallback.

### 9. License — Apache-2.0

vault is licensed **Apache-2.0** (`Cargo.toml` `Apache-2.0`). Open-source and free to use,
modify, and distribute, including in commercial and proprietary products; contributions are
inbound=outbound under Apache-2.0 §5 (no CLA, DCO sign-off required).

## Consequences

- The zero-knowledge guarantee (the agent core never sees plaintext) holds as long as `resolve`
  stays value-free and the injection floor stays raise-only. Any future convenience path that
  returns or logs a value is a regression to flag, not ship.
- The `vault://` seam means adopting an encrypted store or an external backend is an *additive*
  change behind `resolve`/`inject` — no agent, no exec-sandbox client changes.
- The minimal-dependency property (`serde` + `serde_json` only) ends when a crypto crate is added
  for encrypted-at-rest; that is the moment dep-scan and code-scanner become blocking gates
  (recorded in CLAUDE.md → Recommended tooling).
- The v0 store being in-memory plaintext, TTL being stored-but-unenforced, and the missing
  SO_PEERCRED check are accepted v0 scoping — each is recorded as a limitation in the spec and (for
  the security gaps) a fitness row, so they are tracked rather than forgotten.

## Open questions

- **Encrypted-at-rest mechanism** — AES-256-GCM + age vs. client-side encryption for store-level
  zero-knowledge, and which crypto crate. **Not decided here** — a future ADR once the encrypted
  store is real.
- **TTL clock** — where the auto-wipe clock lives (in-process timer vs. lazy-on-access expiry) is
  open; `ttl` is stored now for the eventual clock (`src/vault.rs` `HandleRec.ttl`).
- **Identity model** — `requester_identity` / `sandbox_identity` are string-shaped today; SPIFFE
  SVID binding is a future ADR.
