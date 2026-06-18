# Fitness functions

**Project:** vault
**Last updated:** 2026-06-18

## What this file is

Fitness functions are **executable architectural invariants** — automated checks that verify the
code still obeys the rules vault commits to. This file is the declarative spec for those checks; the
implementation lives in the runner the rules point to.

## Status

There is **no `make fitness` / `cargo fitness` target wired yet** — `cargo build && cargo test`
(plus dep-scan / code-scanner for the supply chain) is the verification gate today. The rows below
are **proposed** (the security invariants the codebase implies). Promoting one to `active` means
adding its check command and wiring it into a `fitness` umbrella target, in the same commit as the
rule change.

## How to run (once wired)

```bash
make fitness          # run all fitness functions
make fitness-<rule>   # run one rule by name
```

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Status | Why this rule earns its row |
|----|------|----------|---------|-----------|---------------|----------|--------|----------------------------|
| F-001 | Zero-knowledge: `resolve` never returns the value | security | No `resolve` return path (or any error path) contains the secret value; the response is `{handle, ttl, injection_mode}` only | 0 value leaks from `resolve` | `make fitness-resolve-no-value` (TODO) | block | proposed | The whole purpose of vault is that the agent core never sees plaintext. A value in a `resolve` response is the exact leak vault exists to prevent (ADR-001 §1; test `resolve_hides_value_and_inject_delivers_proxy`). |
| F-002 | Injection floor is raise-only | security | No `inject` path delivers a mode lower than the secret's `injection_floor`; the effective mode is `max(secret_floor, requested)` | 0 lowering deliveries | `make fitness-floor-raise-only` (TODO) | block | proposed | Lowering the floor would let a caller weaken the credential posture policy-engine raised. The reconciliation rule is raise-only, never lower (ADR-001 §5; test `floor_cannot_be_lowered`). |
| F-003 | Single-use + first-use sandbox binding | security | A handle injects at most once and only from the sandbox it first bound to; replays → `handle_consumed`, other sandboxes → `handle_bound_to_other_sandbox` | 0 successful replays / cross-sandbox injects | `make fitness-handle-single-use` (TODO) | block | proposed | A replayable or transferable handle defeats the capability model — it would let a leaked handle be reused or stolen across sandboxes (ADR-001 §6, D5; test `replay_is_rejected`). |
| F-004 | Fail-closed on unknown handle/secret/op | security | Every non-delivery path (unknown handle, unknown secret, unknown op, malformed request, RNG failure) returns the structured error shape, never a credential | 0 deliver-on-error paths | `make fitness-fail-closed` (TODO) | block | proposed | Deliver-on-error is the classic credential-broker regression; the safe terminal state must always be a structured error with no value delivered (ADR-001 §8, behaviors B-006). |
| F-005 | Memory-safe language on the secret path | security | The secret-handling path stays in safe Rust — no `unsafe` blocks in `src/vault.rs` / `src/handle.rs` without a documented, reviewed justification | 0 unreviewed `unsafe` on the secret path | `make fitness-no-unsafe-secret-path` (TODO) | block | proposed | Memory safety is *why* vault is Rust — the crown-jewel path must not reintroduce the buffer-overrun / use-after-free leak class via casual `unsafe` (ADR-001 §2). |
| F-006 | Plaintext crosses only the uid-restricted socket | security | The `serve` socket is bound `0600` **and** (target) a SO_PEERCRED peer-uid check rejects other uids | socket `0600` present; **peer-uid check is a KNOWN GAP** | `make fitness-uid-restricted-socket` (TODO) | block | proposed (**partially enforced — gap**) | The D5 handoff relies on a uid-restricted channel. `0600` is in place (`src/main.rs::serve`); the SO_PEERCRED peer-uid check is **not yet wired** (needs the `nix` crate) — this row is partially enforced and tracks the gap until it closes. |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.

Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Handle-generation latency budget | Handle minting is one `/dev/urandom` read of 32 bytes — latency is a non-issue. Premature as a v0 rule. |
| Encrypted-at-rest assertion | The v0 store is intentionally in-memory plaintext (scoping). A fitness rule asserting encryption would fail by design until the encrypted store is built — track it as a limitation in the spec, not a red fitness row, until then. |

## Source-of-truth links

- F-001 ← [SPEC.md](SPEC.md) top-level invariants, ADR-001 §1, [behaviors.md](behaviors.md) B-002
- F-002 ← ADR-001 §5, [behaviors.md](behaviors.md) B-005, [data-model.md](data-model.md) `Mode`
- F-003 ← ADR-001 §6, [behaviors.md](behaviors.md) B-004
- F-004 ← ADR-001 §8, [behaviors.md](behaviors.md) B-006, [data-model.md](data-model.md) error shape
- F-005 ← ADR-001 §2, [architecture.md](architecture.md) §3
- F-006 ← ADR-001 §6/§7, [configuration.md](configuration.md) socket permissions

## Notes

- These rules are vault's commitments, not generic best practice. Each guards a stated invariant in
  the spec; a violation breaks a security promise, not just style.
- They are `proposed` until the operator confirms and the check command exists. Don't claim a rule
  is enforced until its check command runs.
- **F-006 is explicitly partial** — `0600` is enforced today, the SO_PEERCRED peer-uid check is a
  known gap. Do not mark F-006 fully active until the peer-uid check is wired.
