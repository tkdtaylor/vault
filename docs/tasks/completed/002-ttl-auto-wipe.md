# Task 002: TTL auto-wipe clock — enforce handle TTL + env wiped_at

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Enforce the handle `ttl` that is currently stored but unused (`#[allow(dead_code)] ttl` in
`src/vault.rs`): a handle that is injected after its TTL has elapsed is rejected, and the env-mode
`inject` response carries a real `wiped_at` timestamp instead of the `0` placeholder.

## Context

- Tech stack: Rust, `serde`-only. Core broker `src/vault.rs` (`resolve` stores `ttl`; `inject`
  returns `wiped_at: 0`). Entry point `src/main.rs`.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md). This task
  introduces **ADR-003** for the injectable clock + expiry-vs-single-use ordering decision.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (resolve/inject, fail-closed),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (`HandleRec.ttl`),
  [roadmap](../../plans/roadmap.md) v1 row 2.
- Dependencies: none. **No new crate required** — use `std::time` (`SystemTime`/`Instant`); keep
  the dependency floor at `serde`. Introduce a small injectable clock trait/function so tests are
  deterministic without sleeping.
- **Constraint:** do NOT change the single-use / sandbox-binding semantics; TTL is an *additional*
  rejection reason layered before delivery. The raise-only floor and "resolve never returns value"
  invariants are untouched.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `resolve` records an expiry derived from `ttl` (e.g. `expires_at = now + ttl`) on the handle record. | must have |
| REQ-002 | `inject` on a handle whose TTL has elapsed returns `{error:{code:"handle_expired",…}}` and does **not** deliver the credential. | must have |
| REQ-003 | `inject` within the TTL window delivers normally (no behavior change on the happy path). | must have |
| REQ-004 | The env-mode `inject` response sets `wiped_at` to a real timestamp (the moment the credential is handed to the env-setter / its scheduled wipe), not `0`. | must have |
| REQ-005 | The clock is injectable so expiry is tested deterministically (no real sleeping); production uses the system clock. | must have |
| REQ-006 | Ordering is well-defined and fail-closed: an expired handle is rejected as `handle_expired` regardless of single-use state; an already-consumed handle still returns `handle_consumed`. The precedence is documented in ADR-003. | must have |

## Readiness gate

- [x] Test spec `002-ttl-auto-wipe-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No blocking tasks

## Acceptance criteria

- [ ] [REQ-001] A resolved handle carries an expiry computed from its TTL (TC-001).
- [ ] [REQ-002] Injecting after expiry → `handle_expired`, no credential in the response (TC-002).
- [ ] [REQ-003] Injecting before expiry → normal `proxy`/`env` delivery (TC-003).
- [ ] [REQ-004] env-mode `wiped_at` is a real non-zero timestamp consistent with the inject time (TC-004).
- [ ] [REQ-005] Expiry is exercised via an injected clock; tests do not sleep (TC-002, TC-005).
- [ ] [REQ-006] Precedence: expired+unconsumed → `handle_expired`; consumed → `handle_consumed`;
      documented in ADR-003 (TC-006).
- [ ] `cargo build && cargo test` green; v0 tests in `vault.rs` unchanged and passing.

## Verification plan

- **Highest level achievable:** L5 — validation harness (deterministic clock makes expiry fully
  unit-observable). L6 optional via `demo`/socket with a short TTL.
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. the expiry, wiped_at, and precedence tests.
- **Level 6 — Operator observation (optional):** `resolve` with `ttl=1`, advance the injected clock
  (or wait), then `inject` → observe `{"error":{"code":"handle_expired"}}` over the socket.
