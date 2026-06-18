# Task 003: Wire get / list / rotate admin verbs (metadata-only)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Implement the contract's admin verbs `get`, `list`, and `rotate` in the IPC dispatch. Today only
`put` is wired in `src/main.rs` `dispatch`; the other three are defined in the contract
(`docs/CONTRACT.md` §Verbs) but unreachable. All three are **value-free** — they return metadata
only, never the secret value.

## Context

- Tech stack: Rust, `serde`-only. Dispatch in `src/main.rs` (`dispatch`); core in `src/vault.rs`.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md). No new ADR
  expected unless rotation introduces a non-obvious invalidation rule (then add **ADR-004**).
- Reference: [`docs/CONTRACT.md`](../../CONTRACT.md) (`put | get | list | rotate` — "return
  metadata, never the value"), [`docs/spec/interfaces.md`](../../spec/interfaces.md),
  [`docs/spec/behaviors.md`](../../spec/behaviors.md), [roadmap](../../plans/roadmap.md) v1 row 3.
- Dependencies: none.
- **Constraint:** the **value never appears** in any `get`/`list`/`rotate` response. Do not change
  `resolve`/`inject` semantics. Fail-closed on unknown `secret_ref`.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `get{secret_ref}` returns the secret's metadata (`{exists:true, injection_floor, binding}`) and **never** the value; unknown ref → `{error:{code:"no_such_secret",…}}` (fail-closed). | must have |
| REQ-002 | `list` returns the set of stored `secret_ref`s (and optionally their floors), **never** any value. | must have |
| REQ-003 | `rotate{secret_ref, value}` replaces the stored value in place, preserving `injection_floor` + `binding`, and returns metadata only (no value echoed back); unknown ref → `no_such_secret`. | must have |
| REQ-004 | Rotation invalidates outstanding handles for that `secret_ref` (a handle resolved against the old value must not inject the new one) **or** the chosen semantics are explicitly documented; the safe default is invalidate-on-rotate. | must have |
| REQ-005 | All three verbs are reachable over the IPC socket and via the in-process API; unknown op still → `unknown_op`. | must have |

## Readiness gate

- [x] Test spec `003-admin-verbs-get-list-rotate-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No blocking tasks

## Acceptance criteria

- [ ] [REQ-001] `get` on a seeded ref returns floor+binding, no value; unknown ref → `no_such_secret` (TC-001, TC-002).
- [ ] [REQ-002] `list` returns the stored refs with no values present in the response (TC-003).
- [ ] [REQ-003] `rotate` swaps the value, keeps floor+binding, echoes no value (TC-004).
- [ ] [REQ-004] After `rotate`, a pre-rotation handle cannot inject the new value (invalidated) — or
      the documented alternative is asserted (TC-005).
- [ ] [REQ-005] All three verbs round-trip over the Unix socket (TC-006).
- [ ] No response from any admin verb contains the secret value (grep-level assertion) (TC-007).
- [ ] `cargo build && cargo test` green; v0 tests unchanged and passing.

## Verification plan

- **Highest level achievable:** L6 — runtime-observable over the socket.
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. the value-absence assertions.
- **Level 6 — Operator observation:** against `vault serve`, send `{"op":"put",…}` then
  `{"op":"get","secret_ref":"vault://test/api_key"}` → metadata only; `{"op":"list"}` → refs;
  `{"op":"rotate","secret_ref":…,"value":…}` → metadata only; confirm no value in any response.
