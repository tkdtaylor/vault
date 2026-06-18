# Task 001: SO_PEERCRED peer-uid check on the Unix socket

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Add a kernel-level **peer-uid assertion** (`SO_PEERCRED`) to the vault IPC socket so a connecting
caller's uid is *verified*, not merely inferred from the 0600 file permission. This completes the
D5 vault→proxy handoff scheme (uid-restricted socket + unguessable single-use handle + first-use
sandbox binding), closing the gap noted in `src/main.rs` (`NOTE v1 hardening: add an SO_PEERCRED
peer-uid check`).

## Context

- Tech stack: Rust, single binary, `serde`-only today. Entry point `src/main.rs` (`serve` /
  `handle_conn`); core broker `src/vault.rs`; handles `src/handle.rs`.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (as-built stack,
  Unix-socket JSON IPC, fail-closed, D5 handoff). This task introduces **ADR-002** to record the
  peer-uid check and the new `nix` (or equivalent) dependency.
- Reference: [`docs/spec/interfaces.md`](../../spec/interfaces.md) (the `serve` socket),
  [`docs/spec/behaviors.md`](../../spec/behaviors.md) (fail-closed paths), [`docs/CONTRACT.md`](../../CONTRACT.md)
  (D5: "SO_PEERCRED peer-uid check is v1"), [roadmap](../../plans/roadmap.md) v1 row 1.
- Dependencies: none (first v1 task).
- **Constraint:** do NOT change the `resolve`/`inject`/`put` semantics in `vault.rs` or the handle
  logic in `handle.rs`. This is a socket-acceptance hardening in `main.rs` only.
- **Ask-first:** adding the `nix` crate (for `SO_PEERCRED`/`getsockopt`) is a new dependency — it
  must clear dep-scan and be recorded in ADR-002 (vault's whole point is a minimal, auditable path).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | On each accepted connection, the server reads the peer credential (`SO_PEERCRED`) and obtains the connecting process's uid. | must have |
| REQ-002 | If the peer uid does not match the server process's own effective uid, the connection is **rejected fail-closed** — no op is dispatched; the socket returns a structured `{error:{code:"peer_uid_denied",…}}` (or closes) and nothing from `vault.rs` runs. | must have |
| REQ-003 | A same-uid peer is accepted and dispatched exactly as before (no behavior change on the happy path). | must have |
| REQ-004 | The check is fail-closed: if the peer credential cannot be read, the connection is rejected, not allowed. | must have |
| REQ-005 | The peer-uid check is a testable unit (a function taking a uid + server uid → allow/deny) independent of an actual socket, so it can be tested without spawning a second-uid process. | must have |

## Readiness gate

- [x] Test spec `001-socket-peercred-check-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No blocking tasks

## Acceptance criteria

- [ ] [REQ-001] The server obtains the peer uid via `SO_PEERCRED` on an accepted Unix-socket
      connection (TC-001).
- [ ] [REQ-002] A peer whose uid ≠ server uid is rejected with `peer_uid_denied`; no `resolve`/
      `inject`/`put` is executed for that connection (TC-002, TC-005).
- [ ] [REQ-003] A same-uid peer round-trips a `ping`/`resolve` unchanged (TC-003).
- [ ] [REQ-004] Unreadable peer credential → reject, not allow (TC-004).
- [ ] [REQ-005] The decision function is unit-tested for {equal uid → allow, different uid → deny}
      without a live socket (TC-005).
- [ ] `cargo build && cargo test` green; v0 tests in `vault.rs` unchanged and passing.
- [ ] dep-scan (`cargods`) run on the newly pulled `nix` crate tree before merge; ADR-002 records
      the dependency and the check design.

## Verification plan

- **Highest level achievable:** L6 — runtime-observable: a same-uid client gets a normal response
  over the socket; the peer-uid decision is exercised on every accept.
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` (all unit tests pass, incl. the peer-uid decision
  unit test).
- **Level 6 — Operator observation:** `vault serve --socket /tmp/vault.sock &` then a same-uid
  client sends `{"op":"ping"}` and receives `{"ok":true}`; the accept path logs/asserts the peer
  uid was checked. (A genuine different-uid rejection requires a second uid; if unavailable in the
  run environment, record the unit-level proof of REQ-002/005 and note the environmental limit.)
