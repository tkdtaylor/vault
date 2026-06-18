# Test Coverage Tracker

**Project:** vault

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | SO_PEERCRED peer-uid check on the Unix socket | `001-socket-peercred-check-test-spec.md` | TC-001…TC-005 | ✅ | L6: same-uid `serve` round-trip observed (ping/put/resolve over live socket) + L2 unit tests (`peer_uid_allowed_is_equality_not_privilege`, `unreadable_peer_cred_is_denied`); different-uid rejection unit-proven (no 2nd uid in env) |
| 002 | TTL auto-wipe clock (enforce handle TTL + env wiped_at) | `002-ttl-auto-wipe-test-spec.md` | TC-001…TC-006 | 🟡 | L2: `test result: ok. 15 passed; 0 failed` (TC-001 `tc001_*`, TC-002 `tc002_*`, TC-003 `tc003_*`, TC-004 `tc004_*`, TC-005 `tc005_default_clock_is_system_clock`, TC-006 `tc006_precedence_expired_vs_consumed`) + L6: live socket `resolve ttl=1` → wait 2s → `inject` → `handle_expired` observed; awaiting spec-verifier |
| 003 | Wire get/list/rotate admin verbs (metadata-only) | `003-admin-verbs-get-list-rotate-test-spec.md` | TC-001…TC-007 | ❌ | pending — backlog |
| 004 | Encrypted-at-rest store (AES-256-GCM, key off-ciphertext) | `004-encrypted-at-rest-store-test-spec.md` | TC-001…TC-007 | ❌ | pending — backlog |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | **Verified** — validation harness exercised the live runtime path, or operator observed the targeted behaviour |
| 🟡 | **Code merged** — feat-commit landed, unit tests + fitness + CI green, but runtime/live behaviour not yet observed |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

## Verification ladder

A task earns 🟡 at levels 1–4 and ✅ only at level 5 or 6. The `Verified by` column records which level the row reached.

| Level | Evidence | Status this earns |
|-------|----------|-------------------|
| 1 | Code merged | 🟡 |
| 2 | Unit tests pass (paste verbatim final line of `make check`) | 🟡 |
| 3 | `make fitness` passes (verbatim closing line) | 🟡 |
| 4 | CI passes (`gh run watch <id> --exit-status` → success) | 🟡 |
| 5 | **Validation harness** exercises the live runtime path end-to-end — paste the command and the final assertion line | ✅ |
| 6 | **Operator-observed** — operator (or executor via `cargo run` / `npm start` / etc.) saw the targeted behaviour in stdout / logs / UI | ✅ |

If the task targets runtime-observable behaviour (logging, CLI args, TUI, server endpoints, file outputs, side effects), level 5 or 6 is **required** before flipping to ✅. If the task only adds an internal helper covered by unit tests, level 2 may be sufficient — but in that case the row's `Verified by` should explicitly say "unit-test-only; no runtime surface" so future readers don't mistake silence for verification.

## Rule

**The task-executor commits at 🟡 by default.** Only the main session (after spec-verifier APPROVE + the appropriate level-5/6 evidence) updates the row to ✅, in a separate commit titled `verify: confirm task NNN — <level-5/6 evidence>`. This keeps the verification step visible in git history and prevents "merged ≠ done" drift.
