# Test Spec 003: Wire get / list / rotate admin verbs (metadata-only)

**Linked task:** [`docs/tasks/backlog/003-admin-verbs-get-list-rotate.md`](../backlog/003-admin-verbs-get-list-rotate.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002 | ✅ |
| REQ-002 | TC-003 | ✅ |
| REQ-003 | TC-004 | ✅ |
| REQ-004 | TC-005 | ✅ |
| REQ-005 | TC-006 | ✅ |
| (value-absence, all verbs) | TC-007 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: get returns metadata, never the value

- **Requirement:** REQ-001
- **Input:** seeded vault (`vault://test/api_key`, floor proxy, binding host api.example.com);
  `get{secret_ref:"vault://test/api_key"}`.
- **Expected output:** `{exists:true, injection_floor:"proxy", binding:{host:"api.example.com",…}}`;
  the response string does **not** contain `SK-SECRET`.
- **Edge cases:** binding defaults (header/scheme/env_var) are reflected.

### TC-002: get on unknown ref is fail-closed

- **Requirement:** REQ-001
- **Input:** `get{secret_ref:"vault://nope/x"}`.
- **Expected output:** `{"error":{"code":"no_such_secret",…}}`; no metadata, no value.
- **Edge cases:** empty/missing `secret_ref` → fail-closed error, not a panic.

### TC-003: list returns refs, no values

- **Requirement:** REQ-002
- **Input:** seed two secrets; `list`.
- **Expected output:** both `secret_ref`s present (optionally with floors); the response contains no
  secret value substring.
- **Edge cases:** empty store → empty list, not an error.

### TC-004: rotate swaps value, preserves floor+binding, echoes no value

- **Requirement:** REQ-003
- **Input:** seed `vault://test/api_key` = "SK-OLD" (floor proxy); `rotate{secret_ref, value:"SK-NEW"}`.
- **Expected output:** metadata-only response (no `SK-NEW`/`SK-OLD` in it); a subsequent
  resolve→inject delivers `SK-NEW`; the floor + binding are unchanged.
- **Edge cases:** rotate unknown ref → `no_such_secret`.

### TC-005: rotation invalidates outstanding handles

- **Requirement:** REQ-004
- **Input:** resolve a handle against "SK-OLD"; `rotate` to "SK-NEW"; inject the pre-rotation handle.
- **Expected output:** the pre-rotation handle does **not** deliver "SK-NEW" — it is invalidated
  (e.g. `{error:{code:"handle_invalidated"|"unknown_handle",…}}`). If a different documented
  semantics is chosen, the test asserts that documented behavior instead.
- **Edge cases:** a handle resolved *after* rotation injects "SK-NEW" normally.

### TC-006: all three verbs round-trip over the socket

- **Requirement:** REQ-005
- **Input:** against `vault serve`, send put → get → list → rotate → (unknown op).
- **Expected output:** each verb returns its expected metadata shape; unknown op → `unknown_op`.
- **Edge cases:** malformed JSON line → `bad_request`, connection survives per existing behavior.

### TC-007: no admin verb leaks the value

- **Requirement:** cross-cutting (REQ-001/002/003)
- **Input:** capture the full response strings of get, list, and rotate against a seeded secret.
- **Expected output:** none of the three responses contains the secret value substring.
- **Edge cases:** values containing JSON-special characters are still never echoed.
