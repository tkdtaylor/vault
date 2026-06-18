# Test Spec 001: SO_PEERCRED peer-uid check on the Unix socket

**Linked task:** [`docs/tasks/backlog/001-socket-peercred-check.md`](../backlog/001-socket-peercred-check.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002, TC-005 | ✅ |
| REQ-003 | TC-003 | ✅ |
| REQ-004 | TC-004 | ✅ |
| REQ-005 | TC-005 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: Peer uid is read on accept

- **Requirement:** REQ-001
- **Input:** a client connects to the served socket from the same uid as the server.
- **Expected output:** the accept path obtains the peer uid via `SO_PEERCRED` (observable: the
  connection proceeds only after the peer-uid decision runs; instrumented test or log confirms the
  uid was read).
- **Edge cases:** multiple concurrent connections each get their own peer-uid read.

### TC-002: Different uid is rejected fail-closed

- **Requirement:** REQ-002
- **Input:** the peer-uid decision is invoked with `peer_uid = 9999`, `server_uid = 1000`.
- **Expected output:** decision = deny; at the socket layer this maps to
  `{"error":{"code":"peer_uid_denied",…}}` (or a closed connection) and **no** `resolve`/`inject`/
  `put` is dispatched.
- **Edge cases:** root (uid 0) connecting to a non-root server is still denied unless it equals the
  server uid — the rule is equality, not privilege.

### TC-003: Same uid round-trips unchanged

- **Requirement:** REQ-003
- **Input:** same-uid client sends `{"op":"ping"}` then `{"op":"resolve","secret_ref":"vault://test/api_key"}`
  against a seeded vault.
- **Expected output:** `{"ok":true}` for ping; a `{handle, ttl, injection_mode}` for resolve with
  **no** secret value present — identical to pre-task behavior.
- **Edge cases:** the happy path latency/shape is unchanged (no contract drift).

### TC-004: Unreadable peer credential → reject

- **Requirement:** REQ-004
- **Input:** the peer-credential read returns an error (simulated at the decision boundary).
- **Expected output:** decision = deny (fail-closed) — never "allow because we couldn't tell".
- **Edge cases:** the error is not propagated as a panic; the connection closes cleanly.

### TC-005: Decision function is unit-testable without a socket

- **Requirement:** REQ-002, REQ-005
- **Input:** call the pure decision function with pairs: `(1000, 1000)`, `(1000, 1001)`, `(0, 1000)`.
- **Expected output:** `(1000,1000) → allow`; `(1000,1001) → deny`; `(0,1000) → deny`.
- **Edge cases:** the function has no I/O — it is a total function of the two uids, enabling the
  REQ-002 proof without spawning a second-uid process.

---

## Notes

A genuine end-to-end different-uid rejection requires a second uid (root/sudo), which may be
unavailable in the build environment. REQ-002 is therefore proven at the unit level (TC-005) plus
the same-uid acceptance E2E (TC-003); the verifier should accept the unit-level proof and note any
environmental limit on the live different-uid path.
