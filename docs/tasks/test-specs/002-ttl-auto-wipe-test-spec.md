# Test Spec 002: TTL auto-wipe clock — enforce handle TTL + env wiped_at

**Linked task:** [`docs/tasks/backlog/002-ttl-auto-wipe.md`](../backlog/002-ttl-auto-wipe.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002 | ✅ |
| REQ-003 | TC-003 | ✅ |
| REQ-004 | TC-004 | ✅ |
| REQ-005 | TC-002, TC-005 | ✅ |
| REQ-006 | TC-006 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: resolve records an expiry from TTL

- **Requirement:** REQ-001
- **Input:** seeded vault; `resolve("vault://test/api_key", ttl=300)` at clock t=1000.
- **Expected output:** the handle record's expiry = 1300 (t + ttl); the resolve response still
  contains `{handle, ttl:300, injection_mode}` and **no** value.
- **Edge cases:** `ttl=0` → already-expired handle (any inject fails); document the chosen
  semantics (treat 0 as "expires immediately").

### TC-002: inject after expiry is rejected

- **Requirement:** REQ-002, REQ-005
- **Input:** resolve at t=1000 with ttl=300; advance the injected clock to t=1400; `inject(handle, "sbx-1", proxy)`.
- **Expected output:** `{"error":{"code":"handle_expired",…}}`; no `credential` field anywhere in
  the response.
- **Edge cases:** exactly-at-expiry (t=1300) boundary behavior is defined and asserted (e.g.
  `expired iff now >= expires_at`).

### TC-003: inject before expiry delivers normally

- **Requirement:** REQ-003
- **Input:** resolve at t=1000 ttl=300; clock at t=1200; `inject(handle, "sbx-1", proxy)`.
- **Expected output:** `{ok:true, delivery:"proxy", credential:"SK-SECRET", binding:{…}}` — the v0
  happy path, unchanged.
- **Edge cases:** the raise-only floor still applies (env request against a proxy floor still
  delivers proxy).

### TC-004: env-mode wiped_at is a real timestamp

- **Requirement:** REQ-004
- **Input:** a secret with `env` floor; resolve; `inject(handle, "sbx-1", env)` at clock t=1200.
- **Expected output:** `{ok:true, delivery:"env", credential, var_name, wiped_at}` where `wiped_at`
  is non-zero and consistent with the inject time / scheduled wipe (not the `0` placeholder).
- **Edge cases:** proxy-mode responses do not gain a spurious `wiped_at` (it is env-mode only).

### TC-005: expiry tested without sleeping

- **Requirement:** REQ-005
- **Input:** all expiry tests use the injected clock to advance time.
- **Expected output:** no test calls `thread::sleep` for TTL; runtime is deterministic.
- **Edge cases:** production path uses the system clock (a smoke assertion that the default clock is
  wired).

### TC-006: precedence — expired vs consumed

- **Requirement:** REQ-006
- **Input:** (a) expired-but-unconsumed handle → inject; (b) consume a handle within TTL, then
  inject the same handle again (still within TTL).
- **Expected output:** (a) `handle_expired`; (b) `handle_consumed`. The precedence is deterministic
  and matches ADR-003.
- **Edge cases:** a handle that is both consumed AND expired returns one defined code (document
  which; suggested: `handle_consumed` if consumption already happened, else `handle_expired`).
