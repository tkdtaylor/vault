# Test Spec 004: Encrypted-at-rest store (AES-256-GCM, key held off-ciphertext)

**Linked task:** [`docs/tasks/backlog/004-encrypted-at-rest-store.md`](../backlog/004-encrypted-at-rest-store.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-006 | ✅ |
| REQ-002 | TC-002 | ✅ |
| REQ-003 | TC-003 | ✅ |
| REQ-004 | TC-004, TC-005 | ✅ |
| REQ-005 | TC-007 | ✅ |
| REQ-006 | TC-006 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: put stores ciphertext, not plaintext

- **Requirement:** REQ-001
- **Input:** `put("vault://test/api_key", "SK-SECRET", proxy, binding)`.
- **Expected output:** the stored `Secret` holds ciphertext bytes; the `String "SK-SECRET"` is not
  present in the stored representation.
- **Edge cases:** empty value and long (>1 block) value both encrypt/round-trip.

### TC-002: resolve→inject round-trips the plaintext

- **Requirement:** REQ-002
- **Input:** put "SK-SECRET"; resolve; `inject(handle, "sbx-1", proxy)`.
- **Expected output:** `credential == "SK-SECRET"` — decryption at the injection edge yields the
  exact original. `resolve` carries no value (unchanged invariant).
- **Edge cases:** env-mode delivery also round-trips the correct plaintext.

### TC-003: key comes from a provider seam, not stored beside ciphertext

- **Requirement:** REQ-003
- **Input:** construct the store with a test key provider; inspect the stored struct.
- **Expected output:** no key bytes are present in the serialized/stored `Secret`; the same provider
  decrypts successfully; a *different* key fails to decrypt (proving the key is external, not embedded).
- **Edge cases:** missing/unconfigured key source → construction or inject fails closed, never a
  plaintext fallback.

### TC-004: unique nonces, no reuse

- **Requirement:** REQ-004
- **Input:** put the same value twice (two refs) and rotate one; capture nonces.
- **Expected output:** all nonces differ; identical plaintexts produce different ciphertexts.
- **Edge cases:** rotation generates a fresh nonce (no reuse with the prior value).

### TC-005: tampered ciphertext fails closed

- **Requirement:** REQ-004
- **Input:** flip a byte in a stored ciphertext (or its tag); resolve→inject.
- **Expected output:** `{"error":{"code":"decrypt_failed",…}}` — never a silent wrong/garbage value,
  never a panic.
- **Edge cases:** truncated ciphertext also → `decrypt_failed`.

### TC-006: at-rest negative — cleartext absent

- **Requirement:** REQ-001, REQ-006
- **Input:** put "SK-DEMO-DO-NOT-LEAK"; serialize/inspect the entire store.
- **Expected output:** the cleartext substring does not appear anywhere in the at-rest store
  representation.
- **Edge cases:** binding/metadata (host, header) may remain cleartext — only the secret *value* is
  required encrypted; the test targets the value.

### TC-007: backend is swappable behind a trait

- **Requirement:** REQ-005
- **Input:** a second backend implementation (e.g. a test/in-memory-plaintext backend used only in
  tests, or a no-op) substituted behind the seam.
- **Expected output:** `resolve`/`inject` signatures and the contract responses are unchanged when
  the backend is swapped; no AEAD type leaks into the contract.
- **Edge cases:** the default production backend is the AES-256-GCM one.
