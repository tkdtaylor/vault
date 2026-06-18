# Task 004: Encrypted-at-rest store (AES-256-GCM, key held off-ciphertext)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Upgrade the v0 in-memory **plaintext** store to an **encrypted-at-rest** store: secret values are
held as AES-256-GCM ciphertext, decrypted only at the injection edge (`inject`), with the
encryption key kept separate from the ciphertext (client-side / age-style — the key never lands
beside the data it protects). This is the headline store-level zero-knowledge upgrade, sitting
behind a backend seam so later backends (OpenBao, KMS, HSM) slot in without changing callers.

## Context

- Tech stack: Rust, `serde`-only today. Store is `Vault.store: HashMap<String, Secret{value,…}>`
  in `src/vault.rs` (plaintext). `inject` reads `secret.value` and returns it as `credential`.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md). This task
  introduces **ADR-005** to record the AEAD choice (cipher, crate, nonce strategy, key-source seam)
  and the encrypt-on-put / decrypt-at-inject boundary.
- Reference: [`docs/spec/data-model.md`](../../spec/data-model.md) (store), [`docs/spec/SPEC.md`](../../spec/SPEC.md)
  (zero-knowledge invariant), [`README.md`](../../../README.md) ("Deferred (v1): encrypted-at-rest
  store"), [roadmap](../../plans/roadmap.md) v1 row 4.
- Dependencies: builds naturally on the store; independent of 001–003.
- **Ask-first:** introduces an AEAD crate (e.g. `aes-gcm`, or `ring`/`age`) — a new dependency in a
  crypto-critical path. It must clear dep-scan (`cargods`), be a well-maintained audited crate, and
  be recorded in ADR-005. Prefer a pure-Rust, widely-audited crate; pin the version.
- **Constraint:** the contract is unchanged — `resolve` still returns no value; `inject` still
  returns the plaintext `credential` at the edge. Encryption is internal to the store. The
  raise-only floor, single-use, fail-closed, and (task 001/002) peer-uid/TTL invariants hold.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `put` stores the secret value as AES-256-GCM ciphertext; the plaintext value is not retained in the store after `put` returns. | must have |
| REQ-002 | `inject` decrypts the ciphertext only at delivery time and returns the correct plaintext `credential` (round-trip integrity); decryption happens at the injection edge, not at `resolve`. | must have |
| REQ-003 | The encryption key is sourced through a **key-provider seam** (a trait/function), not hard-coded beside the ciphertext; the default provider reads a key from a configured source (env/file path), and the key material is never serialized into the store. | must have |
| REQ-004 | Each secret uses a unique nonce/IV (no nonce reuse across secrets or rotations); tampered ciphertext (bad tag) → decryption fails closed (`{error:{code:"decrypt_failed",…}}`), never a silent wrong value. | must have |
| REQ-005 | The store-encryption sits behind a **backend seam** so an alternative backend can replace it without changing `resolve`/`inject`/callers. | must have |
| REQ-006 | A negative test asserts the at-rest representation does **not** contain the plaintext value (the in-memory `Secret` holds ciphertext, not the cleartext). | must have |

## Readiness gate

- [x] Test spec `004-encrypted-at-rest-store-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No blocking tasks

## Acceptance criteria

- [ ] [REQ-001] After `put`, the stored representation is ciphertext; the plaintext is absent from the store (TC-001, TC-006).
- [ ] [REQ-002] `resolve`→`inject` round-trips the correct plaintext credential (TC-002).
- [ ] [REQ-003] The key comes from a provider seam; no key bytes are stored beside the ciphertext (TC-003).
- [ ] [REQ-004] Unique nonces; tampered ciphertext → `decrypt_failed`, fail-closed (TC-004, TC-005).
- [ ] [REQ-005] The backend is swappable behind a trait; `resolve`/`inject` signatures unchanged (TC-007).
- [ ] [REQ-006] At-rest negative test: cleartext value not present in the stored struct (TC-006).
- [ ] `cargo build && cargo test` green; v0 tests unchanged and passing.
- [ ] dep-scan (`cargods`) on the AEAD crate tree passes; ADR-005 records cipher/crate/nonce/key-seam.

## Verification plan

- **Highest level achievable:** L5 — validation harness (encryption round-trip + tamper + at-rest
  negative test are all unit-observable). L6 via `demo`/socket showing an inject still delivers.
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. round-trip, tamper-fails-closed, and the
  at-rest-no-plaintext assertion.
- **Level 6 — Operator observation:** `vault demo` still prints a successful proxy inject
  (`credential` delivered) with the store now encrypted; a debug dump of the store shows ciphertext,
  not `SK-DEMO-DO-NOT-LEAK`.
