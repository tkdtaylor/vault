# Task 008: Secure-memory zeroization of key + plaintext buffers (hand-rolled, no zeroize crate)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Wipe the AES master key and decrypted-plaintext buffers that vault **directly controls** from memory
on drop, using a small **hand-rolled** `Zeroizing<T>` wrapper (or per-type `Drop` impls) — **no
`zeroize` crate, no new dependency**. This addresses security-auditor finding **SEC-001** (key /
plaintext not wiped from freed memory: a process memory dump or a freed-then-reallocated heap page
could surface a credential or the master key after use). The wipe overwrites bytes on `Drop` via
`core::ptr::write_volatile` per byte + a `core::sync::atomic::compiler_fence(Ordering::SeqCst)` — the
standard elision-resistant pattern. This is **best-effort defense-in-depth**, not a guarantee (Rust
may move values before drop) — the same caveat the `zeroize` crate itself carries.

## Context

- Tech stack: Rust, `serde` + `serde_json` + `aes-gcm` (task 004). Key/plaintext buffers live in
  `src/crypto.rs`: the decoded 32-byte key `[u8;32]` in `EnvKeyProvider::key` /
  `AesGcmBackend::new` (before it enters the cipher), the `random_key()` buffer, the raw key
  `String` in `EnvKeyProvider`, and the decrypted plaintext `Vec<u8>` / intermediate in
  `AesGcmBackend::decrypt` (after the credential `String` is produced).
- **Finding:** security-auditor **SEC-001** — key/plaintext not zeroized from freed memory (a Low
  hardening follow-up flagged at task-004 ship; see the coverage-tracker task-004 row:
  "2 Low hardening follow-ups: zeroize, key-less serve warning").
- **CRITICAL DEPENDENCY DECISION (the executor MUST write ADR-009 recording it):** the `zeroize`
  crate (latest **1.9.0**) was run through **dep-scan** and **BLOCKED** on **`maintainer_change`** —
  a complete maintainer changeover: removed `tarcieri`, added `trustpub:github:RustCrypto/utils`
  (RustCrypto's migration to GitHub trusted-publishing). Per the project's **dep-scan hard-stop
  rule** AND its **minimal-dependency ethos** (no `rand`, hand-rolled base64), the decision is:
  **hand-roll zeroization — NO zeroize crate, NO new dependency.** ADR-009 records: the dep-scan
  BLOCK, the hand-rolled decision + rationale, the volatile-write+fence technique, the scope (which
  buffers are wiped), the honest residual, and the best-effort caveat.
- **HONEST RESIDUAL (document in ADR-009 + here, do NOT over-claim):** the key copy held **inside**
  the `aes_gcm::Aes256Gcm` cipher object cannot be wiped without enabling aes-gcm's `zeroize`
  feature — which pulls the same dep-scan-**BLOCKED** `zeroize` crate. So that residual remains until
  `zeroize` clears dep-scan (re-evaluate when the maintainer-change flag ages out). Also: Rust may
  move values before drop, so this is best-effort defense-in-depth, not a guarantee.
- Related ADRs: [ADR-005](../../architecture/decisions/005-encrypted-at-rest-store.md) (the
  key-provider seam + AES path being hardened), [ADR-001](../../architecture/decisions/001-foundational-stack.md)
  (minimal-dep ethos, `/dev/urandom`-not-`rand`).
- Dependencies: builds on the task-004 crypto path; independent of 006/007 (composes cleanly if 007
  lands first — more prior tests to keep green).
- **Constraint:** **NO behavior change to the secret path** — encrypt/decrypt round-trips, fail-closed,
  and every invariant (resolve value-free, inject delivers, raise-only floor, single-use) are
  unchanged; all prior tests stay green; no new crate; never log key/plaintext.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A hand-rolled `Zeroizing<T>` wrapper (or per-type `Drop` impls) overwrites its bytes to zero on `Drop` using `core::ptr::write_volatile` per byte + `core::sync::atomic::compiler_fence(Ordering::SeqCst)`. Applied to the buffers vault directly controls: the decoded `[u8;32]` key in `EnvKeyProvider`/`AesGcmBackend::new` (before it enters the cipher), the `random_key()` buffer, the raw key `String` in `EnvKeyProvider`, and the decrypted plaintext `Vec<u8>`/intermediate in `AesGcmBackend::decrypt` after the credential `String` is produced. | must have |
| REQ-002 | Round-trip correctness is unchanged: `encrypt`→`decrypt` still yields the exact plaintext via the wrapped key path; the AES backend behaves identically; all task-004 `src/crypto.rs` tests still pass. | must have |
| REQ-003 | No behavior / contract change on the secret path: `resolve` value-free, `inject` delivers the credential, fail-closed on bad key / tamper, raise-only floor, single-use replay rejection — all unchanged; no key/plaintext is logged by the new code. | must have |
| REQ-004 | **No new dependency:** the diff adds **no** crate to `Cargo.toml` — the `zeroize` crate is **NOT** added (hand-rolled, std-only); aes-gcm's `zeroize` feature is **not** enabled. Deps remain `serde` + `serde_json` + `aes-gcm`. | must have |
| REQ-005 | The documented residual is recorded, not claimed away: the cipher-internal key copy inside `aes_gcm::Aes256Gcm` is **out of scope** (needs the BLOCKED `zeroize` crate) and the best-effort caveat is stated in ADR-009 + the wrapper doc-comment. | must have |

## Readiness gate

- [x] Test spec `008-secure-memory-zeroization-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] The dep-scan BLOCK on `zeroize` 1.9.0 (`maintainer_change`) + the hand-rolled decision are captured here and will be recorded in ADR-009
- [x] No blocking tasks (tasks 001–005 shipped)

## Acceptance criteria

- [ ] [REQ-001] `Zeroizing<T>` zeros its bytes on drop via volatile-write + `compiler_fence`; applied to the key/plaintext buffers vault controls (TC-001).
- [ ] [REQ-002] Encrypt→decrypt round-trip exact through the wrapped key path; all task-004 crypto tests pass (TC-002).
- [ ] [REQ-003] resolve value-free, inject delivers, fail-closed on bad key/tamper, single-use, raise-only — all unchanged (TC-003).
- [ ] [REQ-004] `git diff` adds no crate to `Cargo.toml`; `zeroize` absent; aes-gcm `zeroize` feature off (TC-004).
- [ ] [REQ-005] Cipher-internal key residual documented (ADR-009 + doc-comment), not claimed wiped; best-effort caveat stated (TC-005).
- [ ] `cargo build && cargo test` green incl. the zeroization-on-drop test + unchanged crypto round-trip; all prior tests pass.
- [ ] **ADR-009 written** by the executor, recording: the dep-scan BLOCK on `zeroize` 1.9.0
      (`maintainer_change`), the hand-rolled decision + rationale (hard-stop + minimal-dep ethos), the
      volatile-write+fence technique, the scope (buffers wiped), the honest residual (cipher-internal
      key), and the best-effort caveat.

## Verification plan

- **Highest level achievable:** **L5** — validation harness (the zeroization-on-drop test +
  unchanged crypto round-trip are unit-observable). Zeroization is **best-effort defense-in-depth**;
  there is no portable runtime forensic observation, so L6 is not claimed. Note this honestly in the
  `Verified by` column.
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. the `Zeroizing<T>`-zeros-on-drop test, the
  unchanged AES round-trip / tamper / wrong-key tests, the no-behavior-change vault flow, and the
  no-new-dependency check. All prior tests pass.
- **Level 3 (supporting):** record the dep-scan BLOCK on `zeroize` 1.9.0 (`maintainer_change`) as the
  evidence motivating the hand-rolled path; `cargo fmt --check` + `cargo clippy` clean.
- **ADR owed:** the executor writes
  [`docs/architecture/decisions/009-secure-memory-zeroization.md`](../../architecture/decisions/009-secure-memory-zeroization.md)
  (the dep-scan BLOCK, hand-rolled decision + rationale, technique, scope, residual, caveat).

## Spec/doc updates owed in the feat commit

- [`docs/spec/SPEC.md`](../../spec/SPEC.md) / [`docs/spec/data-model.md`](../../spec/data-model.md):
  a memory-hygiene note — best-effort key/plaintext zeroization on the buffers vault controls; the
  documented cipher-internal residual (only if it fits the spec's current-state framing; the ADR
  carries the history).
