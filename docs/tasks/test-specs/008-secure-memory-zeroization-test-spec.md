# Test Spec 008: Secure-memory zeroization of key + plaintext buffers (hand-rolled, no zeroize crate)

**Linked task:** [`docs/tasks/backlog/008-secure-memory-zeroization.md`](../backlog/008-secure-memory-zeroization.md)
**Written:** 2026-06-18
**Addresses:** security-auditor finding **SEC-001** (key / plaintext not wiped from freed memory)
**Design:** ADR-009 (written by the executor — records the `zeroize` dep-scan BLOCK + hand-rolled decision)

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002 | ✅ |
| REQ-003 | TC-003 | ✅ |
| REQ-004 | TC-004 | ✅ |
| REQ-005 | TC-005 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

> **Why these are structural/correctness tests, not memory forensics.** Asserting "the heap byte is
> zero after free" is not portable or reliable in safe Rust (the allocator may reuse/return the page,
> values may be moved before drop). So zeroization is verified by (a) a controlled drop test against a
> buffer reachable through a raw pointer captured *before* drop, (b) the volatile-write+fence pattern
> being present (code-level), and (c) proving no behavior changed. Zeroization is **best-effort
> defense-in-depth** — the spec states this, the tests do not over-claim a guarantee.

---

## Test cases

### TC-001: `Zeroizing<T>` zeros its bytes on drop (volatile-write + fence)

- **Requirement:** REQ-001
- **Input:** construct `Zeroizing` over a known non-zero buffer (e.g. `[0xAB; 32]`). Capture a raw `*const u8` to the wrapped bytes **before** dropping (controlled test scope — the backing storage is not moved/freed within the assertion window, e.g. a heap `Box`/`Vec` whose pointer stays valid for the read). Run the `Drop`. Read the bytes back through the captured pointer.
- **Expected output:** every byte the wrapper covered reads back as `0x00` after `Drop` — the wrapper zeroed the buffer. The implementation uses `core::ptr::write_volatile` per byte plus `core::sync::atomic::compiler_fence(Ordering::SeqCst)` (the elision-resistant pattern) — asserted at the code level.
- **Edge cases:** zero-length buffer drops cleanly (no-op, no panic); the wrapper still `Deref`s to `&T` so wrapped values are usable before drop.

### TC-002: round-trip correctness unchanged with the wrapped key path

- **Requirement:** REQ-002
- **Input:** all task-004 `src/crypto.rs` AEAD tests run against the backend whose key now flows through the zeroizing wrapper: `encrypt(pt)` → `decrypt(ev)` for `["", "SK-SECRET", "x".repeat(100)]`; identical-plaintext-different-ciphertext; tampered/truncated → `decrypt_failed`; different-key-cannot-decrypt; hex/base64 key decode.
- **Expected output:** every assertion is identical to pre-change — exact round-trip plaintext, fail-closed on tamper/wrong-key. The AES backend behaves identically; the wrapper is transparent to the crypto.
- **Edge cases:** the decrypted plaintext `Vec<u8>` / intermediate in `AesGcmBackend::decrypt` is wrapped/zeroed **after** the credential `String` is produced — the produced `String` is still exact and complete.

### TC-003: no behavior / contract change on the secret path

- **Requirement:** REQ-003
- **Input:** the full vault flow — `resolve` (value-free), `inject` delivers credential, fail-closed on bad key / tampered ciphertext, raise-only floor, single-use replay rejection.
- **Expected output:** every invariant unchanged: `resolve` carries no value; `inject` returns the exact credential; bad key / tamper → `decrypt_failed`; replay → `handle_consumed`; floor never lowered. All prior tests (task 001–005, plus task 007 if landed) stay green.
- **Edge cases:** no key or plaintext is ever logged by the new code path (grep the diff — no `println!`/`eprintln!`/`dbg!` of key or plaintext bytes).

### TC-004: no new dependency — zeroize crate absent

- **Requirement:** REQ-004
- **Input:** `Cargo.toml` (and `Cargo.lock`) before vs after; inspect the dependency set.
- **Expected output:** the diff adds **no** crate to `Cargo.toml` — `zeroize` is **not** added, and dependencies remain exactly `serde` + `serde_json` (+ the existing `aes-gcm` from task 004). The zeroization is hand-rolled (`core::ptr::write_volatile` + `compiler_fence`, std-only). A note/assertion records that `zeroize` is absent from the tree.
- **Edge cases:** the `aes-gcm` crate's `zeroize` feature is **not** enabled (enabling it would pull the dep-scan-BLOCKED `zeroize` crate transitively).

### TC-005: documented residual — cipher-internal key wipe is out of scope (not claimed)

- **Requirement:** REQ-005
- **Input:** ADR-009 + the task file + a doc-comment on the wrapper.
- **Expected output:** the honest residual is **documented, not claimed away**: the key copy held inside the `aes_gcm::Aes256Gcm` cipher object is **not** wiped (doing so needs aes-gcm's `zeroize` feature → the BLOCKED crate), so it remains until `zeroize` clears dep-scan. The best-effort caveat (Rust may move values before drop; this is defense-in-depth, not a guarantee — the same caveat the zeroize crate itself carries) is stated. No test or doc asserts the cipher-internal key is wiped.
- **Edge cases:** ADR-009 records the dep-scan **BLOCK** on `zeroize` 1.9.0 (`maintainer_change`: removed `tarcieri`, added `trustpub:github:RustCrypto/utils`) as the reason for hand-rolling — this is the load-bearing decision record.
