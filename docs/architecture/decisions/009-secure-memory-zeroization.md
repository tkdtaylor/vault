# ADR-009 — Hand-rolled secure-memory zeroization (no `zeroize` crate)

**Status:** Accepted
**Date:** 2026-06-18
**Addresses:** security-auditor finding **SEC-001** (key / plaintext not wiped from freed memory)
**Relates to:** [ADR-001](001-foundational-stack.md) (minimal-dependency ethos — no `rand`,
hand-rolled base64; RNG via `/dev/urandom`), [ADR-005](005-encrypted-at-rest-store.md) (the
AES-256-GCM key-provider seam being hardened here).

## Context

The AES-256 master key and the decrypted plaintext credentials live, however briefly, in vault's
process memory. After use, the buffers holding them are dropped — but a plain Rust `Drop` only
frees the allocation; it does **not** overwrite the bytes. A process memory dump, a swapped page,
or a freed-then-reallocated heap page could therefore surface a credential or the master key
**after** it was logically "done with." This is security-auditor finding **SEC-001**, flagged as a
Low hardening follow-up at task-004 ship ("2 Low hardening follow-ups: zeroize, key-less serve
warning").

The standard fix is the `zeroize` crate: overwrite secret buffers on drop with a volatile write the
compiler may not elide. The question this ADR settles is **whether to adopt `zeroize` or hand-roll
the wipe.**

## The dep-scan BLOCK on `zeroize` 1.9.0

The `zeroize` crate (latest **1.9.0**) was run through **dep-scan** and **BLOCKED** on a
**`maintainer_change`** flag: a *complete* maintainer changeover — the prior maintainer `tarcieri`
was removed and `trustpub:github:RustCrypto/utils` was added. This is RustCrypto's migration to
GitHub **trusted-publishing** (a legitimate infrastructure change, not evidence of compromise) —
but a complete owner changeover on a crate that would sit directly on the crown-jewel secret path
is exactly what dep-scan's hard-stop rule exists to catch, and the project's policy is a **hard
stop on a BLOCK**, re-evaluated when the flag ages out.

Enabling the `aes-gcm` crate's own `zeroize` **feature** is not an escape hatch: it pulls the same
BLOCKED `zeroize` crate transitively. So that option is off the table too.

## Decision

**Hand-roll the zeroization — no `zeroize` crate, no new dependency, std-only.** This is consistent
with the project's established minimal-dependency ethos (no `rand` — `/dev/urandom` instead; no
base64 crate — a hand-rolled encoder in `crypto.rs`). The wipe is implemented in a small new
`src/zeroize.rs` module.

### Technique: volatile write + compiler fence

`Zeroize::zeroize` overwrites each byte with `0x00` via
[`core::ptr::write_volatile`] and then issues a
[`core::sync::atomic::compiler_fence(Ordering::SeqCst)`]. **Why this exact pattern:** the compiler
is normally free to delete stores to memory it can prove is never read again (dead-store
elimination) — which would silently defeat a naive `buf.fill(0)`. A *volatile* write is defined to
have an observable side effect the optimizer may not elide; the `SeqCst` compiler fence prevents
the writes from being reordered or sunk past the end of the wipe. This is the same pattern the
`zeroize` crate itself uses.

The module exposes a `Zeroize` trait (impls for `[u8; N]`, `Vec<u8>`, `String` — the concrete
buffer types vault holds) and a `Zeroizing<T>` RAII wrapper that calls `zeroize()` on `Drop` and
`Deref`s to the wrapped value so it stays transparently usable until then. `Vec<u8>` wipes its full
capacity (including spare bytes already written) before resetting length to 0.

### Scope — buffers vault directly controls (wiped)

- The decoded **32-byte master key** `[u8; 32]` in `EnvKeyProvider::key` / `decode_key`, and in
  `AesGcmBackend::new` after it is loaded into the cipher.
- The raw master-key **`String`** read from `VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE` (wiped
  after decode, including the error-return paths).
- The intermediate **decoded key `Vec<u8>`** in `decode_key` (wiped after copy into the array).
- The **`random_key()`** ephemeral-key buffer at its call site (`Vault::with_ephemeral_key`), wiped
  after the backend loads it.
- The **decrypted plaintext `Vec<u8>`** in `AesGcmBackend::decrypt`, wiped after the credential
  `String` is produced (including the fail-closed UTF-8-error path).

## Honest residual (NOT claimed closed)

- **Cipher-internal key copy.** `Aes256Gcm::new` keeps its own copy of the key (expanded round
  keys) **inside** the cipher object. We **cannot** wipe that without enabling aes-gcm's `zeroize`
  feature → the BLOCKED `zeroize` crate. So this residual **remains** until `zeroize` clears
  dep-scan (re-evaluate when the `maintainer_change` flag ages out). No test or doc asserts the
  cipher-internal key is wiped.
- **Best-effort, not a guarantee.** Rust may **move** a value (a bitwise copy) before its `Drop`
  runs, and values may spill to registers or be copied by the allocator; only the final resting
  copy is wiped. This is **defense-in-depth**, not a hard guarantee — the *same* caveat the
  `zeroize` crate itself carries. The returned credential `String` itself is owned by the caller
  (the injection edge), whose lifetime governs when it is wiped; this module wipes only the
  intermediate buffers.

## Consequences

- No new dependency; `Cargo.toml` and `Cargo.lock` are unchanged; `zeroize` is absent from the
  tree; aes-gcm's `zeroize` feature stays off.
- No behavior change on the secret path: encrypt→decrypt still round-trips the exact plaintext;
  fail-closed on bad key / tamper is unchanged; `resolve` stays value-free; all prior tests green.
- When `zeroize` next clears dep-scan, a follow-up may adopt it (and the aes-gcm feature) to close
  the cipher-internal residual — at which point this hand-rolled module can be retired or kept as
  the std-only fallback.
