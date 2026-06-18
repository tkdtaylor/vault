# ADR-005 — Encrypted-at-rest store (AES-256-GCM, key held off-ciphertext)

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** [ADR-001](001-foundational-stack.md) (foundational stack, in-memory plaintext
store, the `vault://` backend seam, RNG via `/dev/urandom`),
[ADR-004](004-admin-verbs-rotation-invalidation.md) (rotate semantics — `rotate` now re-encrypts).

## Context

The v0 store held secret values in **plaintext** in process memory
(`Secret { value: String, … }`). vault's whole job is holding secrets; a memory dump, a swapped
page, or a future on-disk persistence layer would expose every value in the clear. The headline v1
upgrade (`README.md` "Deferred (v1): encrypted-at-rest store", roadmap v1 row 4) is **store-level
zero-knowledge**: the value at rest is ciphertext, decrypted only at the injection edge, with the
encryption key kept **off the ciphertext** (client-side / age-style — the key never lands beside
the data it protects).

The contract is unchanged: `resolve` still returns no value; `inject` still returns the plaintext
`credential` at the edge. Encryption is **internal to the store**. All prior invariants hold —
raise-only floor, single-use + first-use binding, TTL expiry, peer-uid gate, rotate-invalidation,
fail-closed.

## Decisions

### 1. Cipher: AES-256-GCM (AEAD)

AES-256-GCM is the AEAD: a 256-bit key, a 96-bit nonce, and a 128-bit authentication tag. GCM gives
**confidentiality + integrity** in one primitive — a tampered or truncated ciphertext fails the tag
check on decrypt, so there is no path to a silent wrong value. This is the standard, widely-audited
AEAD for "encrypt a small blob with a symmetric key."

### 2. Crate: `aes-gcm = "0.10.3"` (pinned) — RC line rejected

The implementation is RustCrypto's `aes-gcm`, **pinned to `0.10.3`** — the mature 0.10.x line
(pulls `aead 0.5.x`). The `0.11.0-rc.4` release candidate was **rejected**: it is a release
candidate (not a stable release) **and** pulls `aead 0.6.1`, which fails dep-scan's 48-hour age
gate. A release-candidate AEAD in the crown-jewel secret path is unacceptable. Default features only
(`aes` + `alloc`); no extra features added.

**dep-scan clearance.** `dep-scan check --lockfile Cargo.lock --lockfile-type crates` passes on the
resolved 0.10.3 tree — all 37 crates (incl. `aes 0.8.4`, `aead 0.5.2`, `ghash 0.5.1`, `polyval`,
`cipher`, `ctr`, `universal-hash`, `crypto-common`, `subtle`) return **pass**, exit 0, stable across
repeated runs. (A first cold-cache run streams transient `maintainer_change` notices for a few
RustCrypto crates while it rebuilds its cache; the authoritative final verdict — and every
subsequent run — is a clean pass with exit 0.)

### 3. Nonce strategy: a fresh 96-bit nonce per put/rotation, from `/dev/urandom`

Every `encrypt` (on `put` and on every `rotate`) draws a **fresh random 96-bit nonce** from the OS
CSPRNG via `/dev/urandom` — the **same source as `handle.rs`, no `rand` crate** (project rule D4; a
third-party RNG crate is attack surface on the crown-jewel path). Consequences:

- Identical plaintexts produce **different ciphertexts** (no deterministic-encryption leakage).
- **No nonce reuse** across secrets or across rotations of the same secret — the GCM
  catastrophic-nonce-reuse failure mode is avoided by construction.
- A nonce-RNG read failure **fails closed** (no nonce ⇒ no encryption ⇒ nothing stored).

The nonce is stored alongside the ciphertext (it is not secret); the tag is appended to the
ciphertext by the AEAD.

### 4. Key-provider seam: the key is external, never serialized, fail-closed if missing

The 32-byte master key is sourced through a **`KeyProvider` seam** (`src/crypto.rs`), not hard-coded
beside the ciphertext. The production provider `EnvKeyProvider` reads the key from, in precedence
order, `VAULT_MASTER_KEY_FILE` (a path) then `VAULT_MASTER_KEY` (inline), decoding hex or base64 to
exactly 32 bytes.

- The key material is held only in the backend's memory (inside the `Aes256Gcm` cipher) — it is
  **never serialized into the store** and **never logged**.
- A **missing/unconfigured/unreadable key fails closed**: the production vault constructs with an
  `UnconfiguredBackend` whose encrypt/decrypt always error — `put` then stores nothing and `inject`
  returns `decrypt_failed`. There is **no plaintext fallback**.
- Tests inject a fixed 32-byte key via the seam (`InMemoryKeyProvider`) for determinism — they never
  depend on the process environment.

### 5. Backend seam: store-encryption behind a `StoreBackend` trait

Store-encryption sits behind a **`StoreBackend` trait** (`encrypt(&str) -> EncryptedValue`,
`decrypt(&EncryptedValue) -> String`). The default production backend is `AesGcmBackend`;
`resolve`/`inject`/callers are unchanged when the backend swaps (a future OpenBao / KMS / HSM
backend slots in here). **No AEAD type leaks into the contract responses** — only the opaque
`EncryptedValue` blob crosses the seam, and the plaintext `String` `decrypt` returns is handed
straight to the injection edge.

### 6. Encrypt-on-put / decrypt-at-inject boundary

- **`put` / `rotate` encrypt** the value with a fresh nonce; the `Secret` holds
  `EncryptedValue { ciphertext, nonce }` — **never the cleartext** (the plaintext `&str` is dropped
  when `put`/`rotate` returns). `rotate` re-encrypts with a fresh nonce and bumps the generation
  (ADR-004 invalidation still holds).
- **`inject` decrypts** — the only place the cleartext re-materialises — and only at delivery time,
  after the consumed/expired/invalidated/binding checks pass. Decryption happens **before** the
  handle is marked consumed, so an integrity fault does not burn the single-use handle.
- **`get` / `list` never decrypt** — they were already metadata-only (ADR-004) and stay that way.

### 7. `decrypt_failed` — fail-closed on a bad tag

A tampered, truncated, or wrong-key ciphertext fails the GCM tag check; `inject` surfaces
`{error:{code:"decrypt_failed", retryable:false}}` with **no credential** and **no panic**. This is
a new error code in the stable error shape. (A `rotate` whose encryption fails likewise returns
`encrypt_failed` and leaves the prior ciphertext untouched.)

## Consequences

- A memory dump of the store shows ciphertext + nonce, not the value. The at-rest negative test
  asserts the cleartext (`SK-DEMO-DO-NOT-LEAK`, `SK-SECRET`) appears nowhere in the stored bytes.
- The dependency floor grows by one crate tree (`aes-gcm` 0.10.3 and its RustCrypto transitive
  deps), all dep-scan-cleared. dep-scan / code-scanner are now blocking gates for any further crypto
  change (CLAUDE.md "Recommended tooling").
- The store still has **no on-disk persistence** — "at rest" here means "at rest in process memory."
  On-disk persistence can now be added behind the same `StoreBackend` seam without re-touching the
  secret path.
- An operator must supply a master key (`VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE`) for a
  production `serve`; without one the store fails closed. The `demo` subcommand uses a self-contained
  **ephemeral** key (fresh random 32 bytes for the process) so it is genuinely encrypted-at-rest with
  no operator key.

## Alternatives considered

- **`aes-gcm 0.11.0-rc.4`** — rejected: release candidate + `aead 0.6.1` fails the dep-scan age gate
  (decision §2).
- **`ring` / `age` crate** — heavier dependency trees for the same AES-256-GCM primitive; `aes-gcm`
  is the minimal, pure-Rust, RustCrypto-audited choice. (`age`'s X25519 envelope is overkill for a
  single local symmetric key; revisit if multi-recipient / key-wrapping is needed.)
- **Deterministic encryption (no nonce / fixed nonce)** — rejected: leaks plaintext equality and is
  the GCM catastrophic-failure mode. A fresh random nonce per encryption is mandatory.
- **Key embedded beside the ciphertext** — rejected: defeats the entire point of encrypted-at-rest
  (an attacker with the store has both halves). The key-provider seam keeps the key external.
