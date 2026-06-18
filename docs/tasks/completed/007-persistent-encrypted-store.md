# Task 007: Persistent encrypted-on-disk store (opt-in, key off disk, handles never persist)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Add an **opt-in persistent encrypted-on-disk store** so secrets survive a `serve` restart **without
weakening zero-knowledge**. Today the encrypted store is **in-memory only** — `Vault.store:
HashMap<String, Secret>` holds each value as AES-256-GCM `EncryptedValue{ciphertext,nonce}` (ADR-005,
ciphertext in RAM, never cleartext) but the whole map vanishes on process exit. This task serializes
the *already-encrypted* `EncryptedValue`s + non-secret metadata to a single `0600`,
atomically-written JSON file via a thin **`StoreFile`** layer that is **orthogonal** to the
`StoreBackend` value-crypto seam (NOT a new backend). Two headline properties to preserve and prove:
*a stolen on-disk file is useless without the separately-held master key* (ciphertext-only at rest),
and *a restart invalidates all outstanding handles* (handles never persist).

## Context

- Tech stack: Rust, `serde` + `serde_json` only. Store + crypto seams live in `src/vault.rs`
  (`Vault.store`, `Secret`) and `src/crypto.rs` (`StoreBackend`, `KeyProvider`, `AesGcmBackend`,
  `EncryptedValue`, the hand-rolled `decode_base64`).
- **Binding design:** [ADR-008](../../architecture/decisions/008-persistent-encrypted-store.md)
  (Accepted) — implement it **exactly**. The executor writes **NO new ADR**; ADR-008 covers this
  task in full (the `StoreFile`-not-a-backend decision §1, the JSON+base64+DTO format §2, cleartext
  metadata §3, write-through+atomicity §4, handles-never-persist §5, key-off-disk §6, load-ciphertext-only
  §7, refuse-to-start §8, opt-in §9).
- Related ADRs: [ADR-005](../../architecture/decisions/005-encrypted-at-rest-store.md) (the
  `StoreBackend`/`KeyProvider` seams + AES-256-GCM representation this serializes — its "at rest in
  *process memory*" limitation is what this lifts), [ADR-002](../../architecture/decisions/002-socket-peercred-check.md)
  (the `0600` posture reused for the file), [ADR-004](../../architecture/decisions/004-admin-verbs-rotation-invalidation.md)
  (rotate bumps `generation` — the field that must persist), [ADR-006](../../architecture/decisions/006-vault-http-api-compat.md)
  (the opt-in `--http-addr` default-off precedent `--store-path` mirrors).
- Reference: [`docs/spec/data-model.md`](../../spec/data-model.md) (store + the "none on disk"
  non-goal to lift), [`docs/spec/configuration.md`](../../spec/configuration.md) (flags/env),
  [`docs/spec/SPEC.md`](../../spec/SPEC.md) (the "no on-disk persistence" non-goal),
  [`docs/spec/behaviors.md`](../../spec/behaviors.md).
- Dependencies: builds on the task-004 encrypted store; independent of 006. Tasks 001–005 shipped.
- **Constraint:** the contract is unchanged — `resolve` still returns no value; `inject` still
  decrypts only at the edge. Persistence is internal to the store. All ADR-005/002 invariants hold:
  the master key lives off the ciphertext, decrypt happens only at `inject`, fail-closed on
  missing/wrong/tampered ciphertext, raise-only floor, single-use, first-use binding, TTL.
- **No new crate.** Reuse the hand-rolled `decode_base64` in `src/crypto.rs` and add a small
  hand-rolled base64 *encoder* beside it. `serde_json` only.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | With `--store-path PATH` set, secrets persist across a restart: an in-process drop+reload from the same path round-trips ciphertext, and `resolve`→`inject` delivers the exact original plaintext (empty and >1-block values included). Load reads ciphertext only — **no decrypt at load**; decrypt stays at the inject edge. | must have |
| REQ-002 | The 32-byte AES master **key is NEVER written to disk** (only ciphertext + nonce + non-secret metadata); the cleartext value is **never** on disk. A reload with a *different* key → `inject` returns `decrypt_failed` (stolen-file-is-inert). The key bytes and the cleartext both appear nowhere in the file bytes. | must have |
| REQ-003 | **Handles NEVER persist**: only `store` is serialized, never `handles`/`HandleRec`. A restart invalidates every outstanding handle — `inject` of a pre-restart handle returns `unknown_handle`, and the reloaded handle table is empty. | must have |
| REQ-004 | Fail-closed on bad input: a **missing** file with the path set ⇒ fresh empty store (first-run, not an error); a **structurally corrupt** file (bad JSON / unknown version / invalid base64 / wrong-length nonce) ⇒ **refuse to start** (structured error, non-zero exit, **no panic**, store not silently emptied); a **tampered-but-structurally-valid** ciphertext loads then fails closed at `inject` with `decrypt_failed`. | must have |
| REQ-005 | The persisted file is mode `0600` (`mode & 0o777 == 0o600`); the temp file is `0600` **before** any ciphertext is written to it. | must have |
| REQ-006 | The write is **atomic + crash-safe**: temp file in the same directory → `fsync` → atomic `rename` over the real path. A mid-write failure leaves the prior complete file intact; a failed persist surfaces `store_persist_failed` (new error) — never a silent success. | must have |
| REQ-007 | **Write-through on `put` and `rotate` only** (after the in-memory mutation succeeds); rotate's bumped `generation` + fresh nonce are reflected on disk and after reload. `resolve`/`inject`/`get`/`list` do **NOT** write. | must have |
| REQ-008 | **Opt-in, off by default:** source is `--store-path PATH` flag with `VAULT_STORE_PATH` env fallback (**flag wins**). Unset ⇒ in-memory only, **byte-for-byte today's behavior** (no file read/written); tasks 001–005 tests stay green. | must have |
| REQ-009 | Types stay wire-free: `Secret`/`EncryptedValue` gain **no** serde derive; serialization goes through a dedicated `StoredRecord` serde DTO with explicit `Secret ⇄ StoredRecord` mapping; the new base64 encoder round-trips with `decode_base64`. | must have |

## Readiness gate

- [x] Test spec `007-persistent-encrypted-store-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] Binding design ([ADR-008](../../architecture/decisions/008-persistent-encrypted-store.md)) is Accepted — no new ADR owed
- [x] No blocking tasks (tasks 001–005 shipped)

## Acceptance criteria

- [ ] [REQ-001] Drop+reload from the same `--store-path` round-trips; `resolve`→`inject` delivers the exact plaintext (empty + >1-block); no decrypt at load (TC-001).
- [ ] [REQ-002] Master-key bytes absent from the file; cleartext value absent from the file; reload with a different key → `inject` `decrypt_failed` (TC-002, TC-003).
- [ ] [REQ-003] Pre-restart handle → `unknown_handle`; reloaded handle table empty (TC-004).
- [ ] [REQ-004] Missing file ⇒ fresh store; corrupt file ⇒ refuse-to-start (non-zero, no panic); tampered ciphertext ⇒ `decrypt_failed` at inject (TC-005).
- [ ] [REQ-005] Persisted + temp file mode `0o600` (TC-006).
- [ ] [REQ-006] Temp+fsync+rename; mid-write failure leaves prior file intact; failed persist ⇒ `store_persist_failed` (TC-007).
- [ ] [REQ-007] `put` and `rotate` persist (generation + nonce reflected on disk); reads do not write (TC-008).
- [ ] [REQ-008] Unset path ⇒ no file I/O, byte-for-byte default; flag beats env; 001–005 green (TC-009).
- [ ] [REQ-009] `Secret`/`EncryptedValue` serde-free; `StoredRecord` DTO; encoder round-trips with `decode_base64` (TC-010).
- [ ] `cargo build && cargo test` green; all 48 prior tests unchanged and passing; no new crate.

## Verification plan

- **Highest level achievable:** **L6** — runtime round-trip via in-process drop+reload (L5
  validation harness) **plus** a live `serve --store-path` restart smoke (operator-observed: put →
  kill → restart → resolve→inject delivers the persisted secret; pre-restart handle ⇒
  `unknown_handle`).
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. restart round-trip (drop+reload), key/cleartext
  absent from the file, handles-don't-persist (`unknown_handle`), refuse-to-start on corrupt files,
  `0600` perms, atomic-write + `store_persist_failed`, write-through points, opt-in default unchanged,
  and the DTO/base64 round-trip. The 48 prior tests still pass.
- **Level 6 — Operator observation:** `cargo run -- serve --socket /run/vault.sock --store-path
  /tmp/vault.store` → `put` a secret → stop → restart with the same `--store-path` → `resolve`→`inject`
  over the socket delivers the persisted credential; an `inject` of a handle minted before the restart
  returns `unknown_handle`; `stat /tmp/vault.store` shows mode `0600` and the file contains no
  cleartext value.

## Spec/doc updates owed in the feat commit

- [`docs/spec/data-model.md`](../../spec/data-model.md): the store-file format + `StoredRecord` DTO;
  lift the "none on disk" non-goal.
- [`docs/spec/configuration.md`](../../spec/configuration.md): `--store-path` / `VAULT_STORE_PATH`
  (flag-wins precedence), `0600`, atomic write-through.
- [`docs/spec/SPEC.md`](../../spec/SPEC.md): the "no on-disk persistence" non-goal → opt-in
  persistent store; new invariant — file is ciphertext-only, key off disk, handles never persist.
- [`docs/spec/behaviors.md`](../../spec/behaviors.md): load-on-start / persist-on-mutate (`put`,
  `rotate`) / refuse-to-start on corrupt file / `store_persist_failed`.
- [`docs/architecture/diagrams.md`](../../architecture/diagrams.md): the `StoreFile` load/persist
  edges (date bump).
