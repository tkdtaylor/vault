# Test Spec 007: Persistent encrypted-on-disk store (opt-in, key off disk, handles never persist)

**Linked task:** [`docs/tasks/backlog/007-persistent-encrypted-store.md`](../backlog/007-persistent-encrypted-store.md)
**Written:** 2026-06-18
**Design:** [ADR-008](../../architecture/decisions/008-persistent-encrypted-store.md) (binding — no new ADR)

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002, TC-003 | ✅ |
| REQ-003 | TC-004 | ✅ |
| REQ-004 | TC-005 | ✅ |
| REQ-005 | TC-006 | ✅ |
| REQ-006 | TC-007 | ✅ |
| REQ-007 | TC-008 | ✅ |
| REQ-008 | TC-009 | ✅ |
| REQ-009 | TC-010 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

> **Restart is simulated in-process:** a "restart" means *drop the `Vault` and construct a fresh one
> from the same `--store-path`* (load on startup). No process re-exec is needed for L5; the live
> `serve --store-path` restart is the L6 smoke. The fresh `Vault` shares the same key provider (same
> master key) except where a test deliberately injects a different key (TC-004).

---

## Test cases

### TC-001: restart round-trip — persisted ciphertext reloads and injects the exact plaintext

- **Requirement:** REQ-001
- **Input:** construct a `Vault` with `--store-path P` (temp dir) + fixed key; `put("vault://test/api_key", "SK-SECRET", proxy, binding)`; drop the `Vault`; construct a fresh `Vault` from the same `P` + same key; `resolve` → `inject(handle, "sbx-1", proxy)`.
- **Expected output:** `credential == "SK-SECRET"` — the value survives the drop+reload and decrypts (only at the inject edge) to the exact original. The file on disk is created by the `put`.
- **Edge cases:** an **empty** value (`""`) and a **>1-block** value (`"A".repeat(64)`) both persist and round-trip after reload.

### TC-002: KEY never on disk — stolen file is inert (headline negative)

- **Requirement:** REQ-002
- **Input:** `put` with fixed master key `K = [42;32]`; read the **raw bytes of the store file**. Then construct a fresh `Vault` from the same `P` but with a **different** key `K' = [7;32]`; `resolve` → `inject`.
- **Expected output:** (a) the 32 master-key bytes `[42;32]` appear **nowhere** in the file bytes; (b) inject under `K'` → `{"error":{"code":"decrypt_failed",…}}`, no credential — the file is useless without the original key (stolen-file-is-inert proof). No decrypt happens at load; the wrong key surfaces only at inject (ADR-008 §7).
- **Edge cases:** the wrong-key load itself does **not** error or panic (ciphertext-only load); failure is deferred to inject.

### TC-003: cleartext value never on disk

- **Requirement:** REQ-002
- **Input:** `put("vault://demo/key", "SK-DEMO-DO-NOT-LEAK", proxy, binding)`; read the raw store-file bytes.
- **Expected output:** the cleartext substring `SK-DEMO-DO-NOT-LEAK` does **not** appear anywhere in the file (the file holds base64 ciphertext + nonce + non-secret metadata only).
- **Edge cases:** metadata (`host`, `header`, `scheme`, `env_var`, `floor`, `generation`) MAY appear in the clear per ADR-008 §3 — the scan targets the secret *value* only.

### TC-004: handles DON'T persist — restart invalidates every outstanding handle (security headline)

- **Requirement:** REQ-003
- **Input:** `put`; `resolve` a handle `H` (record it); drop the `Vault`; construct a fresh `Vault` from the same `P` + same key; `inject(H, "sbx-1", proxy)`.
- **Expected output:** `{"error":{"code":"unknown_handle",…}}` — the pre-restart handle is dead by construction; no credential is delivered. The fresh `Vault`'s handle table is **empty** after reload (only `store` is persisted, never `handles`).
- **Edge cases:** a fresh `resolve` against the reloaded store mints a working handle (the store is intact; only handles reset).

### TC-005: tamper / corrupt fail-closed

- **Requirement:** REQ-004
- **Input (a) tampered-but-valid ciphertext:** `put`; flip a byte inside the base64-decoded ciphertext on disk (re-encode), keeping the file structurally valid JSON; reload; `resolve` → `inject`.
- **Input (b) structurally corrupt file:** for each of {bad JSON, unknown `version`, invalid base64 in a record, wrong-length nonce}, write that file at `P` and attempt to construct the `Vault` (load on start).
- **Input (c) missing file with path set:** point `--store-path` at a path that does not exist yet; construct the `Vault`.
- **Expected output:** (a) inject → `{"error":{"code":"decrypt_failed",…}}`, no credential, no panic — the AEAD tag is the value-integrity check; the structurally-valid tampered record loads fine and fails at the edge (ADR-008 §8). (b) load **refuses to start** — a structured error / non-zero exit, **no panic**, store not silently emptied. (c) **not an error** — a fresh empty store; the first `put` creates the file (first-run bootstrap, ADR-008 §8).
- **Edge cases:** all four corruption variants in (b) are distinct and each must refuse-to-start, not partially load or drop the bad record.

### TC-006: store file is `0600`

- **Requirement:** REQ-005
- **Input:** `put` so the file is written; `stat` the persisted file; also `stat` the temp file before the rename (via a test seam / observation of the write path).
- **Expected output:** persisted file `mode & 0o777 == 0o600`; the temp file is also `0600` **before** any ciphertext is written to it (chmod-before-write, ADR-008 §4).
- **Edge cases:** Unix-only assertion; the mode check is gated on `cfg(unix)`.

### TC-007: atomic write — temp + fsync + rename; mid-write failure leaves the prior file intact

- **Requirement:** REQ-006
- **Input:** (a) observe a successful persist writes `<path>.tmp.<pid>`, fsyncs, then renames over `P` (no partial file at `P` is ever observable). (b) simulate a mid-write persist failure (e.g. an un-writable directory / injected write error) on a store that already has a complete prior file.
- **Expected output:** (a) after persist, only `P` exists (temp gone), and `P` is the complete new store. (b) the prior complete file at `P` is **unchanged**, and the failing `put`/`rotate` surfaces `{"error":{"code":"store_persist_failed",…}}` — **not** a silent success; the in-memory store is never reported as the sole source of truth.
- **Edge cases:** the rename is within the same directory (same filesystem → atomic, no copy-degrade).

### TC-008: write-through points — `put` and `rotate` persist; reads do not

- **Requirement:** REQ-007
- **Input:** `put` (capture file mtime/contents); `rotate("vault://test/api_key", "SK-NEW")` (bumps generation); then exercise `resolve`, `inject`, `get`, `list`; drop+reload from `P`.
- **Expected output:** both `put` and `rotate` write the file; after reload the record's `generation` reflects the rotate (bumped, persisted) and `inject` of a post-reload `resolve` delivers `SK-NEW`. `resolve` / `inject` / `get` / `list` do **not** write the file (mtime/contents unchanged across those calls).
- **Edge cases:** rotate's fresh nonce is persisted (the reloaded ciphertext differs from the pre-rotate ciphertext).

### TC-009: opt-in default unchanged — unset path ⇒ in-memory only, byte-for-byte

- **Requirement:** REQ-008
- **Input:** construct a `Vault` with **no** `--store-path` / `VAULT_STORE_PATH`; `put` / `resolve` / `inject` / `rotate`.
- **Expected output:** **no file is read or written** anywhere; behavior is byte-for-byte today's in-memory path. All tasks 001–005 tests stay green (the prior 48 assertions unchanged).
- **Edge cases:** flag-vs-env precedence — when both `--store-path` and `VAULT_STORE_PATH` are set, the **flag wins** (mirrors `VAULT_MASTER_KEY_FILE` / `VAULT_MASTER_KEY`).

### TC-010: types stay wire-free — serialization via the `StoredRecord` DTO

- **Requirement:** REQ-009
- **Input:** code-level / structural — `Secret` and `EncryptedValue` definitions; the base64 encoder beside `decode_base64`.
- **Expected output:** `Secret` and `EncryptedValue` gain **no** `serde` derive; serialization goes through a dedicated `StoredRecord` serde DTO with explicit `Secret ⇄ StoredRecord` mapping. The new base64 **encoder** round-trips with the existing `decode_base64` (`decode_base64(encode_base64(b)) == b`) across empty, 1-, 2-, 3-byte (padding) and long inputs.
- **Edge cases:** the encoder's padding matches what `decode_base64` accepts (it strips `=` already); round-trip holds at every length mod 3.
