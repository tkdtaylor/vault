# ADR-008 — Persistent encrypted-on-disk store (ciphertext at rest, key off disk, handles never persist)

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** [ADR-001](001-foundational-stack.md) (foundational stack, the `vault://` backend
seam, RNG via `/dev/urandom`, "no on-disk persistence" v0 limitation),
[ADR-002](002-socket-peercred-check.md) (the `0600` + peer-uid posture this reuses for the store
file), [ADR-004](004-admin-verbs-rotation-invalidation.md) (rotate bumps `generation` — the field
that must persist), [ADR-005](005-encrypted-at-rest-store.md) (the `StoreBackend` / `KeyProvider`
seams and the AES-256-GCM at-rest representation this serializes — its "at rest in **process
memory**" is the limitation this ADR lifts).

## Context

Today the encrypted store is **in-memory only**. `Vault.store: HashMap<String, Secret>` holds each
value as AES-256-GCM `EncryptedValue { ciphertext, nonce }` (ADR-005) — ciphertext in RAM, never
cleartext — but the whole map **vanishes on process exit**. There is **no disk persistence**: a
restarted `serve` comes up with an empty store, and every secret must be re-`put`.

The ask is an **opt-in persistent encrypted-on-disk store** so secrets survive a restart, **without
weakening zero-knowledge**. The headline property to preserve and prove: *a stolen on-disk store
file is useless without the separately-held master key* (ciphertext-only at rest), *and a restart
invalidates all outstanding handles*.

All ADR-005 / ADR-002 invariants must continue to hold over the new path: `resolve` returns no
value, decrypt happens only at the `inject` edge, the master key lives off the ciphertext behind the
`KeyProvider` seam, a missing/wrong/tampered ciphertext fails closed (`decrypt_failed`), and the
plaintext crosses only the uid-restricted socket.

### Two facts about the current code that shape the design

1. **`EncryptedValue` and `Secret` deliberately have no `serde` derive** (data-model.md: *"No serde
   derive — it never crosses the wire"*). Persistence needs a serializable representation, but
   deriving serde on the internal types would couple the on-disk format to the in-memory struct
   layout and risk a value-leak the day someone adds a `value` field. A **separate on-disk DTO**
   keeps the internal types wire-free and the disk format explicit.
2. **The key path is already isolated behind `KeyProvider` / `StoreBackend`.** Persistence does not
   touch it. The thing being persisted is the *output* of `encrypt` (the `EncryptedValue` + the
   non-secret metadata), never the key and never the plaintext.

## Decisions

### 1. Persistence is ORTHOGONAL to the `StoreBackend` seam — a separate `StoreFile` layer, not a new backend

The `StoreBackend` trait answers *"how is a value's bytes sealed/opened?"* (value crypto:
`encrypt(&str) -> EncryptedValue`, `decrypt(&EncryptedValue) -> String`). Persistence answers a
different question — *"where does the `store: HashMap` live across restarts?"*. These are
**orthogonal**, so persistence is **not** a `StoreBackend`. `AesGcmBackend` stays the value-crypto
backend, unchanged.

Persistence is a thin **`StoreFile` serialization layer** that takes the *already-encrypted*
`EncryptedValue`s plus their cleartext metadata and writes/reads them to a single JSON file. It sits
*beside* the store, owned by `Vault`:

```text
put(value) ──▶ backend.encrypt ──▶ EncryptedValue ──▶ store.insert ──▶ StoreFile::persist(&store)
                (value crypto seam)                     (in RAM)        (serialization layer, opt-in)

startup ──▶ StoreFile::load ──▶ store = { ref -> Secret{ EncryptedValue, meta } }   (ciphertext only; no decrypt)
inject  ──▶ store.get ──▶ backend.decrypt(&enc)  ──▶ credential        (decrypt still ONLY here, at the edge)
```

**Why this seam and not a new backend:** a `PersistentBackend` would have to *re-implement or wrap*
AES-256-GCM to know what bytes to write, re-coupling value-crypto and storage — the exact
entanglement ADR-005's seam removed. Keeping `StoreFile` orthogonal means the encrypted-on-disk
store is *the same AES path* plus a serializer, and a future cloud/HSM `StoreBackend` (ADR-007)
composes with persistence for free (persist whatever opaque locator that backend stores). One thing,
well; small composable pieces.

### 2. On-disk format: a single JSON file, ciphertext base64-encoded, via a dedicated DTO — no new crate

The store file is **plain-text JSON** (project rule: plain text for data interchange; `serde_json`
is already a dependency, no new crate). Shape:

```json
{
  "version": 1,
  "records": {
    "vault://test/api_key": {
      "ciphertext_b64": "…",
      "nonce_b64": "…",
      "injection_floor": "proxy",
      "binding": { "host": "api.example.com", "header": "Authorization", "scheme": "Bearer", "env_var": "API_KEY" },
      "generation": 3
    }
  }
}
```

- **A dedicated `StoredRecord` DTO** carries the serde derives — the internal `Secret` /
  `EncryptedValue` stay wire-free. `Vault` maps `Secret ⇄ StoredRecord` explicitly. This makes the
  disk format an intentional, reviewable surface (a leak would have to be *typed in*), and decouples
  it from in-memory struct churn.
- **`ciphertext` (`Vec<u8>`) and `nonce` (`[u8;12]`) are base64-encoded** as JSON strings.
  `serde_json` cannot hold raw bytes, and `serde`'s default for `Vec<u8>` is a JSON array of numbers
  (correct but bloated/opaque). vault **already has a hand-rolled base64 *decoder*** in
  `src/crypto.rs` (`decode_base64`, for the master key); this adds the **encoder** beside it. **No
  base64 crate** is added — adding one would be an ask-first + dep-scan event for ~10 lines of
  well-understood code. *(Acceptable alternative if the encoder proves fiddly: serialize the byte
  arrays via serde's array form — uglier on disk but zero new code. base64 is the recommendation for
  a readable, greppable file the at-rest negative test can scan.)*
- **`version: 1`** is a forward-compat hook: an unknown version fails closed at load (refuse to
  start) rather than silently misparsing.

### 3. Metadata (`floor` / `binding` / `generation`) is persisted CLEARTEXT alongside the ciphertext — accepted

`injection_floor`, `binding{host,header,scheme,env_var}`, and `generation` are **not the secret
value**. Task 004 / ADR-005 already treat them as non-secret: `get`/`list` return floor + binding in
the clear, and the in-memory `Secret` holds them in the clear beside the ciphertext. Persisting them
cleartext is consistent with that boundary.

**Considered and rejected: encrypting the whole record.** It would hide the binding host (mild
metadata-confidentiality gain) but (a) needs a record-level nonce/scheme on top of the value's,
adding crypto surface; (b) breaks the property that the file is a readable, greppable artifact the
at-rest negative test scans for cleartext leaks; and (c) the binding host is *already* disclosed by
`get`/`list` over the socket, so encrypting it on disk buys little. **Recommendation: persist
metadata cleartext.** If metadata-at-rest confidentiality ever becomes a requirement, it is a
separable later ADR (encrypt the whole `StoredRecord` blob under the same key) — deferred until a
concrete need (defer premature decisions).

### 4. Write-through on every `store` mutation: `put` and `rotate`. Synchronous, atomic, `0600`

Every operation that mutates `store` persists the **whole file** synchronously after the in-memory
mutation succeeds:

- **`put`** — after a successful `encrypt` + `insert`.
- **`rotate`** — after the re-encrypt + `generation` bump (the generation MUST persist, else a
  restart would resurrect a stale generation and un-invalidate handles — but see §5: handles don't
  persist, so the risk is only a wrong baseline generation; persisting it keeps the on-disk truth
  correct).
- Nothing else mutates `store` (`resolve`/`inject`/`get`/`list` are read-only or mutate only
  `handles`, which never persist — §5).

**Synchronous write-through, not batched.** The store is small (operator-managed secrets, not
high-write), so the simplest correct option wins: each `put`/`rotate` returns only after the file is
durably replaced. No background flush, no dirty-tracking, no lost-write window on crash. (Rewriting
the whole file per mutation is O(n) in stored secrets; at vault's scale — tens of secrets — this is
negligible. If the store ever grows large enough to matter, an append-log is a later optimization
behind the same `StoreFile` interface.)

**Atomic + crash-safe write (mandatory).** Persist writes a **temp file in the same directory**
(`<path>.tmp.<pid>`), `chmod 0600` on it **before** writing any ciphertext, `write_all` + **`fsync`**
the temp file, then **atomically `rename`** it over the real path. A crash mid-write leaves either
the old complete file or the temp file — **never a half-written store**. The `0600` mode matches the
socket (ADR-002): the file holds ciphertext + metadata; same-uid-only by filesystem ACL, the
on-disk analogue of the uid-restricted socket. (`rename` within a directory is atomic on POSIX; same
directory guarantees same filesystem so the rename can't degrade to copy.)

**Fail-closed on a persist failure.** If the atomic write fails (disk full, permission, fsync error),
the op surfaces a structured error (`store_persist_failed`) — the in-memory mutation is **not** the
source of truth alone; we do not silently diverge from disk. (Exact rollback granularity is a
task-level detail; the invariant is: never report success for a `put`/`rotate` whose persistence
failed.)

### 5. Handles NEVER persist — a restart invalidates every outstanding handle (security-load-bearing)

**Only `store` (secrets) is persisted. `handles` / `HandleRec` are ephemeral and are NEVER written
to disk.** This is not an omission — it is a security requirement, stated explicitly:

- A persisted single-use handle would be a **replay / forgery vector**: an attacker who reads the
  store file (or a stale backup) could resurrect a consumed or unconsumed handle, defeating
  single-use, first-use sandbox binding, and TTL.
- `HandleRec` holds `expires_at` (absolute time), `consumed`, `bound_sandbox`, and the
  `generation` snapshot — all of which are only meaningful within the live process that minted them.
  Persisting them across a restart would carry stale liveness/binding state.
- Therefore **a restart invalidates all outstanding handles by construction**: the new process
  starts with `handles = {}`. An `inject` of a pre-restart handle returns `unknown_handle`
  (fail-closed). Agents must re-`resolve` after a vault restart — the correct, safe behavior.

This is the second headline property: *restart ⇒ all handles dead*. It is a direct consequence of
persisting `store` but not `handles`, and is asserted by a negative test (resolve, drop+reload the
`Vault` from the same path, inject the old handle ⇒ `unknown_handle`).

### 6. The master key is NEVER written to disk — only ciphertext + nonce + non-secret metadata

Unchanged from ADR-005 and **reaffirmed as the load-bearing property of this ADR**: the 32-byte
AES-256-GCM key stays behind the `KeyProvider` seam (`VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE`),
held only in the backend's `Aes256Gcm` cipher in memory. The store file contains **only** AEAD
ciphertext, the (non-secret) nonce, and cleartext metadata. Consequently:

- **A stolen store file is useless without the separately-held key.** This is the entire point of
  encrypted-at-rest, now extended to disk. The at-rest negative test (the cleartext appears nowhere
  in the file bytes — extended from ADR-005's in-memory scan to the on-disk file) and a
  key-never-on-disk test (the 32 key bytes appear nowhere in the file) assert it.
- The key file and the store file are **separate artifacts** an operator can place on separate
  media / mounts (key in a tmpfs or secrets mount; store on persistent disk).

### 7. Load semantics: load ciphertext only (no decrypt at load); a wrong key surfaces at `inject`

On startup with `--store-path PATH` set and the file present:

- **Parse the JSON, base64-decode each record into an `EncryptedValue`, build the `store` map.** No
  decryption happens at load — decrypt stays **only** at the `inject` edge (ADR-005 §6 boundary,
  preserved). The loaded entries are ciphertext, exactly as the in-memory store holds them.
- A **wrong master key** therefore does **not** surface at load — it surfaces at the first `inject`
  as `decrypt_failed` (every entry fails the tag check). **This is accepted and is the recommended
  behavior**, for three reasons: (a) it keeps the strict "decrypt only at the edge" invariant with no
  exception; (b) a load-time decrypt probe would re-materialise a plaintext value at startup — a new,
  unnecessary place the cleartext lives, which is exactly what vault minimizes; (c) the failure is
  still fail-closed and loud per-inject (`decrypt_failed`, no credential).
- **Optional, recommended diagnostic (non-decrypting):** at load, verify each record *parses* (valid
  base64, nonce is 12 bytes, floor/binding well-formed). A structurally-corrupt record fails closed
  per §8. This catches file corruption at startup **without** decrypting — distinct from a key
  mismatch, which is a per-inject concern. *(A key-mismatch "probe" that decrypts one entry is
  explicitly NOT done, to avoid re-materialising plaintext at startup.)*

### 8. Fail-closed on a bad store file: REFUSE TO START

A **missing** file when `--store-path` is set but no file exists yet is **not** an error — it is a
fresh store (first run): start with an empty `store`, the first `put` creates the file. This is the
normal bootstrap path.

A file that is **present but unreadable, not valid JSON, an unknown `version`, or structurally
corrupt** (a record with invalid base64, a wrong-length nonce, a malformed binding) → **vault
refuses to start** with a clear diagnostic and a non-zero exit, rather than starting with a partial
or empty store. Rationale: a persistent store that silently comes up empty (or drops the corrupt
entries) after a disk fault would **silently lose secrets** and mask a real problem — start-with-warning
is the *less* safe choice for a store whose job is durability. Refuse-to-start forces the operator to
notice and restore from backup. (Contrast: a *tampered ciphertext* that is structurally valid still
loads fine and fails closed at `inject` with `decrypt_failed` — the AEAD tag is the integrity check
for the value bytes; the load-time check is only for *structural* parseability.)

**No path panics, ever.** Every failure is a structured error / clean refuse-to-start, never an
`unwrap` on a corrupt file.

### 9. Opt-in: `--store-path PATH` / `VAULT_STORE_PATH`; unset ⇒ today's in-memory behavior, unchanged

Persistence is **opt-in and off by default**:

- **`--store-path PATH`** flag on `serve`, with **`VAULT_STORE_PATH`** env as the fallback source
  (flag takes precedence, mirroring the `VAULT_MASTER_KEY_FILE` / `VAULT_MASTER_KEY` precedence
  pattern in ADR-005).
- **Unset → in-memory only**, exactly today's behavior: no file is read or written, the store lives
  and dies with the process. The default posture is byte-for-byte unchanged (the same property
  `--http-addr` has in ADR-006).
- **Set → load on startup** (§7/§8), **persist on `put`/`rotate`** (§4). The `demo` subcommand is
  unaffected (it uses an ephemeral key and never persists).

## Consequences

**Positive:**

- Secrets survive a `serve` restart when `--store-path` is set, with **store-level zero-knowledge
  extended to disk**: the file is ciphertext + non-secret metadata only; the key is off-disk; a
  stolen file is inert without the separately-held key.
- A restart **invalidates every outstanding handle** (handles never persist) — single-use,
  first-use binding, and TTL cannot be replayed across a restart.
- The change is **additive and composable**: no new crate, the `StoreBackend` value-crypto path is
  untouched, and a future cloud/HSM backend (ADR-007) gets persistence of its opaque locators for
  free behind the same `StoreFile` layer.
- The store file is a plain, greppable JSON artifact — auditable, and the at-rest negative test can
  scan it directly.

**Negative / what gets harder:**

- **A new on-disk trust boundary and attack surface**: the store file's `0600` mode + atomic write
  are now load-bearing. A misconfigured umask or a backup tool that widens permissions is a new way
  to expose ciphertext (still useless without the key, but defense-in-depth degrades). The spec must
  state the `0600` + same-directory-rename requirements as invariants.
- **Synchronous write-through adds an `fsync` to every `put`/`rotate`** — fine at vault's scale,
  but it makes those ops disk-bound and introduces `store_persist_failed` as a new failure mode.
- **Whole-file rewrite per mutation is O(n)** — a non-issue for tens of secrets; an append-log is a
  deferred optimization behind the same interface if scale ever demands it.
- **Refuse-to-start on a corrupt file** trades availability for not-silently-losing-secrets — an
  operator must restore from backup rather than limp along. This is the deliberate choice for a
  durability-focused store.
- A new **DTO + base64 encoder** to maintain (≈one small module); the encoder must round-trip with
  the existing `decode_base64` (a unit test pins this).

## Alternatives considered

- **A `PersistentBackend: StoreBackend`** (persistence as a new backend) — **rejected** (§1): it
  re-couples value-crypto and storage that ADR-005 deliberately split, and would have to wrap or
  duplicate AES-256-GCM to know what bytes to write. The orthogonal `StoreFile` layer keeps the AES
  path intact and composes with *any* backend.
- **Encrypt the whole `StoredRecord` (metadata included)** — **rejected for now** (§3): adds a
  record-level crypto scheme for little gain (the binding host is already disclosed by `get`/`list`),
  and breaks the greppable-file property. Deferred to a later ADR if metadata-at-rest confidentiality
  becomes a real requirement.
- **Persist handles too (so in-flight handles survive a restart)** — **rejected, hard** (§5):
  persisted single-use handles are a replay/forgery vector; restart-invalidates-all-handles is a
  security feature, not a regression. Re-`resolve` after restart is the correct path.
- **Start-with-empty-store (or drop-corrupt-entries) on a bad file** — **rejected** (§8): silently
  losing secrets after a disk fault is the *less* safe failure for a durability store; refuse-to-start
  forces operator attention.
- **Load-time key-mismatch probe (decrypt one entry at startup)** — **rejected** (§7): it
  re-materialises a plaintext value at startup, a new place the cleartext lives, to detect a
  condition that already fails closed loudly at `inject` (`decrypt_failed`). Strict "decrypt only at
  the edge" wins.
- **Add a base64 crate** — **rejected**: ~10 lines of well-understood encoder beside the existing
  hand-rolled decoder avoids an ask-first + dep-scan event on the crown-jewel path.
- **A real embedded DB (`sled`/SQLite)** — **rejected**: a large new dependency tree and operational
  surface for what is a small, write-rarely key→blob map. A single atomic JSON file matches the scale
  and the plain-text-interchange principle.
