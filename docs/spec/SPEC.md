# vault — Authoritative Spec

**Project:** vault
**Last updated:** 2026-06-18

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of vault. It answers:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured — output of every task that changes externally-observable behavior, the
data model, an interface, or configuration; and input to onboarding, drift audits, and (in the
limit) regenerating the codebase. The code is one realization of this spec. If they disagree, one
is wrong — fix it in the same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour | Snapshot, human-readable |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

## The seven sub-files

| File | Covers |
|------|--------|
| [behaviors.md](behaviors.md) | What the system does — put, resolve (handle, no value), inject (proxy/env), raise-only floor, single-use binding, fail-closed errors, the IPC server, the opt-in loopback HTTP read surface, demo |
| [architecture.md](architecture.md) | C4 element catalog — persons, systems, the binary, its components |
| [data-model.md](data-model.md) | In-memory store + handle table, `Mode`/`Binding`, the resolve/inject wire shapes, error shape |
| [interfaces.md](interfaces.md) | CLI (`serve`/`demo`), the IPC protocol (`ping`/`put`/`resolve`/`inject`), the opt-in loopback HTTP read surface (`/v1/sys/health`, `/v1/secret/data/:path`), the `Vault` core methods |
| [configuration.md](configuration.md) | `--socket`, `--http-addr` (opt-in, loopback-only), socket permissions, injection floor / binding defaults, no secrets in repo |
| [fitness-functions.md](fitness-functions.md) | Proposed executable invariants (zero-knowledge resolve, raise-only floor, single-use, fail-closed, memory-safe path, uid-restricted socket, read-only loopback HTTP surface) |

## Project summary

vault is the JIT zero-knowledge secret store + credential broker for the secure-agent ecosystem.
It answers *"does the agent core ever see a credential in plaintext?"* — and the answer is **no**.
The agent holds only an opaque, single-use **handle**; the plaintext is injected at the host
boundary into `exec-sandbox` at execution time, then wiped. vault coordinates with `policy-engine`
(it honors the raise-only `vault_injection_floor`), `exec-sandbox` (the injection edge), and
`audit-trail` (handle lifecycle, never the value). The interface is shaped to the
`vault://<scope>/<key>` scheme + Vault HTTP API path semantics — an adapter seam so a local
encrypted store, OpenBao, HashiCorp Vault, cloud KMS, or PKCS#11 HSM can sit behind it. vault ships
an **AES-256-GCM encrypted-at-rest** store (the key held off the ciphertext, behind a backend seam),
in-memory by default with an **opt-in `0600` on-disk persistence layer** (`--store-path`, ADR-008 —
ciphertext-only at rest, key off disk, handles never persist), + a `resolve`/`inject` broker over a
uid-restricted Unix-socket IPC server, written in Rust for memory safety on the secret path. An
**opt-in, loopback-only, read-only HTTP read surface**
(`--http-addr 127.0.0.1:PORT`, ADR-006) speaks the Vault KV-v2 API shape and maps a read onto
value-free `resolve` — returning the **handle** in a Vault-shaped envelope, never the value.

## Top-level invariants

- **The agent core never receives plaintext.** `resolve` returns `{handle, ttl, injection_mode}` —
  never the value; plaintext lives only in vault's memory and at the injection edge. *(Enforced in
  `src/vault.rs::resolve`; test `resolve_hides_value_and_inject_delivers_proxy`. Proposed fitness rule F-001.)*
- **Raise-only injection floor.** `inject`'s effective mode is `max(secret_floor, requested)` —
  vault raises (env→proxy), never lowers. *(Enforced in `src/vault.rs::inject`; test
  `floor_cannot_be_lowered`. Proposed fitness rule F-002.)*
- **Single-use handles + first-use sandbox binding.** A handle is consumed on first `inject` and
  bound to that sandbox; replays → `handle_consumed`, a different sandbox →
  `handle_bound_to_other_sandbox`. *(Enforced in `src/vault.rs::inject`; test `replay_is_rejected`.
  Proposed fitness rule F-003.)*
- **Fail-closed.** Unknown handle / secret / op, malformed request, or RNG failure → the structured
  error shape; no credential delivered. *(Enforced in the `err()` paths of `src/vault.rs` /
  `src/main.rs`. Proposed fitness rule F-004.)*
- **Memory-safe language for the secret path.** vault is Rust. *(Enforced by the language. Proposed
  fitness rule F-005.)*
- **Best-effort zeroization of key/plaintext buffers vault controls.** The 32-byte master key (raw
  `String`, decoded buffer, in-`new` copy, the ephemeral `random_key()` buffer) and the decrypted
  plaintext `Vec<u8>` are overwritten with zeros on drop via a hand-rolled `Zeroizing<T>` wrapper
  (`core::ptr::write_volatile` per byte + a `SeqCst` `compiler_fence`, std-only — no `zeroize`
  crate; SEC-001, ADR-009). This is **defense-in-depth, not a guarantee** — Rust may move a value
  before drop. **Documented residual:** the key copy held *inside* the `aes_gcm::Aes256Gcm` cipher
  object is **not** wiped (that needs aes-gcm's `zeroize` feature → the dep-scan-BLOCKED `zeroize`
  crate). *(Enforced in `src/zeroize.rs` + the key/plaintext call sites in `src/crypto.rs` /
  `src/vault.rs`; test `wrapper_zeros_backing_bytes_on_drop`; ADR-009.)*
- **Encrypted at rest, key off the ciphertext.** Each stored value is AES-256-GCM ciphertext with a
  unique 96-bit nonce per `put`/`rotate`; the cleartext is held nowhere at rest and re-materialises
  only at `inject` (the edge). The 32-byte key comes from a key-provider seam and is never serialized
  beside the ciphertext or logged; a missing key fails the store closed, and a tampered ciphertext
  fails `decrypt_failed` (never a silent wrong value). *(Enforced in `src/crypto.rs` + the
  encrypt-on-put / decrypt-at-inject boundary in `src/vault.rs`; tests `tc001_put_stores_ciphertext_not_plaintext`,
  `tc005_tampered_ciphertext_fails_closed`, `tc006_at_rest_negative_cleartext_absent`; ADR-005.)*
- **The on-disk store is ciphertext-only, key off disk, handles never persist.** When persistence is
  enabled (`--store-path PATH`), the store file holds AEAD ciphertext + nonce + non-secret metadata
  only — the master key and the cleartext are never written (a stolen file is inert without the
  separately-held key; a reload under a different key fails closed at `inject` with `decrypt_failed`).
  Only `store` is serialized; **handles never persist**, so a restart invalidates every outstanding
  handle (`unknown_handle`). The file is `0600`, written atomically (temp + fsync + rename); a corrupt
  file makes `serve` refuse to start (no panic, store never silently emptied); a missing file is a
  fresh first-run store. Unset → in-memory only, byte-for-byte today's behavior. *(Enforced in
  `src/store_file.rs` + `src/vault.rs` load/persist; tests `tc001_restart_round_trips_plaintext`,
  `tc002_key_never_on_disk_wrong_key_fails_at_inject`, `tc004_handles_do_not_persist`,
  `tc005_tamper_and_corrupt_fail_closed`; ADR-008.)*
- **Plaintext crosses only the uid-restricted socket.** The vault→proxy handoff (D5) travels a
  `0600` Unix socket, and every accepted connection is gated by a kernel-verified `SO_PEERCRED`
  peer-uid check — admit iff `peer_uid == server_uid` (equality, not privilege), fail-closed on an
  unreadable credential, before any op dispatches. *(Enforced in `src/main.rs::handle_conn` /
  `peer_uid_allowed`; ADR-002. Proposed fitness rule F-006.)*
- **The HTTP read surface is zero-knowledge, read-only, and loopback-only.** When enabled with
  `--http-addr 127.0.0.1:PORT`, vault exposes a Vault-KV-v2-shaped read (`GET /v1/secret/data/:path`)
  that maps onto value-free `resolve` and returns the **handle**, never the value, plus a
  `GET /v1/sys/health` liveness endpoint. No HTTP route reaches `inject`/`put`/`rotate`/`get`/`list`;
  a non-loopback bind is refused fail-closed; absent the flag there is no HTTP listener. The two
  listeners are asymmetric: the Unix socket is `SO_PEERCRED`-gated with the full verb set, the HTTP
  surface is unauthenticated and therefore loopback + read-only. *(Enforced in `src/http.rs`; tests
  `tc004_read_returns_handle_value_absent`, `tc007_non_get_is_405_mutation_unreachable`,
  `tc002_loopback_only_accepts_only_127`; ADR-006. Proposed fitness rule F-007.)*
- **Stable error shape.** IPC and core errors are `{error:{code,message,retryable}}`; the HTTP read
  surface maps them to Vault's HTTP shapes (`404 {"errors":[]}`, `405`, `400`).

## Non-goals (current scope)

These are stated as facts about what vault **is not yet**, not as a roadmap (planned work lives in
`docs/plans/` / `docs/tasks/`):

- **On-disk persistence is opt-in, off by default.** Unset `--store-path` ⇒ the store is in-memory
  only and lost on restart ("encrypted at rest" then means at rest in **process memory**). Set ⇒ the
  encrypted store persists to a `0600` JSON file (ciphertext + non-secret metadata only; key off
  disk; handles never persist) loaded on startup and written-through on `put`/`rotate` (ADR-008). The
  persistence layer is **orthogonal** to the `StoreBackend` value-crypto seam (a `StoreFile`
  serializer, not a new backend), so a future cloud/KMS/HSM backend composes with it for free.
- **Not SPIFFE-bound / no cloud-KMS / HSM backends.** These sit behind the `vault://` /
  `StoreBackend` seam but are not built.
- **Vault-HTTP-API compatibility is a read-only, loopback-only subset, not a drop-in.** vault speaks
  the Vault KV-v2 read **shape** over an opt-in loopback HTTP surface (ADR-006), but a read returns a
  **handle**, never the value, and there are **no** HTTP writes (`put`/`rotate`) or value delivery
  (`inject`) — those stay on the `SO_PEERCRED`-gated Unix socket. Remote (non-loopback) and write
  compatibility wait on the auth/token model (roadmap row 6, externally blocked).
- **Not an egress proxy.** vault delivers the credential to the injection edge; the egress proxy
  itself lives in `exec-sandbox`, not here.
