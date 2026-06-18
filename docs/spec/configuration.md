# Configuration

**Project:** vault
**Last updated:** 2026-06-18

Every knob the system exposes. vault is configured by **command-line flags**, the per-secret fields
supplied to `put`, and a small set of **application environment variables** (the at-rest master key
and the opt-in store path) — there are no config files.

Not here: what gets configured ([behaviors.md](behaviors.md)); the parsing lives in `src/main.rs`.

---

## Configuration files

**None.** No config file. Secrets are supplied inline via the `put` op; the socket path is supplied
inline via `--socket`. There is no external policy source to point at. The store is in-memory by
default; an **opt-in** persistent encrypted store file is enabled with `--store-path PATH` /
`VAULT_STORE_PATH` (a JSON ciphertext store, **not** a config file — ADR-008).

---

## Runtime flags

| Flag | Subcommand | Type | Default | Required | Effect |
|------|------------|------|---------|----------|--------|
| `--socket` | `serve` | string (path) | — | yes (serve) | Unix socket to bind; a stale socket at the path is removed first; bound `0600` |
| `--http-addr` | `serve` | string (`HOST:PORT`) | — (absent → no HTTP listener) | no | **Opt-in** loopback HTTP read surface (ADR-006). Present → bind a read-only HTTP listener sharing the same `Vault`, but **only if** the host is literal `127.0.0.1`; a non-loopback host is **refused fail-closed** (logged, no bind). Absent → the Unix socket serves exactly as before |
| `--store-path` | `serve` | string (path) | — (absent → in-memory only) | no | **Opt-in** persistent encrypted store (ADR-008). Present → load the encrypted store from `PATH` on startup and write-through every `put`/`rotate` atomically (`0600` JSON, ciphertext + metadata only). Falls back to `VAULT_STORE_PATH` if the flag is absent (**flag wins**). Absent → in-memory only, byte-for-byte today's behavior (no file read/written) |

`demo` takes no flags. A missing subcommand or a `serve` without `--socket` → usage error (exit `2`).
A `serve` whose `--store-path` file is present but **corrupt** (bad JSON / unknown version / invalid
base64 / wrong-length nonce) **refuses to start** with a logged diagnostic and a non-zero exit
(`1`) — the store is never silently emptied (ADR-008 §8). A **missing** file is a fresh empty store
(first run), not an error.

**`--http-addr` is loopback-only and fail-closed.** The HTTP read surface (`GET /v1/sys/health`,
`GET /v1/secret/data/:path`) is zero-knowledge — a read returns the handle in a Vault KV-v2 envelope,
never the value — and read-only (`inject`/`put`/`rotate`/`get`/`list` are not routed). Because vault
has no auth/token model yet, the listener binds `127.0.0.1` **only**; a non-loopback `--http-addr`
(`0.0.0.0`, a LAN IP, `::`, or unparseable) is refused with a logged message and **no bind** — there
is no operator knob to widen it. Remote exposure waits on the auth model (roadmap row 6). See
[interfaces.md](interfaces.md) for the endpoints and the error→status mapping.

---

## Per-secret configuration (supplied to `put`)

Each secret carries two policy-relevant fields, set at `put` time
([data-model.md](data-model.md)):

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `injection_floor` | `env` \| `proxy` | `env` | The **minimum** mode any later `inject` may deliver. `inject` delivers at `max(injection_floor, requested)` — **raise-only** |
| `binding.host` | string | `""` | Egress host the proxy injects the credential for (proxy mode) |
| `binding.header` | string | `Authorization` | HTTP header the proxy sets (proxy mode) |
| `binding.scheme` | string | `Bearer` | Auth scheme prefix (proxy mode) |
| `binding.env_var` | string | `API_KEY` | Env var name the credential is set as (env mode → returned as `var_name`) |

**Injection floor is a security parameter, not just a default.** `env` is the conservative
baseline; `proxy` (value never enters the sandbox) is stronger. vault may raise the floor at
`inject` (honoring policy-engine's `vault_injection_floor` obligation) but **never lowers** it.

---

## Socket permissions

The `serve` socket is bound `0600` (owner-only) — the file-mode half of the secured vault→proxy
handoff (D5): the filesystem ACL stops other uids from connecting, alongside the unguessable
single-use handle and the first-use sandbox binding.

On top of `0600`, every accepted connection is gated by a kernel-verified **`SO_PEERCRED` peer-uid
check** (`src/main.rs::handle_conn`, ADR-002): vault reads the connecting peer's uid from the kernel
and admits the connection only if it equals the server's own effective uid (`geteuid`) — equality,
not privilege; root is denied unless it is the server's uid. A mismatched or unreadable peer
credential is rejected fail-closed with `peer_uid_denied` and no op runs. There is no configuration
knob for the allowed uid — it is always the server's own uid by construction. Tracked as fitness
rule F-006.

---

## Store-file permissions and atomicity (`--store-path`)

When `--store-path PATH` is set, the persistent store file is written **`0600`** (owner-only) — the
on-disk analogue of the `0600` socket: the filesystem ACL stops other uids from reading the
ciphertext. The write is **atomic, crash-safe, and safe-by-construction**: a temp file
`<PATH>.tmp.<hex>` in the same directory is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode
`0o600` set **at creation** (not chmod-after-open — there is no umask-mode window), where `<hex>` is
fresh random bytes from `/dev/urandom` so the temp path is unpredictable across restarts. A
pre-existing temp path — a planted symlink or a stale temp — is an **error** (`O_EXCL`), never
silently reused, and the open refuses to follow a symlink (`O_NOFOLLOW`), closing the symlink/TOCTOU
arbitrary-overwrite vector (SEC-001). Then `write_all` + `fsync`, an atomic `rename` over `PATH`,
and finally an **`fsync` of the parent directory** so the rename's directory-entry update itself
survives a crash (SEC-002). A crash mid-write leaves either the old complete file or the temp file
— never a half-written store. A failed write surfaces `store_persist_failed` and rolls back the
in-memory mutation (ADR-008 §4). The file holds **ciphertext + nonce + non-secret metadata only** —
the master key and the cleartext are never written, and **handles never persist** (ADR-008 §5/§6).

**Operator invariant — store-directory posture (SEC-003).** The `--store-path` **parent
directory** MUST be owned by the vault uid and **not group- or world-writable**. The `0600` file
protects the store's *contents*, but a writable directory is the surface for temp-path games
(planting a symlink at the temp name, racing the rename). FIX 1's `O_EXCL`/`O_NOFOLLOW`/random
suffix already closes the active vector; the directory restriction is defense-in-depth and is the
operator's responsibility. At `serve` startup with a store path set, vault emits a **non-fatal
stderr WARNING** if the parent directory is group/world-writable (it does **not** refuse to start,
and never logs any secret — only the directory path and its mode).

---

## Environment variables

**Application — the at-rest master key (ADR-005):** the AES-256-GCM store key is sourced from the
environment via the key-provider seam (`EnvKeyProvider`), in precedence order:

| Var | Type | Effect |
|-----|------|--------|
| `VAULT_MASTER_KEY_FILE` | path | File whose contents are the 32-byte master key (hex `64`-char or base64). Takes precedence over the inline var. |
| `VAULT_MASTER_KEY` | string | The 32-byte master key inline (hex or base64). Used if `…_FILE` is unset. |

**Application — the persistent store path (ADR-008):**

| Var | Type | Effect |
|-----|------|--------|
| `VAULT_STORE_PATH` | path | Fallback source for `--store-path` (the flag wins). Set → opt-in persistent encrypted store at this path; unset (and no flag) → in-memory only. |

The key is decoded to **exactly 32 bytes** (anything else is an error). It is held only in the
backend's memory — **never serialized into the store, never logged**. A **missing/unreadable/wrong-
length key fails the store closed**: `put` stores nothing and `inject` returns `decrypt_failed` —
there is no plaintext fallback. The `demo` subcommand needs **no** key: it generates a self-contained
ephemeral 32-byte key for the process.

**Hook profile env vars** (consumed by `.claude/scripts/`, not the application):
- `CLAUDE_HOOK_PROFILE` — `minimal` / `standard` / `strict` (default `standard`)
- `CLAUDE_DISABLED_HOOKS` — comma-separated list of hook names to disable

---

## Secrets

vault's entire job is **holding secrets** — but it holds them in its own process memory (and, at
`inject`, delivers them to the injection edge). It never returns a value from `resolve`, never logs
a value, and never writes a value to the repo.

| Secret | Source | Used for |
|--------|--------|----------|
| Application credentials (API keys, tokens) | supplied at runtime via the `put` op | minted into single-use handles (`resolve`); delivered to the injection edge (`inject`) |
| AES-256-GCM master key (32 bytes) | `VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE` (operator-supplied) | encrypts every stored value at rest; held only in backend memory, off the ciphertext (ADR-005) |

The stored value is **AES-256-GCM ciphertext at rest** — in process memory always, and (with
`--store-path` set) on disk in the `0600` store file — decrypted only at the injection edge. The
master key (above) is the protection on the value at rest, and it lives off the ciphertext **and off
the store file**. A stolen store file is inert without the separately-held key (ADR-008).

**Rule:** secrets — application credentials **and the master key** — are never pasted into chat,
logged, or written into the repo. The `protect-secrets` hook blocks writes to common credential
filenames. The demo's `SK-DEMO-DO-NOT-LEAK` is an obvious non-secret placeholder, and the demo's key
is an ephemeral in-process value.

---

## Deployment configuration

| Aspect | Value | Notes |
|--------|-------|-------|
| Artifact | single static Rust binary (`vault`) | `cargo build` → `target/release/vault` |
| Socket | Unix domain socket at `--socket` path | `chmod 0600` **plus** an `SO_PEERCRED` peer-uid check (admit iff peer uid == server uid); co-located with the agent, not network-exposed |
| Ports exposed | none by default; **opt-in** loopback TCP via `--http-addr 127.0.0.1:PORT` | The HTTP read surface (ADR-006) is off unless `--http-addr` is passed, and binds `127.0.0.1` only (a non-loopback bind is refused fail-closed). Read-only + zero-knowledge — never delivers a value |
| On-disk store | none by default; **opt-in** `0600` JSON file via `--store-path PATH` / `VAULT_STORE_PATH` | The persistent encrypted store (ADR-008) is off unless a path is set. Ciphertext + non-secret metadata only; key off-disk, handles never persist; atomic `0600` write-through on `put`/`rotate`; refuse-to-start on a corrupt file |
| Runtime dependencies | `serde` + `serde_json` + `nix` (socket+user) + `aes-gcm` 0.10.3 (AES-256-GCM) + `tiny_http` 0.12 (HTTP read surface) | `nix` supplies `SO_PEERCRED`/`geteuid` for the peer-uid gate (ADR-002); `aes-gcm` 0.10.3 supplies the at-rest AEAD (ADR-005), pinned to the stable line (the 0.11 RC was rejected) and dep-scan-cleared; `tiny_http` 0.12 (sync, thread-per-connection — no async runtime) supplies the opt-in loopback HTTP read surface (ADR-006), pinned and dep-scan-cleared (tree: `ascii`/`chunked_transfer`/`httpdate`/`log`); no `rand` crate (RNG/nonces via `/dev/urandom`); dep-scan / code-scanner are blocking gates for any further crypto/dependency change |
| Master key | `VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE` (32 bytes, hex/base64) | required for a production `serve` (store fails closed without it); `demo` uses an ephemeral in-process key |

---

## Defaults policy

Defaults are **safe / fail-closed**: the per-secret `injection_floor` defaults to `env` (the
conservative baseline that `inject` may still raise, never lower); `--socket` has no default (the
operator must name it explicitly rather than risk binding a surprise path). No path defaults to
returning or delivering a value the floor would forbid.
