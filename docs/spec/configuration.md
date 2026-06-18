# Configuration

**Project:** vault
**Last updated:** 2026-06-18

Every knob the system exposes. vault is configured entirely by **command-line flags** and the
per-secret fields supplied to `put` in v0 — there are no config files and no application
environment variables.

Not here: what gets configured ([behaviors.md](behaviors.md)); the parsing lives in `src/main.rs`.

---

## Configuration files

**None.** No config file. Secrets are supplied inline via the `put` op; the socket path is supplied
inline via `--socket`. There is no external policy or store-config source to point at (the v0 store
is in-memory).

---

## Runtime flags

| Flag | Subcommand | Type | Default | Required | Effect |
|------|------------|------|---------|----------|--------|
| `--socket` | `serve` | string (path) | — | yes (serve) | Unix socket to bind; a stale socket at the path is removed first; bound `0600` |

`demo` takes no flags. A missing subcommand or a `serve` without `--socket` → usage error (exit `2`).

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

## Environment variables

**Application — the at-rest master key (ADR-005):** the AES-256-GCM store key is sourced from the
environment via the key-provider seam (`EnvKeyProvider`), in precedence order:

| Var | Type | Effect |
|-----|------|--------|
| `VAULT_MASTER_KEY_FILE` | path | File whose contents are the 32-byte master key (hex `64`-char or base64). Takes precedence over the inline var. |
| `VAULT_MASTER_KEY` | string | The 32-byte master key inline (hex or base64). Used if `…_FILE` is unset. |

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

The stored value is **AES-256-GCM ciphertext at rest** (in process memory), decrypted only at the
injection edge — the master key (above) is the protection on the value at rest, and it lives off the
ciphertext. There is no on-disk persistence yet.

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
| Ports exposed | none | IPC is a Unix socket, not a TCP port |
| Runtime dependencies | `serde` + `serde_json` + `nix` (socket+user) + `aes-gcm` 0.10.3 (AES-256-GCM) | `nix` supplies `SO_PEERCRED`/`geteuid` for the peer-uid gate (ADR-002); `aes-gcm` 0.10.3 supplies the at-rest AEAD (ADR-005), pinned to the stable line (the 0.11 RC was rejected) and dep-scan-cleared; no `rand` crate (RNG/nonces via `/dev/urandom`); dep-scan / code-scanner are blocking gates for any further crypto change |
| Master key | `VAULT_MASTER_KEY` / `VAULT_MASTER_KEY_FILE` (32 bytes, hex/base64) | required for a production `serve` (store fails closed without it); `demo` uses an ephemeral in-process key |

---

## Defaults policy

Defaults are **safe / fail-closed**: the per-secret `injection_floor` defaults to `env` (the
conservative baseline that `inject` may still raise, never lower); `--socket` has no default (the
operator must name it explicitly rather than risk binding a surprise path). No path defaults to
returning or delivering a value the floor would forbid.
