# Architecture — C4 Element Catalog

**Project:** vault
**Last updated:** 2026-06-18

The structured catalog of architectural elements that
[`../architecture/diagrams.md`](../architecture/diagrams.md) renders. Tables here are the
machine-readable spec for the structure — a drift audit checks the code against them.

---

## 1. Persons (actors)

| Name | Description | Goals |
|------|-------------|-------|
| Autonomous agent core | The agent runtime that needs a credential to perform an action | Get a `resolve` handle (never the value) it can pass to exec-sandbox |
| Operator | Human running the daemon, seeding secrets, or running the demo | Start `serve`; `put` secrets; run `demo` to verify the single-use invariant |

---

## 2. Systems

| Name | Type | Description | Owner |
|------|------|-------------|-------|
| vault | In-scope | JIT zero-knowledge secret store + credential broker; `resolve`/`inject` | This team |
| exec-sandbox | External | Presents `{handle, sandbox_identity}` at spawn; receives the credential at the injection edge (egress proxy / env-setter) | secure-agent ecosystem |
| policy-engine | External | Emits the raise-only `vault_injection_floor` obligation vault honors | secure-agent ecosystem |
| audit-trail | External | Records the handle lifecycle; **never** the value | secure-agent ecosystem |

Note: the **value** crosses only the vault↔exec-sandbox injection edge. policy-engine influences
vault indirectly via the raise-only floor, honored as `max(secret_floor, requested)`.

---

## 3. Containers

| Name | Technology | Responsibility | Source path | Depends on |
|------|------------|----------------|-------------|------------|
| vault binary | Rust (edition 2021) single static binary | Store secrets, mint single-use handles (`resolve`), and broker credential delivery to the injection edge (`inject`); serve over a uid-restricted Unix socket or a one-shot demo | `src/main.rs`, `src/vault.rs`, `src/handle.rs` | `serde`, `serde_json`, `nix` (socket+user, for `SO_PEERCRED`/`geteuid`) |

**Invariants for this table**
- The single container corresponds to the one binary crate `vault` (the single-binary layout,
  ADR-001 §2).
- Runtime dependencies are **`serde` + `serde_json` + `nix`** (`nix` pulls `SO_PEERCRED`/`geteuid`
  for the peer-uid gate, ADR-002, minimal `socket`+`user` features); randomness is `/dev/urandom`
  (no `rand` crate). Each added crate makes dep-scan / code-scanner blocking gates — `nix`'s tree was
  cleared on adoption (ADR-002); a crypto crate for encrypted-at-rest is the next such gate
  (ADR-001 §2 consequences).

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| vault binary | CLI / IPC server | `src/main.rs` | Parse `serve`/`demo` subcommands and `--socket`; bind the `0600` Unix socket (remove stale first); gate every accept with the kernel-verified `SO_PEERCRED` peer-uid check (`peer_uid_allowed`, equality not privilege, fail-closed) before dispatch; frame newline-delimited JSON; dispatch `ping`/`put`/`resolve`/`inject` over an `Arc<Mutex<Vault>>`; run the in-process demo | Vault broker |
| vault binary | Vault broker | `src/vault.rs` | The in-memory store + handle table; `put`/`resolve`/`inject`; the `Mode` (env/proxy, ranked), `Binding`, and `Clock` (injectable, `SystemClock` default) types; raise-only floor `max(secret_floor, requested)`; single-use + first-use sandbox binding; TTL expiry (`now >= expires_at`, `handle_expired`); fail-closed errors. The single seam every future backend replaces | Handle generator |
| vault binary | Handle generator | `src/handle.rs` | `new_handle()` — 32 random bytes from `/dev/urandom` (OS CSPRNG), hex-encoded; the opaque single-use capability token | — (std only) |

---

## 5. Cross-cutting decisions

- **Zero-knowledge to the agent core** — `resolve` returns a handle, never the value; plaintext
  lives only in vault's memory and at the injection edge.
  ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **Raise-only injection floor** — `inject` delivers at `max(secret_floor, requested)`; never
  lowers. (ADR-001 §5)
- **Single-use handles + first-use sandbox binding (D5)** — consumed once, bound to the first
  sandbox; replays / other sandboxes rejected. (ADR-001 §6)
- **`vault://` backend adapter seam** — the `resolve`/`inject` contract + `vault://<scope>/<key>`
  scheme is backend-agnostic; the in-memory store can be swapped for an encrypted local store /
  OpenBao / cloud KMS / HSM without changing callers. (ADR-001 §4)
- **Fail-closed** — every non-delivery path resolves to a structured error; no credential delivered.
  (ADR-001 §8)
- **Memory-safe language** — Rust for the crown-jewel secret path. (ADR-001 §2)
- **Uid-restricted Unix socket** — the D5 handoff travels a `0600` socket, and every accept is gated
  by a kernel-verified `SO_PEERCRED` peer-uid check (admit iff `peer_uid == server_uid`, fail-closed)
  before dispatch (fitness F-006). (ADR-001 §6, §7; ADR-002)

---

## Maintenance

- Update in the same commit as `../architecture/diagrams.md` when structure changes.
- Supersede in place; never append. The ADR carries the *why*.
- The drift-audit mode of the `architect` agent uses this catalog against the module graph and the
  deployable-artifact list. The dependency set (`serde` + `serde_json` + `nix`) is recorded in
  Container §3 `Depends on`; a new crate (e.g. a crypto dependency) updates that cell in the same commit.
