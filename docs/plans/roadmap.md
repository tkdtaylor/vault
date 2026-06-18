# Roadmap — vault

The JIT zero-knowledge secret store + credential broker for autonomous agents: answers one
question — *does the agent core ever see a credential in plaintext?* The answer is **no**. The
agent holds only an opaque, single-use **handle**; the plaintext is injected at the host
boundary, into `exec-sandbox`, at the moment of execution, then wiped. The `vault://` scheme +
Vault HTTP API path semantics are the adapter seam, so the backend (local encrypted store,
OpenBao, HashiCorp Vault, cloud KMS, HSM) can be swapped without touching callers.

Authoritative design: the project's internal design notes
+ `interface-contracts.md §2 (v1)`. As-built foundational stack:
[ADR-001](../architecture/decisions/001-foundational-stack.md).

## v0 — resolve/inject broker + single-use handles + raise-only floor — ✅ shipped

Working today (`main.rs`/`vault.rs`/`handle.rs`): the `resolve(secret_ref) -> {handle, ttl,
injection_mode}` contract (mints an opaque single-use handle, **never returns the value**);
`inject(handle, sandbox_identity, mode)` pull-triggered push with the `proxy`/`env` delivery
split; **raise-only** effective mode (`max(secret_floor, requested)` — vault raises, never
lowers); single-use enforcement + first-use sandbox binding (replay → `handle_consumed`, wrong
sandbox → `handle_bound_to_other_sandbox`); fail-closed on unknown handle/secret/op; 32-byte
`/dev/urandom` capability handles; out-of-process over a uid-restricted (0600) Unix-socket JSON
IPC server (`serve --socket`), plus an in-process `demo`. Pure Rust, `serde`-only. The `vault://`
scheme + the `inject` `{credential, binding}` return are the adapter seam — backends and
hardening slot in behind them without changing the contract.

## v1 — Store-level zero-knowledge + handoff hardening + admin surface

Each item a self-contained task. The contract (`resolve`/`inject`/admin verbs) stays the swap
point — hardening and richer backends slot in **without changing the contract or any caller**.
The load-bearing invariants (agent never sees plaintext, raise-only floor, single-use binding,
fail-closed, memory-safe path) hold across every task; a change that violates one is a blocker,
not a trade-off.

| # | Work | Status |
|---|------|--------|
| 1 | **SO_PEERCRED peer-uid check on the socket** — completes the D5 handoff scheme. Today the socket is uid-restricted by 0600 file perms only; add a kernel-level peer-uid assertion (`SO_PEERCRED`) so a caller's uid is verified, not just inferred from perms. | ✅ ready — **task 001** |
| 2 | **TTL auto-wipe clock** — `ttl` is stored on the handle but not enforced (`#[allow(dead_code)]` in `vault.rs`). Expire handles past their TTL (`resolve` → `inject` window), and fill the env-mode `wiped_at` timestamp instead of the `0` placeholder. | ✅ ready — **task 002** |
| 3 | **Wire `get`/`list`/`rotate` admin verbs** — the contract defines them (metadata only, never the value) but only `put` is in the IPC `dispatch` today. Add the three verbs, value-free, fail-closed. | ✅ ready — **task 003** |
| 4 | **Encrypted-at-rest store** — the headline store-level zero-knowledge upgrade. AES-256-GCM with client-side / age-style encryption so the v0 in-memory plaintext store becomes encrypted-at-rest; the key never lands beside the ciphertext. Behind the backend seam. | ✅ ready — **task 004** |
| 5 | **Vault HTTP API compatibility** — expose the `vault://` path semantics over the Vault HTTP API shape so existing Vault clients/backends interoperate through the seam. | 🔜 planned (larger; sequence after 001–004) |
| 6 | **SPIFFE identity binding** — bind handles to SPIFFE workload identities instead of opaque `sandbox_id` strings. | ⛔ **blocked** (external identity from agent-mesh) — see *Remaining work* → R1. |
| 7 | **Cloud-KMS / HSM backends** — PKCS#11 HSM and AWS/GCP/Azure secret-manager backends behind the `vault://` seam. | 🔜 planned (larger; external deps; sequence after 004) |

Tasks 001–004 are the executable v1 increment **within this repo** — self-contained, no external
blockers, concrete acceptance criteria. They are the autopilot runway. Rows 5 and 7 are larger
and sequenced after the core; row 6 is externally blocked (below). The working v0 source is **not
rewritten** — v1 work extends it behind the contract + backend seam.

## Remaining work — blocked / decisions needed

### R1 — SPIFFE identity binding (row 6) — blocked: external identity
Gated on **agent-mesh** providing per-agent / per-workload SPIFFE identity. Today `inject` binds
a handle to an opaque `sandbox_id` string (first-use binding). **Needed before a task can be
written:** the workload-identity model (SPIFFE SVID issuance, trust domain, how exec-sandbox
presents a verifiable identity) so the binding can assert a real identity rather than a string.
Until then, the opaque-`sandbox_id` first-use binding is the v0/v1 behavior.

### R2 — Cloud-KMS / HSM backends (row 7) — decision needed (not externally blocked)
The `vault://` seam supports pluggable backends, but which to build first (PKCS#11 HSM vs. a
cloud secret-manager vs. OpenBao passthrough) is a product/deployment-target call. **Decision:**
pick the first backend target before planning a task. Builds on task 004's backend seam.

## Notes for the orchestrator

This repo is built out one task at a time by **agent-builder** (and drivable via `/autopilot`):
it reads this roadmap + `docs/tasks/backlog/NNN-*.md`, builds the next ready task, runs the
verification gate (`cargo build && cargo test`, plus dep-scan/code-scanner on any new crate), and
integrates it. The working v0 source (`main.rs`, `vault.rs`, `handle.rs`) is **not rewritten** —
v1 work extends it behind the contract + backend seam. Adding a dependency (e.g. `nix` for
SO_PEERCRED, an AES-GCM crate for task 004) is an "ask-first" event: it must clear dep-scan and be
recorded in the task's ADR, because vault's whole point is a minimal, auditable secret-handling
path.
