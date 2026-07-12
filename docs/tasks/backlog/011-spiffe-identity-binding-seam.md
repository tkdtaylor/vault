# Task 011: SPIFFE identity binding seam (bind handles to a verified spiffe_id)

**Project:** vault
**Created:** 2026-07-11
**Status:** ready (mock issuer now; real verified-principal delivery blocked on agent-mesh 008)

> **Depends on agent-mesh task 008 — but executable now against a mock issuer.** Roadmap row 6 /
> Remaining-work **R1** names exactly this work ("bind handles to SPIFFE workload identities instead
> of opaque `sandbox_id` strings") and marks it blocked on agent-mesh providing per-workload identity.
> agent-mesh's task 008 (in flight) is publishing an **identity-propagation contract exposing verified
> principals `{spiffe_id, trust_tier}`** — that unblocks the *shape*. This task builds the vault-side
> **seam** (`PrincipalResolver`) plus a **mock issuer** validating that exact shape; the real
> agent-mesh-backed resolver lands later as one new trait impl behind the same seam. Do NOT claim the
> cross-repo end-to-end (a principal actually verified by agent-mesh) from a local run — the mock
> issuer trusts its input's shape, not its provenance; provenance is agent-mesh's half.

## Goal

Behind an explicit opt-in, make the handle's first-use binding key a **SPIFFE workload identity**
(the verified principal's `spiffe_id`) instead of the opaque `sandbox_id` string — so a handle first
injected by `spiffe://secure-agents.local/exec-sandbox/sbx-1` can never be presented by any other
workload identity. Default mode preserves today's opaque binding byte-for-byte. The
`PrincipalResolver` seam is the single landing spot for agent-mesh task 008's verified-principal
contract; a mock issuer implements it now.

## Context

- Roadmap: [roadmap](../../plans/roadmap.md) **row 6** ("SPIFFE identity binding" — ⛔ blocked → this
  task unblocks the vault side) and **R1** ("Gated on agent-mesh providing per-agent / per-workload
  SPIFFE identity. Today `inject` binds a handle to an opaque `sandbox_id` string (first-use binding)…
  Until then, the opaque-`sandbox_id` first-use binding is the v0/v1 behavior."). R1 asked for the
  workload-identity model before a task could be written; agent-mesh task 008's published contract
  shape — verified principals `{spiffe_id, trust_tier}` — is that model. This task aligns to it.
- **Where binding lives today:**
  - `src/vault.rs::inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>)` —
    the `sandbox_id` parameter IS the binding key: first use sets
    `rec.bound_sandbox = Some(sandbox_id.to_string())` on the `HandleRec`; a later mismatch returns
    `handle_bound_to_other_sandbox`; precedence is unknown_handle → consumed → expired →
    invalidated → binding → deliver (ADR-003/004). **None of this changes.** The task changes only
    *which string* flows in as the binding key when spiffe mode is on.
  - `src/main.rs::dispatch`, the `Some("inject")` arm — today extracts
    `req["sandbox_identity"]["sandbox_id"].as_str().unwrap_or("")`. In spiffe mode it instead
    resolves the verified principal and passes `principal.spiffe_id` as the binding key.
- **New module `src/principal.rs`** (house pattern: one module per concern):
  - `pub struct VerifiedPrincipal { pub spiffe_id: String, pub trust_tier: String }` — the
    agent-mesh task 008 contract shape, verbatim.
  - `pub trait PrincipalResolver: Send + Sync { fn resolve(&self, sandbox_identity: &serde_json::Value) -> Result<VerifiedPrincipal, PrincipalError>; }`
  - `pub enum PrincipalError { Missing, Invalid(String) }` → error codes `principal_missing` /
    `principal_invalid` in the standard `{error:{code,message,retryable:false}}` shape.
  - `pub struct MockIssuerResolver` — reads `sandbox_identity.principal.{spiffe_id,trust_tier}`,
    validates the shape (REQ-005), returns the principal. It is the spiffe-mode default until
    agent-mesh task 008 ships; its doc-comment states it validates shape, not provenance.
  - `pub fn validate_spiffe_id(s: &str) -> Result<(), String>` — the pure validator (REQ-005),
    unit-testable without a vault.
- **Wire shape (spiffe mode; superset of today's request):**

  ```json
  {"op":"inject","handle":"<hex64>","mode":"proxy",
   "sandbox_identity":{
     "sandbox_id":"sbx-1",
     "principal":{
       "spiffe_id":"spiffe://secure-agents.local/exec-sandbox/sbx-1",
       "trust_tier":"attested"
     }}}
  ```

  The `principal` member is agent-mesh's verified-principal block, propagated to vault by the
  caller (exec-sandbox / the orchestrator). Response shapes are byte-for-byte unchanged — no
  SPIFFE type leaks out (contract v1, no contracts bump; `handle_bound_to_other_sandbox` keeps its
  name — in spiffe mode "sandbox" reads as "workload", documented in `docs/spec/interfaces.md`).
- **Configuration (mirror `resolve_store_path` exactly):** flag `--identity-binding sandbox|spiffe`
  wins over env `VAULT_IDENTITY_BINDING`; both absent ⇒ `sandbox` (default — today's behavior);
  any other value ⇒ refuse to start (fail-fast, never a silent fallback on a security mode). A pure
  `resolve_identity_binding(flag, env) -> Result<BindingMode, String>` makes the precedence
  unit-testable.
- **SPIFFE ID validation (REQ-005 — the deliberate minimal subset of the SPIFFE spec):** scheme
  exactly `spiffe://`; non-empty lowercase trust domain of `[a-z0-9.-]`; non-empty path beginning
  `/`; no query (`?`) or fragment (`#`); total length ≤ 2048 bytes. Anything else ⇒
  `principal_invalid`. Full SPIFFE-spec conformance is out of scope (the real issuer — agent-mesh —
  owns issuance; vault only refuses obviously-invalid keys).
- **Composition with task 010 (neither blocks the other):** 010 makes the *sandbox identity*
  cryptographically verifiable (Ed25519 attestation at dispatch); 011 makes the *binding key* a
  SPIFFE principal. If both land, dispatch order is: peer-uid gate → attestation verify (010) →
  principal resolve (011) → `Vault::inject`. Whichever task lands second wires its step into the
  order above; each guards its own opt-in config, and each works with the other absent.
- **No new dependency.** The mock issuer and the validator are std + serde_json only — no SPIFFE
  crate, no workload-API client. (A real SVID/workload-API integration would be a future ask-first
  event, on agent-mesh's side of the seam.)
- **Constraint:** all invariants hold — `resolve` value-free, raise-only floor, single-use +
  first-use binding, fail-closed error shape, no secret ever logged; all prior tests (tasks
  001–008, 74 tests) pass unmodified; default mode is byte-for-byte today's behavior.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | In spiffe mode the handle's first-use binding key is the verified `spiffe_id` (asserted on the handle record: `bound_sandbox == Some(spiffe_id)`); in default (sandbox) mode it is the opaque `sandbox_id`, byte-for-byte today's behavior, `principal` member ignored. | must have |
| REQ-002 | Opt-in config: `--identity-binding` flag > `VAULT_IDENTITY_BINDING` env; values exactly `sandbox` (default) / `spiffe`; any other value refuses to start (no panic, no silent fallback); precedence is a pure unit-testable function. | must have |
| REQ-003 | Binding enforcement over the spiffe_id: replay with the same principal → `handle_consumed`; a bound-but-unconsumed handle presented by a different spiffe_id → `handle_bound_to_other_sandbox`; the whole URI is the key (no prefix matching); inject precedence order unchanged. | must have |
| REQ-004 | Fail-closed at the dispatch edge in spiffe mode: missing `principal` → `principal_missing`; malformed `spiffe_id` or missing/empty `trust_tier` → `principal_invalid`; standard error shape, `retryable:false`, no credential, `Vault::inject` never called, handle neither consumed nor bound. | must have |
| REQ-005 | `validate_spiffe_id` enforces the documented subset: `spiffe://` scheme, non-empty lowercase `[a-z0-9.-]` trust domain, non-empty `/`-prefixed path, no query/fragment, ≤ 2048 bytes. | must have |
| REQ-006 | Contract + invariants preserved: response shapes byte-for-byte unchanged; `resolve` value-free; raise-only floor; all prior tests (tasks 001–008) pass unmodified; `Vault::inject`'s signature and binding/precedence logic untouched. | must have |
| REQ-007 | Drop-in seam proven: a second `PrincipalResolver` impl substitutes behind the same wiring with no change to dispatch/`Vault`/contract — so agent-mesh task 008's real resolver lands as one new impl + a selection entry (the task-006 pluggability bar). | must have |

## Implementation outline

1. `scripts/start-task.sh 011 spiffe-identity-binding-seam` (branch or worktree; `cd` in if WORKTREE).
2. Write the ADR (next free number at execution time; 011 if task 010 has taken 010): the
   `PrincipalResolver` seam, the agent-mesh `{spiffe_id, trust_tier}` contract shape, the mock-issuer
   decision (shape-validation now, provenance later), the validation subset, the mode flag, and the
   `handle_bound_to_other_sandbox` name retention. Commit (`docs: add ADR NNN — …`).
3. Create `src/principal.rs`: `VerifiedPrincipal`, `PrincipalError`, `PrincipalResolver`,
   `validate_spiffe_id`, `MockIssuerResolver`; register `mod principal;` in `src/main.rs`.
4. In `src/main.rs`: `BindingMode` enum + pure `resolve_identity_binding(flag, env)`; `serve` reads
   `--identity-binding` / `VAULT_IDENTITY_BINDING`, refuses to start on an unknown value, and threads
   the mode + a `Box<dyn PrincipalResolver>` into `dispatch`; the `Some("inject")` arm in spiffe mode
   calls `resolver.resolve(&req["sandbox_identity"])`, maps `Err` to `principal_missing` /
   `principal_invalid`, and on `Ok(p)` calls `v.lock().unwrap().inject(handle, &p.spiffe_id, mode)`;
   sandbox mode keeps today's extraction verbatim. `demo()` stays in sandbox mode.
5. Tests per the test spec (TC-001…TC-006): dispatch-level spiffe flow, binding-key assertion on the
   handle record, data-driven malformed-id table with a valid control on the same handle, the
   two-resolver drop-in proof, and the default-mode byte-for-byte regression.
6. Spec updates in the same feat commit: `docs/spec/configuration.md` (flag/env row + refuse-to-start
   rule), `docs/spec/interfaces.md` (spiffe-mode request shape, the two new error codes, the
   binding-key semantics note), `docs/spec/behaviors.md` (binding-mode behavior),
   `docs/architecture/diagrams.md` (inject flow gains the principal-resolve step; date bump). Update
   the roadmap row 6 / R1 status line only with operator sign-off (docs/plans/ is ask-first).
7. `cargo build && cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`;
   `git mv` this file to `docs/tasks/completed/`; coverage-tracker row 🟡;
   `feat: complete task 011 — …`; then spec-verifier; then L5/L6 evidence in a separate `verify:`
   commit.

## Readiness gate

- [x] Test spec `011-spiffe-identity-binding-seam-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] The workload-identity model R1 required is pinned: agent-mesh task 008's verified-principal contract `{spiffe_id, trust_tier}` (mock issuer stands in for provenance)
- [x] No new dependency needed (std + serde_json only)

## Acceptance criteria

- [ ] [REQ-001] Spiffe-mode inject binds the handle to the spiffe_id (`bound_sandbox == Some(ID_A)` asserted); default mode binds to `sandbox_id` exactly as today (TC-002, TC-006).
- [ ] [REQ-002] Flag > env precedence; default `sandbox`; unknown value → refuse to start (TC-001).
- [ ] [REQ-003] Replay → `handle_consumed`; different spiffe_id on a bound handle → `handle_bound_to_other_sandbox` with a same-id valid control; whole-URI key (TC-002, TC-003).
- [ ] [REQ-004] Missing principal → `principal_missing`; malformed id / empty tier → `principal_invalid`; no credential, handle untouched, valid control succeeds afterward on the same handle (TC-004).
- [ ] [REQ-005] `validate_spiffe_id` accepts/rejects the documented table exactly (TC-004).
- [ ] [REQ-006] Response shapes unchanged; 74 prior tests pass unmodified (TC-006).
- [ ] [REQ-007] Two resolvers substitute behind the seam with no core change; extension point documented (TC-005).
- [ ] `cargo build && cargo test` green; ADR written; spec/diagram updates in the feat commit.

## Verification plan

- **Highest level achievable:** **L6 locally** for the vault-side seam (spiffe-mode binding and
  rejections observable on a live socket with mock-issuer principals). The cross-repo end-to-end
  (agent-mesh actually issuing/verifying the principal) is NOT achievable until agent-mesh task 008
  ships — do not claim it; record the mock-issuer scope honestly in the `Verified by` column.
- **Level 5 — validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — TC-001…TC-006 (config precedence + refuse-to-start,
  spiffe bind-and-deliver with the binding-key assertion, wrong-principal rejection with valid
  control, the data-driven malformed-id table, the two-resolver drop-in proof, default-mode
  regression), plus all 74 prior tests unmodified.
- **Level 6 — runtime observation:** `cargo run -- serve --socket /tmp/v011.sock --identity-binding
  spiffe`; over the socket: put → resolve → (a) inject with a valid ID_A principal → observe
  delivery; (b) replay → observe `handle_consumed`; (c) fresh handle, inject with **no** principal →
  observe `principal_missing`; (d) inject with `"spiffe_id":"http://x/y"` → observe
  `principal_invalid`; (e) restart with no flag and replay today's plain request → observe delivery
  (default mode live). Also observe `--identity-binding bogus` refusing to start (non-zero exit).
  Quote the socket transcripts.
- **Level 3 (supporting):** `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` clean;
  no `Cargo.toml`/`Cargo.lock` diff (no new dependency).
- **ADR owed:** `docs/architecture/decisions/NNN-spiffe-identity-binding-seam.md` (next free number
  at execution time).

## Out of scope

- Provenance: verifying that the principal was actually issued/attested by agent-mesh (its task 008
  publishes the contract; a later task swaps the mock issuer for the real resolver — one impl behind
  this seam). The mock issuer validates shape only.
- SVID issuance, X.509/JWT SVID parsing, the SPIFFE Workload API, trust-domain federation, and full
  SPIFFE-spec ID conformance beyond the documented subset.
- Mapping `trust_tier` to injection-floor policy (the tier is carried on `VerifiedPrincipal` and
  validated non-empty; using it to raise floors is a separate future task — raise-only would still
  hold).
- Task 010's attestation verification (composes at dispatch; neither blocks the other).
- Any change to `Vault::inject`'s signature, `HandleRec`, error codes, or the v1 contract response
  shapes.

## Dependencies

- **Blocked-by (provenance half only):** agent-mesh task 008 — the published identity-propagation
  contract with verified principals `{spiffe_id, trust_tier}`. The seam, mock issuer, config, and
  binding semantics land NOW; the real resolver is a follow-up impl behind `PrincipalResolver`.
- Builds on: the v0 first-use binding machinery in `src/vault.rs` (unchanged, reused), task 001's
  dispatch-edge layering, task 004's fixed-key test backend. No new crate. Composes with task 010
  (verify-then-resolve order); independent of tasks 006/007/008.
- Roadmap alignment: closes the vault side of row 6 / R1 (the row flips from ⛔ to the mock-issuer
  posture only via an ask-first roadmap edit, step 6).
