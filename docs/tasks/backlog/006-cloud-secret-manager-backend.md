# Task 006: Cloud secret-manager backend (behind the StoreBackend seam)

**Project:** vault
**Created:** 2026-06-18
**Status:** blocked

> **BLOCKED — plannable now, executable later.** Execution is blocked on two prerequisites from
> [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md) "Open items /
> blockers": (1) **confirm the concrete cloud** (AWS Secrets Manager is the reference unless the
> operator says otherwise — this fixes the SDK/REST dependency), and (2) **live cloud credentials +
> a reachable secret-manager** for the end-to-end L5/L6 inject. The **cloud-agnostic core** (the
> `SecretManagerBackend` + the `SecretManagerClient` trait) is **fully unit-verifiable locally**
> against a mock client — exactly how task 004 proved the `StoreBackend` seam — and that is the bulk
> of this task. The **live adapter** path is not achievable in a local / credential-free run. Do not
> claim L5/L6 from a local run.

## Goal

Add a **cloud secret-manager `StoreBackend`** behind task 004's seam: at the injection edge, `inject`
resolves the plaintext credential by calling a cloud provider's "get secret value" API instead of
decrypting a local AES ciphertext. To keep the seam vendor-neutral, split the backend into a
cloud-agnostic `SecretManagerBackend: StoreBackend` (owns put / rotate / fetch-at-inject and the
zero-knowledge invariants) delegating the actual fetch/store to a `SecretManagerClient` trait
(`get_value` / `put_value` / `rotate_value`) — **the single, documented pluggability seam**.

**Pluggability is a first-class requirement (operator directive).** Ship **2–3 reference adapters
as worked examples** — **AWS Secrets Manager**, **GCP Secret Manager**, and **Azure Key Vault** (or
HashiCorp Vault / OpenBao via the ADR-006 HTTP shape) — each ~one file implementing the trait
against that store's API, sharing zero secret-path logic. Backend selection is config-driven (e.g.
`--secret-backend aws|gcp|azure`). Adopting a **different** store must require **only dropping in one
new `SecretManagerClient` implementation + a selection entry** — nothing in `SecretManagerBackend`,
`Vault`, the contract, or any caller changes. Gate each live adapter behind a Cargo **feature** so an
operator compiles in only the stores they use; the trait + a mock client need no feature. The
contract is unchanged.

## Context

- Direction: [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md) (Accepted,
  execution deferred) — the binding decision for roadmap **Row 7 / R2**. No new ADR is needed; ADR-007
  covers this task.
- Seam this plugs into: [ADR-005](../../architecture/decisions/005-encrypted-at-rest-store.md) §5/§6 —
  the `StoreBackend` trait (`encrypt(&str) -> EncryptedValue`, `decrypt(&EncryptedValue) -> String`)
  in `src/crypto.rs`, wired in `src/vault.rs` (`Vault.backend: Box<dyn StoreBackend>`,
  `with_clock_and_backend`). The new backend is a second `StoreBackend` implementation; `resolve` /
  `inject` / callers do not change. `encrypt` returns an opaque locator (the remote secret id +
  version), `decrypt` fetches the live value via the client — the AES nonce/cipher path is **not**
  used on this backend.
- Roadmap: [roadmap](../../plans/roadmap.md) v1 Row 7 ("Cloud-KMS / HSM backends") and Remaining
  work **R2** ("which to build first … is a product/deployment-target call" — settled to cloud
  secret-manager by ADR-007). Builds on task 004's backend seam.
- Reference: [`docs/spec/SPEC.md`](../../spec/SPEC.md) (zero-knowledge invariant),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (store), [`docs/CONTRACT.md`](../../CONTRACT.md)
  (v1 contract — unchanged here).
- **Dependencies:** the `StoreBackend` seam from **task 004** (✅ shipped). The concrete cloud adapter
  pulls a cloud SDK (e.g. `aws-sdk-secretsmanager`) **or** a hand-rolled REST + request-signing path —
  a **large** new dependency tree. This is an **ask-first** event (CLAUDE.md): it must clear
  `dep-scan` as a **blocking** gate and be **version-pinned**, the same gate applied to `nix`,
  `aes-gcm`, and `tiny_http`. Prefer the smallest viable surface — evaluate REST+signing **and** the
  full SDK under dep-scan and pick the smaller tree that clears. No cloud SDK is added until the
  concrete cloud is confirmed.
- **Constraint:** the contract is unchanged — `resolve` still returns no value; `inject` still returns
  the plaintext `credential` at the edge (now via the remote provider's get-value call). Fail-closed:
  a failed/denied remote fetch → a structured error (`backend_unavailable`), **never** a plaintext
  fallback. Raise-only floor, single-use + first-use binding, TTL, and the peer-uid gate (tasks
  001/002) all hold — they live above the seam in `vault.rs`, so they are backend-independent.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `put` stores the value through the `SecretManagerClient` (the remote), **not** as cleartext in vault's in-process `Secret`; the in-process struct holds only an opaque remote locator. The value re-materialises only at `inject`. | must have |
| REQ-002 | `inject` fetches and returns the correct plaintext `credential` via the client's `get_value` **only at delivery time** (the injection edge), not at `resolve`; the `inject`/`resolve` response shapes are byte-for-byte the existing contract (no provider/AEAD type leaks). | must have |
| REQ-003 | Fail-closed: a denied / unavailable / not-found remote fetch → `{error:{code:"backend_unavailable",…}}`, **no** credential, **no** plaintext fallback, **no** panic; the fetch happens **before** the single-use handle is consumed (a transient remote failure does not burn the handle). | must have |
| REQ-004 | `rotate` updates the value through the client; the generation counter still bumps so every pre-rotation handle is invalidated (`handle_invalidated`), consistent with task 003. A failed `rotate_value` leaves the prior remote value untouched. | must have |
| REQ-005 | `SecretManagerBackend` sits behind the existing `StoreBackend` seam and is swappable for `AesGcmBackend` with **no** change to `resolve`/`inject`/`put`/`rotate` signatures or contract responses; the per-cloud adapter sits behind the `SecretManagerClient` trait so the core is testable without network. | must have |
| REQ-006 | Zero-knowledge preserved over the new backend: the value appears in **no** `resolve` / `get` / `list` response and **not** in the in-process `Secret`; it lives only in the remote and re-materialises only at `inject`. | must have |
| REQ-007 | **Pluggability (drop-in):** ship **2–3** `SecretManagerClient` adapters (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) behind the one trait, each Cargo-**feature**-gated; a new store is reachable by adding **one** trait impl + a selection entry, with **no** change to `SecretManagerBackend`/`Vault`/the contract. A test substitutes ≥2 distinct adapters (mock-level) to prove the seam. | must have |
| REQ-008 | A concrete adapter performs a live get-value round-trip end-to-end against its store (credential-gated — the L5/L6 evidence), for each cloud whose credentials are supplied. | must have *(credential-blocked)* |
| REQ-009 | **Each** shipped adapter's dependency tree clears `dep-scan check --lockfile Cargo.lock --lockfile-type crates` (blocking) and is version-pinned; the smaller of {full SDK, REST+signing} that clears is preferred per store. | must have |

## Readiness gate

- [x] Test spec `006-cloud-secret-manager-backend-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [ ] **BLOCKED — unmet prerequisites (ADR-007 blockers):**
  - [ ] Adapter set confirmed for the first cut (default: AWS Secrets Manager + GCP Secret Manager + Azure Key Vault; operator may adjust)
  - [ ] Live credentials + a reachable, provisioned secret available for L5/L6 (per cloud verified live)
  - [ ] Each adapter dependency (SDK or REST+signing) selected, feature-gated, pinned, and `dep-scan`-cleared (ask-first)

> The locally-verifiable core (the seam + mock client) has **no** unmet prerequisite and can be
> built/verified now; the **live adapter** and its dep cannot land until the three boxes above are checked.

## Acceptance criteria

**Locally verifiable now (core — mock-backed, no credentials):**

- [ ] [REQ-001] `put` stores via the (mock) client; the in-process `Secret` holds an opaque locator, not the cleartext (TC-001).
- [ ] [REQ-002] `resolve`→`inject` round-trips the value the mock client supplied, materialised only at the inject edge; contract responses unchanged (TC-002).
- [ ] [REQ-003] Mock client error / not-found → `backend_unavailable`, fail-closed, no plaintext, no panic, handle not burned (TC-003).
- [ ] [REQ-004] `rotate` updates via the client; pre-rotation handle → `handle_invalidated`; fresh resolve→inject returns the rotated value (TC-004).
- [ ] [REQ-005] `SecretManagerBackend(mock)` swaps in for `AesGcmBackend` with unchanged signatures/responses; single-use/binding/TTL/floor not regressed (TC-005).
- [ ] [REQ-006] Value absent from `resolve`/`get`/`list` and the in-process `Secret` (TC-006).
- [ ] [REQ-007] **Pluggability proven:** ≥2 distinct adapters substitute behind the one `SecretManagerClient` trait (mock-level) with no core/contract change; the drop-in extension point (one trait impl + selection entry) is documented (TC-007).
- [ ] `cargo build && cargo test` green; tasks 001–005 tests unchanged and passing.

**Credential-gated (live — NOT achievable in a local/credential-free run):**

- [ ] [REQ-008] Live adapter get-value round-trip for each cloud whose credentials are supplied (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault); denied/unreachable → `backend_unavailable` (TC-008). **Requires live credentials.**
- [ ] [REQ-009] `dep-scan check --lockfile Cargo.lock --lockfile-type crates` passes on **each** shipped adapter's pinned dependency tree, exit 0, stable; versions pinned + recorded in the spec (TC-009). **Requires the adapter deps to be chosen and added.**

## Verification plan

- **Highest level achievable LOCALLY:** **L2 (unit, mock-backed)** — the `SecretManagerBackend` +
  `SecretManagerClient` seam round-trips resolve→inject yielding the mocked plaintext; fail-closed on
  mock error; the AES nonce/cipher path is no longer involved on this backend; contract responses
  unchanged; backend swaps behind the trait; **≥2 adapters substitute behind the one trait (the
  drop-in pluggability proof, TC-007)**. This is the bulk of the test spec (TC-001…TC-007). A local
  run **cannot** exceed L2 for this task — there is no live provider to exercise.
- **Highest level achievable WITH CREDENTIALS:** **L6** — a live `inject` against a real cloud
  secret-manager (TC-008) plus the per-adapter dep-scan gate (TC-009, L3).

- **Level 2 — unit (achievable locally, no credentials):**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — incl. the mock-backed round-trip,
  `backend_unavailable` fail-closed, rotate-invalidates, value-absence, backend-swap, and the
  ≥2-adapter pluggability tests (TC-001…TC-007). Tasks 001–005 tests unchanged and passing.

- **Level 3 — dep-scan gate (BLOCKED until the adapter deps are chosen + added):**
  ```
  dep-scan check --lockfile Cargo.lock --lockfile-type crates
  ```
  Expected: exit 0, **each** shipped adapter's dependency tree **pass**, stable across runs (TC-009).
  Cannot run until the adapters are confirmed and their SDK/REST dependencies are pinned in `Cargo.lock`.

- **Level 5/6 — live inject (BLOCKED, requires credentials):** with live credentials + a provisioned
  secret for a chosen cloud, `vault demo` / a live `serve` `resolve`→`inject` delivers the exact value
  fetched from that secret-manager via its adapter (TC-008); a denied/unreachable call fails closed to
  `backend_unavailable`. **This is the only evidence that earns ✅ — it is NOT achievable in a local /
  credential-free run and must not be claimed from one.**
