# Task 012: Cloud secret-manager live adapters (real stores + live round-trip)

**Project:** vault
**Created:** 2026-07-12
**Status:** blocked

> **BLOCKED, credential-gated and dependency-gated.** This task ships the **real**
> `SecretManagerClient` adapters (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) behind
> the seam that **[task 006](006-cloud-secret-manager-backend.md)** lands, plus the **live get-value
> round-trip** end-to-end against a provisioned secret per cloud. It **cannot** be verified from a
> local, credential-free run. Execution is blocked on: (1) **[task 006](006-cloud-secret-manager-backend.md)**
> shipping the `SecretManagerBackend` + `SecretManagerClient` seam (the adapters plug into it);
> (2) **the concrete cloud(s) confirmed** and each adapter's SDK-or-REST dependency chosen,
> `dep-scan`-cleared, and version-pinned (ask-first, per CLAUDE.md); and (3) **live cloud credentials
> + a reachable, provisioned secret** per cloud being verified live. Highest achievable level is
> **L6** (credential-gated); do **not** claim L5/L6 from a local or credential-free run. See
> [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md).

## Goal

Implement the **real per-cloud `SecretManagerClient` adapters** behind task 006's single pluggability
seam and prove the **live** secret path end-to-end. Each adapter is ~one file implementing
`get_value` / `put_value` / `rotate_value` against that store's API (AWS Secrets Manager, GCP Secret
Manager, Azure Key Vault), sharing zero secret-path logic with the others (that all lives in
`SecretManagerBackend`). Each adapter is **Cargo-feature-gated** so an operator compiles in only the
stores they use; the trait + the mock client from task 006 need no feature. Backend selection stays
config-driven (`--secret-backend aws|gcp|azure`). With supplied credentials and a provisioned secret,
a live `resolve`→`inject` delivers the exact value fetched from that secret-manager via its adapter;
a denied or unreachable call fails closed to `backend_unavailable`, never a plaintext fallback. The
contract is unchanged.

## Context

- Direction: [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md) (Accepted,
  execution deferred). This task carries the **live half** that ADR-007 "Open items / blockers"
  deferred: confirming the concrete cloud(s), pulling each store's SDK/REST dependency under
  `dep-scan`, and the credentialed end-to-end inject.
- Depends on: **[task 006](006-cloud-secret-manager-backend.md)** (the `SecretManagerBackend` +
  `SecretManagerClient` seam, the mock client, fail-closed `backend_unavailable`, and the >=2-adapter
  mock-level pluggability proof). The seam must land first; these adapters are additional trait impls
  behind it, with **no** change to `SecretManagerBackend`, `Vault`, the contract, or any caller (the
  drop-in bar task 006 proved at mock level, now realized against real stores).
- **Dependency posture (ask-first, not yet added):** each concrete adapter pulls that store's SDK
  (e.g. `aws-sdk-secretsmanager`, `google-cloud-secretmanager`, an Azure Key Vault crate) **or** a
  hand-rolled REST + request-signing path. These are **large** new dependency trees relative to
  vault's minimal floor. Every adapter's dependency tree clears `dep-scan` as a **blocking** gate and
  is **version-pinned** before adoption, the same gate applied to `nix`, `aes-gcm`, and `tiny_http`.
  Because shipping 2–3 adapters multiplies that surface, prefer the smallest viable per-adapter
  dependency (a shared REST client + each provider's signing scheme can beat three full SDK trees);
  evaluate SDK-vs-REST under `dep-scan` per store when the set is confirmed. No cloud SDK is added
  until the concrete cloud is confirmed.
- **Constraint:** the contract is unchanged. `resolve` still returns no value; `inject` still returns
  the plaintext `credential` at the edge (now via the live provider's get-value call). Fail-closed on
  a failed/denied/unreachable remote fetch: `backend_unavailable`, never a plaintext fallback, never a
  panic. Raise-only floor, single-use + first-use binding, TTL, and the peer-uid gate hold unchanged
  (they live above the seam in `vault.rs`).
- Reference: [`docs/spec/SPEC.md`](../../spec/SPEC.md) (zero-knowledge invariant),
  [`docs/CONTRACT.md`](../../CONTRACT.md) (v1 contract, unchanged here).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | Ship real `SecretManagerClient` adapters for AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault, each ~one file implementing `get_value`/`put_value`/`rotate_value` behind task 006's trait, sharing zero secret-path logic; each **Cargo-feature-gated** so compiling one in does not pull the others' deps; selection stays config-driven (`--secret-backend aws\|gcp\|azure`), with **no** change to `SecretManagerBackend`/`Vault`/the contract/any caller. | must have |
| REQ-002 | **(moved from old 006 REQ-008)** A live get-value round-trip end-to-end: with supplied credentials and a reachable provisioned secret, `put`→`resolve`→`inject` delivers the exact value fetched live from the secret-manager via its adapter, for **each** cloud whose credentials are supplied; a denied / unreachable / not-found call fails closed to `backend_unavailable` (parity with task 006's mock fail-closed), never a plaintext fallback, never a panic. **Credential-gated (the L5/L6 evidence).** | must have *(credential-blocked)* |
| REQ-003 | **(moved from old 006 REQ-009)** **Each** shipped adapter's dependency tree clears `dep-scan check --lockfile Cargo.lock --lockfile-type crates` (blocking, exit 0, stable) and is **version-pinned** in `Cargo.toml`/`Cargo.lock`; the smaller of {full SDK, REST+signing} that clears is preferred per store; the pinned versions are recorded in this task and the spec when the adapters land. **Dep-gated (adapter deps must be chosen + added first).** | must have *(dep-blocked)* |

## Readiness gate

- [x] Test spec `012-cloud-secret-manager-live-adapters-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [ ] **BLOCKED, unmet prerequisites:**
  - [ ] **[Task 006](006-cloud-secret-manager-backend.md) shipped** (the `SecretManagerBackend` + `SecretManagerClient` seam and mock client are merged and verified)
  - [ ] Adapter set confirmed for the first cut (default: AWS Secrets Manager + GCP Secret Manager + Azure Key Vault; operator may adjust)
  - [ ] Each adapter dependency (SDK or REST+signing) selected, feature-gated, pinned, and `dep-scan`-cleared (ask-first)
  - [ ] Live credentials + a reachable, provisioned secret available for L5/L6 (per cloud verified live)

## Acceptance criteria

- [ ] [REQ-001] Real feature-gated adapters (AWS/GCP/Azure) implement the trait behind task 006's seam; each compiles independently under its own feature and none pulls the others' deps; `--secret-backend` selects the right adapter; no change to `SecretManagerBackend`/`Vault`/the contract (TC-001).
- [ ] [REQ-002] Live adapter get-value round-trip for **each** cloud whose credentials are supplied delivers the exact provisioned value; denied/unreachable → `backend_unavailable`, fail-closed, no plaintext, no panic (TC-002). **Requires live credentials.**
- [ ] [REQ-003] `dep-scan check --lockfile Cargo.lock --lockfile-type crates` passes on **each** shipped adapter's pinned dependency tree, exit 0, stable; versions pinned + recorded in the spec (TC-003). **Requires the adapter deps to be chosen and added.**
- [ ] `cargo build --features <each adapter>` green; task 006's mock-backed tests and tasks 001–005 tests unchanged and passing.

## Verification plan

- **Highest level achievable:** **L6 (credential-gated).** A live `inject` against a real cloud
  secret-manager (TC-002) plus the per-adapter `dep-scan` gate (TC-003, L3) and the feature-gated
  adapter build (TC-001, L2 once deps land). This task **cannot** be verified from a local or
  credential-free run: there is no live provider to exercise and the adapter deps are an ask-first
  addition. Do not claim L5/L6 from a local run.

- **Level 2 (feature-gated adapter build, once the deps are added):**
  ```
  cargo build --features aws
  cargo build --features gcp
  cargo build --features azure
  cargo test
  ```
  Expected: each adapter compiles behind its feature with none pulling the others' deps; `--secret-backend`
  selection maps to the right adapter; task 006's mock tests + tasks 001–005 unchanged and passing (TC-001).

- **Level 3 (dep-scan gate, BLOCKED until the adapter deps are chosen + added):**
  ```
  dep-scan check --lockfile Cargo.lock --lockfile-type crates
  ```
  Expected: exit 0, **each** shipped adapter's dependency tree **pass**, stable across runs (TC-003).
  Cannot run until the adapters are confirmed and their SDK/REST dependencies are pinned in `Cargo.lock`.

- **Level 5/6 (live inject, BLOCKED, requires credentials):** with live credentials + a provisioned
  secret for a chosen cloud, a live `serve` `put`→`resolve`→`inject` delivers the exact value fetched
  from that secret-manager via its adapter (TC-002); a denied/unreachable call fails closed to
  `backend_unavailable`. **This is the only evidence that earns ✅. It is NOT achievable in a local /
  credential-free run and must not be claimed from one.** Repeat per cloud whose credentials are supplied.

- **ADR note:** ADR-007 governs the direction (the seam, the pluggability model, the fail-closed
  invariant) and no new ADR is needed to proceed. However, the **concrete SDK-vs-REST choice per
  cloud is a non-trivial decision** (large dependency trees, request-signing surface, per-provider
  auth). If that choice is made at execution time, **an ADR is owed then** recording, per store,
  which dependency was picked, why (dep-scan surface, signing complexity, pin), and the alternative
  rejected. Do not write it now; the concrete cloud set and dep evaluation are prerequisites.

## Out of scope

- The cloud-agnostic **core seam** (the `SecretManagerBackend`, the `SecretManagerClient` trait, the
  mock client, fail-closed semantics, zero-knowledge preservation, backend-swap parity, and the
  mock-level pluggability proof): that is **[task 006](006-cloud-secret-manager-backend.md)** and is a
  prerequisite of this task.
- PKCS#11 HSM and OpenBao passthrough backends (available later behind the same seam per ADR-007).
- Any change to the v1 contract, `resolve`/`inject`/`put`/`rotate` signatures, or the invariants that
  live above the seam in `vault.rs`.

## Dependencies

- **Blocked-by:** **[task 006](006-cloud-secret-manager-backend.md)** (the seam + mock client must
  land and verify first) **and** live cloud credentials + a reachable provisioned secret + the
  concrete cloud(s) confirmed with their deps chosen, feature-gated, pinned, and `dep-scan`-cleared.
- Builds on: task 004's `StoreBackend` seam (✅ shipped) via task 006. Composes with tasks 007/008
  (independent). No adapter dependency is added until the concrete cloud is confirmed (ask-first).
- Roadmap alignment: completes the live half of roadmap **Row 7 / R2** (cloud secret-manager backend)
  that ADR-007 deferred.
</content>
