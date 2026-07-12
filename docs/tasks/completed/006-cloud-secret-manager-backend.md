# Task 006: Cloud secret-manager backend core (behind the StoreBackend seam)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

> **Executable now, local and credential-free.** This task is the **cloud-agnostic core**: the
> `SecretManagerBackend` behind task 004's `StoreBackend` seam, the `SecretManagerClient` trait, a
> mock client, fail-closed `backend_unavailable`, zero-knowledge preservation, backend-swap parity,
> and the **pluggability proof** via >=2 mock-level adapter substitutions behind the one trait plus a
> documented drop-in extension point. It is **fully unit-verifiable locally** against a mock client,
> exactly how task 004 proved the `StoreBackend` seam with a test backend. It pulls **no** real cloud
> SDK/REST dependency and needs **no** credentials. The **real cloud adapters** (AWS Secrets Manager,
> GCP Secret Manager, Azure Key Vault), their SDK/REST dependencies, and the **live get-value
> round-trip** are split out to **[task 012](012-cloud-secret-manager-live-adapters.md)**
> (credential-gated); they land behind this same trait once this seam ships. See
> [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md).

## Goal

Add a **cloud secret-manager `StoreBackend`** behind task 004's seam: at the injection edge, `inject`
resolves the plaintext credential by calling a cloud provider's "get secret value" API instead of
decrypting a local AES ciphertext. To keep the seam vendor-neutral, split the backend into a
cloud-agnostic `SecretManagerBackend: StoreBackend` (owns put / rotate / fetch-at-inject and the
zero-knowledge invariants) delegating the actual fetch/store to a `SecretManagerClient` trait
(`get_value` / `put_value` / `rotate_value`), **the single, documented pluggability seam**.

This task builds and proves that seam against a **mock** `SecretManagerClient` only. **Pluggability
is a first-class requirement (operator directive)**, proven here by substituting **>=2 distinct
mock-level adapters** behind the one trait (sharing zero secret-path logic) and documenting the
**drop-in extension point**: adopting a new store must require **only** dropping in one new
`SecretManagerClient` implementation plus a selection entry (e.g. `--secret-backend <name>`), with
**nothing** in `SecretManagerBackend`, `Vault`, the contract, or any caller changing. The real
per-cloud adapters and their feature-gated SDK/REST dependencies are
[task 012](012-cloud-secret-manager-live-adapters.md); this task must **not** pull any real cloud
SDK/REST dependency and needs no credentials. The contract is unchanged.

## Context

- Direction: [ADR-007](../../architecture/decisions/007-cloud-secret-manager-backend.md) (Accepted,
  execution deferred). The binding decision for roadmap **Row 7 / R2**. No new ADR is needed; ADR-007
  covers this task.
- Seam this plugs into: [ADR-005](../../architecture/decisions/005-encrypted-at-rest-store.md) §5/§6,
  the `StoreBackend` trait (`encrypt(&str) -> EncryptedValue`, `decrypt(&EncryptedValue) -> String`)
  in `src/crypto.rs`, wired in `src/vault.rs` (`Vault.backend: Box<dyn StoreBackend>`,
  `with_clock_and_backend`). The new backend is a second `StoreBackend` implementation; `resolve` /
  `inject` / callers do not change. `encrypt` returns an opaque locator (the remote secret id +
  version); `decrypt` fetches the live value via the client. The AES nonce/cipher path is **not**
  used on this backend.
- Roadmap: [roadmap](../../plans/roadmap.md) v1 Row 7 ("Cloud-KMS / HSM backends") and Remaining
  work **R2** ("which to build first … is a product/deployment-target call", settled to cloud
  secret-manager by ADR-007). Builds on task 004's backend seam.
- Reference: [`docs/spec/SPEC.md`](../../spec/SPEC.md) (zero-knowledge invariant),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (store), [`docs/CONTRACT.md`](../../CONTRACT.md)
  (v1 contract, unchanged here).
- **Dependencies:** the `StoreBackend` seam from **task 004** (✅ shipped). No new dependency is
  added by this task; the trait + a mock client are std/serde only. The real per-cloud adapters and
  their SDK-or-REST dependency trees (a **large**, ask-first, `dep-scan`-gated event) are
  [task 012](012-cloud-secret-manager-live-adapters.md), which lands behind this trait once the seam
  is in place.
- **Constraint:** the contract is unchanged. `resolve` still returns no value; `inject` still returns
  the plaintext `credential` at the edge (now via the remote provider's get-value call). Fail-closed:
  a failed/denied remote fetch produces a structured error (`backend_unavailable`), **never** a
  plaintext fallback. Raise-only floor, single-use + first-use binding, TTL, and the peer-uid gate
  (tasks 001/002) all hold; they live above the seam in `vault.rs`, so they are backend-independent.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `put` stores the value through the `SecretManagerClient` (the remote), **not** as cleartext in vault's in-process `Secret`; the in-process struct holds only an opaque remote locator. The value re-materialises only at `inject`. | must have |
| REQ-002 | `inject` fetches and returns the correct plaintext `credential` via the client's `get_value` **only at delivery time** (the injection edge), not at `resolve`; the `inject`/`resolve` response shapes are byte-for-byte the existing contract (no provider/AEAD type leaks). | must have |
| REQ-003 | Fail-closed: a denied / unavailable / not-found remote fetch yields `{error:{code:"backend_unavailable",…}}`, **no** credential, **no** plaintext fallback, **no** panic; the fetch happens **before** the single-use handle is consumed (a transient remote failure does not burn the handle). | must have |
| REQ-004 | `rotate` updates the value through the client; the generation counter still bumps so every pre-rotation handle is invalidated (`handle_invalidated`), consistent with task 003. A failed `rotate_value` leaves the prior remote value untouched. | must have |
| REQ-005 | `SecretManagerBackend` sits behind the existing `StoreBackend` seam and is swappable for `AesGcmBackend` with **no** change to `resolve`/`inject`/`put`/`rotate` signatures or contract responses; the per-cloud adapter sits behind the `SecretManagerClient` trait so the core is testable without network. | must have |
| REQ-006 | Zero-knowledge preserved over the new backend: the value appears in **no** `resolve` / `get` / `list` response and **not** in the in-process `Secret`; it lives only in the remote and re-materialises only at `inject`. | must have |
| REQ-007 | **Pluggability (drop-in), proven at mock level:** >=2 distinct `SecretManagerClient` adapters (mock-level, standing in for "different secret stores") substitute behind the one trait, driving the identical round-trip with **no** change to `SecretManagerBackend`/`Vault`/the contract; the drop-in extension point (one trait impl + a selection entry, e.g. `--secret-backend <name>`) is documented. The real feature-gated per-cloud adapters are [task 012](012-cloud-secret-manager-live-adapters.md). | must have |

## Readiness gate

- [x] Test spec `006-cloud-secret-manager-backend-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No new dependency needed (the trait + mock client are std/serde only; real adapter deps are task 012)
- [x] No unmet prerequisite; the seam + mock client are locally buildable/verifiable now

## Acceptance criteria

- [ ] [REQ-001] `put` stores via the (mock) client; the in-process `Secret` holds an opaque locator, not the cleartext (TC-001).
- [ ] [REQ-002] `resolve`→`inject` round-trips the value the mock client supplied, materialised only at the inject edge; contract responses unchanged (TC-002).
- [ ] [REQ-003] Mock client error / not-found → `backend_unavailable`, fail-closed, no plaintext, no panic, handle not burned (TC-003).
- [ ] [REQ-004] `rotate` updates via the client; pre-rotation handle → `handle_invalidated`; fresh resolve→inject returns the rotated value (TC-004).
- [ ] [REQ-005] `SecretManagerBackend(mock)` swaps in for `AesGcmBackend` with unchanged signatures/responses; single-use/binding/TTL/floor not regressed (TC-005).
- [ ] [REQ-006] Value absent from `resolve`/`get`/`list` and the in-process `Secret` (TC-006).
- [ ] [REQ-007] **Pluggability proven:** >=2 distinct adapters substitute behind the one `SecretManagerClient` trait (mock-level) with no core/contract change; the drop-in extension point (one trait impl + selection entry) is documented (TC-007).
- [ ] `cargo build && cargo test` green; tasks 001–005 tests unchanged and passing.

## Verification plan

- **Highest level achievable:** **L2 (unit, mock-backed).** The `SecretManagerBackend` +
  `SecretManagerClient` seam round-trips resolve→inject yielding the mocked plaintext; fail-closed on
  mock error; the AES nonce/cipher path is no longer involved on this backend; contract responses
  unchanged; backend swaps behind the trait; **>=2 adapters substitute behind the one trait (the
  drop-in pluggability proof, TC-007)**. The whole test spec (TC-001…TC-007) is mock-backed and needs
  no network or credentials. This task has **no** live-provider surface (that is
  [task 012](012-cloud-secret-manager-live-adapters.md)), so L2 is its ceiling and is fully
  achievable now.

- **Level 2 (unit, achievable locally, no credentials):**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok`, incl. the mock-backed round-trip,
  `backend_unavailable` fail-closed, rotate-invalidates, value-absence, backend-swap, and the
  >=2-adapter pluggability tests (TC-001…TC-007). Tasks 001–005 tests unchanged and passing.

## Out of scope

- **Real cloud `SecretManagerClient` adapters** for AWS Secrets Manager / GCP Secret Manager /
  Azure Key Vault, each **Cargo-feature-gated**: [task 012](012-cloud-secret-manager-live-adapters.md).
  This task ships only mock-level adapters behind the trait to prove the seam.
- **The per-adapter SDK/REST dependency trees** and their `dep-scan` (blocking) + version-pin gate:
  [task 012](012-cloud-secret-manager-live-adapters.md). No real cloud SDK/REST crate is added here.
- **The live get-value round-trip end-to-end** against a provisioned secret per cloud (the L5/L6
  credential-gated evidence): [task 012](012-cloud-secret-manager-live-adapters.md). A local run of
  this task cannot and must not claim any live-provider evidence.
</content>
