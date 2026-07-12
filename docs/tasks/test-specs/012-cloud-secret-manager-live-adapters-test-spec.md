# Test Spec 012: Cloud secret-manager live adapters (real stores + live round-trip)

**Linked task:** [`docs/tasks/backlog/012-cloud-secret-manager-live-adapters.md`](../backlog/012-cloud-secret-manager-live-adapters.md)
**Written:** 2026-07-12

> **Execution blocked, credential-gated and dependency-gated.** This spec is authored ahead of
> execution (test-spec-before-code house rule). It covers the **live half** split out of task 006:
> the real feature-gated per-cloud adapters (TC-001), the credentialed live get-value round-trip
> (TC-002), and the per-adapter `dep-scan` gate (TC-003). None of these run in a local, credential-free
> run: TC-002 needs live cloud credentials + a provisioned secret per cloud, and TC-001/TC-003 need the
> adapter SDK/REST deps chosen and added (ask-first). Highest achievable level is **L6**.
> **[Task 006](../backlog/006-cloud-secret-manager-backend.md)**'s seam + mock client must land first.
> See ADR-007 "Open items / blockers."

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ⚠️ build-only, once adapter deps added (feature-gate + drop-in) | ⏳ dep-blocked |
| REQ-002 | TC-002 | ❌ **credential-gated** (live adapters) | ⏳ blocked |
| REQ-003 | TC-003 | ❌ needs adapter deps chosen (`dep-scan` gate) | ⏳ dep-blocked |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous
- [ ] Task 006's seam + mock client have shipped (prerequisite)
- [ ] Each adapter's SDK/REST dependency is chosen, feature-gated, pinned, and `dep-scan`-cleared before its live TC runs

---

## Test fixtures

- **Real per-cloud adapters** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault), each a
  `SecretManagerClient` impl behind task 006's trait, Cargo-feature-gated. They reuse task 006's
  `SecretManagerBackend` and share zero secret-path logic; only the store-facing calls differ.
- **A provisioned secret per cloud** (created out of band by the operator) reachable with the supplied
  credentials, used as the live round-trip target in TC-002.
- Task 006's `MockSecretManagerClient` remains the local, credential-free double for the core seam; it
  is **not** re-tested here (task 006 owns it). This spec exercises only the real adapters.

---

## Test cases

### TC-001: real adapters are feature-gated and drop-in behind task 006's trait

- **Requirement:** REQ-001
- **Status:** ⚠️ build-level, runnable **only once** the adapter SDK/REST deps are chosen and added
  (ask-first, dep-gated). Documented here so the future execution has a concrete target.
- **Input (when deps added):** build with each adapter feature in turn
  (`cargo build --features aws|gcp|azure`); construct a `Vault` with `SecretManagerBackend` over each
  real adapter; exercise `--secret-backend aws|gcp|azure` selection.
- **Expected output:** each adapter compiles behind its own feature with **none** pulling the others'
  deps (feature off ⇒ that store's dependency absent from the build); `--secret-backend` maps to the
  right adapter; **no** change to `SecretManagerBackend`, `Vault`, the contract, or any caller (only a
  new trait impl + a selection entry, realizing task 006's drop-in bar against real stores). Task 006's
  mock tests and tasks 001–005 tests remain unchanged and passing.
- **Edge cases:** default build (no adapter feature) pulls none of the three SDK/REST trees; an unknown
  `--secret-backend` value refuses to start (fail-fast, no silent fallback).

### TC-002: live adapter get-value round-trip (CREDENTIAL-GATED, NOT RUN LOCALLY)

- **Requirement:** REQ-002 (moved from old 006 REQ-008)
- **Status:** ⏳ **blocked**, requires live credentials + a provisioned secret for the cloud(s) being
  verified live (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault). **Not executed in a
  local / credential-free run.** Documented so the future credentialed run has a concrete target.
- **Input (when credentialed):** with valid credentials and a reachable secret-manager, build that
  store's real `SecretManagerClient` adapter; `put` a value; `resolve`→`inject`.
- **Expected output:** `inject` delivers the exact value fetched live from the secret-manager via the
  adapter's `get_value`; a denied/unreachable call fails closed to `backend_unavailable` (parity with
  task 006 TC-003's mock fail-closed), never a plaintext fallback, never a panic. This is the L5/L6
  evidence the task needs to reach ✅; it **cannot** be claimed from a local run. Repeat per cloud whose
  credentials are supplied.
- **Edge cases:** auth failure / throttling / not-found all map to `backend_unavailable`, fail-closed,
  no plaintext; the single-use handle is not burned by a transient fetch failure (decrypt-before-consume
  ordering, same as task 006 TC-003).

### TC-003: dep-scan gate on each shipped adapter's dependency tree (blocking)

- **Requirement:** REQ-003 (moved from old 006 REQ-009)
- **Status:** ⏳ **blocked**, needs the adapter deps chosen + added; runnable at L3 once they are.
- **Input:** once the adapters are confirmed and each SDK/REST dependency is pinned + feature-gated in
  `Cargo.toml` + `Cargo.lock`, run `dep-scan check --lockfile Cargo.lock --lockfile-type crates`.
- **Expected output:** **each** shipped adapter's resolved dependency tree returns **pass**, exit 0,
  stable across repeated runs, the same blocking gate applied to `nix`, `aes-gcm`, and `tiny_http`.
  The task does **not** merge if `dep-scan` flags any tree; the smaller of {full SDK, REST+signing}
  that clears is preferred per store. The pinned versions are recorded in the task and the spec when
  the adapters land.
- **Edge cases:** a flagged transitive crate blocks that adapter; re-evaluate REST+signing vs full-SDK
  under `dep-scan` before picking, per store.
</content>
