# Test Spec 006: Cloud secret-manager backend (behind the StoreBackend seam)

**Linked task:** [`docs/tasks/backlog/006-cloud-secret-manager-backend.md`](../backlog/006-cloud-secret-manager-backend.md)
**Written:** 2026-06-18

> **Execution blocked.** This spec is authored ahead of execution. The cloud-agnostic core +
> pluggability (TC-001…TC-007) is **unit-verifiable locally** against mock `SecretManagerClient`
> adapters — no network, no credentials — exactly as task 004 proved the `StoreBackend` seam with a
> test backend. The **live** adapter case (TC-008) is **credential-gated** (needs live cloud
> credentials + a provisioned secret per cloud verified live) and the per-adapter **dep-scan** gate
> (TC-009) needs the adapter deps chosen + added; neither runs in a local / credential-free run. See
> ADR-007 "Open items / blockers."

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ (mock client) | ✅ |
| REQ-002 | TC-002 | ✅ (mock client) | ✅ |
| REQ-003 | TC-003 | ✅ (mock client) | ✅ |
| REQ-004 | TC-004 | ✅ (mock client) | ✅ |
| REQ-005 | TC-005 | ✅ (mock client) | ✅ |
| REQ-006 | TC-006 | ✅ (mock client) | ✅ |
| REQ-007 | TC-007 | ✅ (≥2 mock adapters — pluggability/drop-in) | ✅ |
| REQ-008 | TC-008 | ❌ **credential-gated** (live adapters) | ⏳ blocked |
| REQ-009 | TC-009 | ❌ needs adapter deps chosen (`dep-scan` gate) | ⏳ blocked |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous
- [ ] The cloud call sits behind the `SecretManagerClient` trait so the core is mock-tested
      without network or credentials

---

## Test fixtures

- **`MockSecretManagerClient`** — an in-memory `SecretManagerClient` used by all locally-verifiable
  TCs: it holds a `HashMap<String, String>` (remote-id → value), supports a settable failure mode
  (`get_value`/`put_value`/`rotate_value` return `Err` on demand to model a denied / unavailable /
  not-found remote), and records call counts. It performs **no** AES/nonce work — proving the cloud
  path does not re-use the local crypto primitives.
- **`AltMockSecretManagerClient`** — a *second*, behaviorally-distinct in-memory adapter used by TC-007
  to stand in for "a different secret store," proving that swapping stores needs only a new trait impl.
- The mocks substitute for the concrete cloud adapters behind the `SecretManagerClient` trait, mirroring
  `FixedKeyProvider` / the swappable-backend pattern from task 004.

---

## Test cases

### TC-001: SecretManagerBackend stores via the client on put (value materialises only at inject)

- **Requirement:** REQ-001
- **Input:** build a `Vault` with `SecretManagerBackend(MockSecretManagerClient)`;
  `put("vault://test/api_key", "SK-SECRET", proxy, binding)`.
- **Expected output:** `put` calls the client's `put_value` (or equivalent store) so the value is
  held by the (mock) remote, **not** as cleartext in vault's `Secret`. The in-process `Secret` holds
  only the opaque reference/locator returned by the backend's `encrypt` — never the cleartext
  "SK-SECRET". A later `inject` is what re-materialises the value.
- **Edge cases:** empty value and a long (>1 KB) value both round-trip through the client.

### TC-002: resolve→inject round-trips the value supplied by the mock client

- **Requirement:** REQ-002
- **Input:** put "SK-SECRET" (stored in the mock); `resolve(...)`; `inject(handle, "sbx-1", proxy)`.
- **Expected output:** `credential == "SK-SECRET"` — the value re-materialises **only at the inject
  edge**, via the client's `get_value`, not at `resolve`. `resolve` carries no value (unchanged
  invariant). The `inject` response shape (`{ok, delivery, credential, binding{...}}`) is **identical**
  to the AES backend's — no provider/AEAD type leaks into the contract.
- **Edge cases:** env-mode delivery also round-trips the correct plaintext and fills `wiped_at`.

### TC-003: fail-closed — client error / not-found yields a structured error, no plaintext, no panic

- **Requirement:** REQ-003
- **Input:** put a secret; put the mock client into failure mode (or remove the entry so `get_value`
  returns not-found); `resolve`→`inject`.
- **Expected output:** `inject` returns `{"error":{"code":"backend_unavailable",…}}` (the
  `decrypt_failed`-analog for a failed remote fetch) — **never** a credential, **never** a plaintext
  fallback, **never** a panic. The single-use handle is **not** burned by the fetch failure
  (decrypt-before-consume ordering preserved from task 004), so a transient remote failure does not
  destroy the handle.
- **Edge cases:** a `put_value` failure → `put` stores nothing (fail-closed); a `rotate_value`
  failure → `encrypt_failed`-analog (`backend_unavailable` on rotate) and the prior remote value is
  left untouched.

### TC-004: rotate via the backend updates the value through the client; pre-rotation handles invalidated

- **Requirement:** REQ-004
- **Input:** put "SK-OLD"; `resolve` → handle H (against generation N); `rotate("vault://test/api_key",
  "SK-NEW")`; then `inject(H, ...)`; then a fresh `resolve`→`inject`.
- **Expected output:** `rotate` calls the client's `rotate_value`/`put_value` so the mock now holds
  "SK-NEW". The pre-rotation handle H → `{"error":{"code":"handle_invalidated",…}}` (generation-counter
  semantics from task 003 preserved). A **fresh** resolve→inject returns `credential == "SK-NEW"`.
- **Edge cases:** rotate on an unknown ref → `no_such_secret`, no client call for store.

### TC-005: backend swappable — Vault works with SecretManagerBackend substituted for AES

- **Requirement:** REQ-005
- **Input:** construct `Vault::with_clock_and_backend(clock, Box::new(SecretManagerBackend(mock)))`
  in place of the `AesGcmBackend`.
- **Expected output:** `resolve`/`inject`/`put`/`rotate` signatures and all contract responses are
  **unchanged**; the seam (`StoreBackend::encrypt`/`decrypt`) is the only touch point; no provider
  type appears in any contract response. The full v0/v1 round-trip (resolve→inject→replay-rejected,
  TTL, first-use binding, raise-only floor) holds with the remote-backed backend.
- **Edge cases:** single-use replay → `handle_consumed`; other-sandbox → `handle_bound_to_other_sandbox`
  — both still hold with the cloud backend (these live in `vault.rs`, above the seam, so they are
  backend-independent; the test asserts they are not regressed).

### TC-006: zero-knowledge preserved — value absent from resolve and all admin responses

- **Requirement:** REQ-006
- **Input:** put "SK-DEMO-DO-NOT-LEAK" through `SecretManagerBackend(mock)`; call `resolve`, `get`,
  and `list`; serialize/inspect each response **and** the in-process `Secret` struct.
- **Expected output:** the cleartext substring "SK-DEMO-DO-NOT-LEAK" appears in **none** of the
  `resolve` / `get` / `list` responses, and **not** in the in-process `Secret` (which holds only the
  opaque remote locator). The value lives only in the (mock) remote and re-materialises only at the
  `inject` edge.
- **Edge cases:** `list` over multiple secrets leaks no value; `get` returns metadata only.

### TC-007: pluggability / drop-in — ≥2 adapters substitute behind the one trait (locally verifiable)

- **Requirement:** REQ-007
- **Input:** define **two** distinct `SecretManagerClient` test adapters (e.g. `MockSecretManagerClient`
  plus a second `AltMockSecretManagerClient` with different internal storage/behavior, standing in for
  "a different secret store"); construct a `Vault` with `SecretManagerBackend` over each in turn.
- **Expected output:** both adapters drive the identical `resolve`→`inject` round-trip and contract
  responses with **no** change to `SecretManagerBackend`, `Vault`, the contract, or any caller — only
  the trait object differs. This proves the operator directive: adopting a different store = **one new
  `SecretManagerClient` impl + a selection entry**, nothing else. The test also asserts the selection
  path (`--secret-backend`/config → the right adapter) maps to the right client.
- **Edge cases:** the live AWS/GCP/Azure adapters are each just a third/fourth such impl (built when
  credentialed, TC-008); each is Cargo-**feature**-gated so compiling one in does not pull the others'
  deps. Documenting the drop-in extension point (one trait impl + selection entry) is part of this TC.

### TC-008: live adapter get-value round-trip — **CREDENTIAL-GATED, NOT RUN LOCALLY**

- **Requirement:** REQ-008
- **Status:** ⏳ **blocked** — requires live credentials + a provisioned secret for the cloud(s) being
  verified live (AWS Secrets Manager / GCP Secret Manager / Azure Key Vault). **Not executed in a
  local / credential-free run.** Documented here so the future credentialed run has a concrete target.
- **Input (when credentialed):** with valid credentials and a reachable secret-manager, build that
  store's real `SecretManagerClient` adapter; `put` a value; `resolve`→`inject`.
- **Expected output:** `inject` delivers the exact value fetched live from the secret-manager via the
  adapter's `get_value`; a denied/unreachable call fails closed to `backend_unavailable` (parity with
  TC-003's mock path). This is the L5/L6 evidence the task needs to reach ✅ — it **cannot** be claimed
  from a local run. Repeat per cloud whose credentials are supplied.
- **Edge cases:** auth failure / throttling / not-found all map to `backend_unavailable`, fail-closed,
  no plaintext.

### TC-009: dep-scan gate on each shipped adapter's dependency tree (blocking)

- **Requirement:** REQ-009
- **Input:** once the adapters are confirmed and each SDK/REST dependency is pinned + feature-gated in
  `Cargo.toml` + `Cargo.lock`, run `dep-scan check --lockfile Cargo.lock --lockfile-type crates`.
- **Expected output:** **each** shipped adapter's resolved dependency tree returns **pass**, exit 0,
  stable across repeated runs — the same blocking gate applied to `nix`, `aes-gcm`, and `tiny_http`.
  The task does **not** merge if dep-scan flags any tree; the smaller of {full SDK, REST+signing} that
  clears is preferred per store. The pinned versions are recorded in the task and (when adapters land)
  the spec.
- **Edge cases:** a flagged transitive crate blocks that adapter; re-evaluate REST+signing vs full-SDK
  under dep-scan before picking, per store.
