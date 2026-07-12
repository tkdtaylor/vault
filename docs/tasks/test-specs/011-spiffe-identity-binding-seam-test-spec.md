# Test Spec 011: SPIFFE identity binding seam (bind handles to a verified spiffe_id)

**Linked task:** [`docs/tasks/backlog/011-spiffe-identity-binding-seam.md`](../backlog/011-spiffe-identity-binding-seam.md)
**Written:** 2026-07-11
**Addresses:** roadmap row 6 / Remaining-work **R1** ("SPIFFE identity binding — bind handles to
SPIFFE workload identities instead of opaque `sandbox_id` strings"; blocked on agent-mesh)
**Design:** ADR (written by the executor — records the `PrincipalResolver` seam, the mock issuer,
and the agent-mesh verified-principal contract shape `{spiffe_id, trust_tier}`)

> **Contract shape is agent-mesh's (its task 008, in flight).** agent-mesh is publishing an
> identity-propagation contract exposing verified principals `{spiffe_id, trust_tier}`. This spec
> tests the **vault-side seam** (`PrincipalResolver` in `src/principal.rs`) against a **mock
> issuer** that validates that exact shape — per R1's own framing and the operator direction, a
> mock issuer is acceptable now. When agent-mesh task 008 ships, the real resolver is one new
> trait impl; every TC below stays valid. All TCs are locally verifiable now (no network, no
> agent-mesh runtime).

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-002, TC-006 | ✅ |
| REQ-002 | TC-001 | ✅ |
| REQ-003 | TC-002, TC-003 | ✅ |
| REQ-004 | TC-004 | ✅ |
| REQ-005 | TC-004 | ✅ |
| REQ-006 | TC-006 | ✅ |
| REQ-007 | TC-005 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous
- [ ] Negative cases carry an in-test valid control on the same state (mutation guard — a
      resolver that rejects everything, or accepts everything, must fail the test)

---

## Test fixtures

- **`principal(spiffe_id, trust_tier)`** — a test helper building the agent-mesh verified-principal
  block: `{"spiffe_id": "<…>", "trust_tier": "<…>"}` placed at
  `sandbox_identity.principal` in the inject request.
- **`MockIssuerResolver`** — the in-tree mock issuer (also the production default for spiffe mode
  until agent-mesh task 008 ships): reads `sandbox_identity.principal`, validates the shape
  (spiffe_id parses per TC-004's rules, trust_tier non-empty), returns
  `VerifiedPrincipal { spiffe_id, trust_tier }`. Stateless, no I/O.
- **`AltTestResolver`** — a second, behaviorally-distinct `PrincipalResolver` impl used by TC-005
  (e.g. reads the principal from a different JSON location, or maps a fixed token → a fixed
  spiffe_id), standing in for "the real agent-mesh-backed resolver" to prove drop-in swap —
  mirrors task 006's ≥2-adapter pluggability proof (TC-007 there).
- **Dispatch-level harness** — TCs 002–005 drive `dispatch` in `src/main.rs` (the live path), not
  `Vault::inject` directly (dead-wire retro: a resolver that exists but is not wired must fail).
- Canonical fixture ids: `ID_A = "spiffe://secure-agents.local/exec-sandbox/sbx-1"`,
  `ID_B = "spiffe://secure-agents.local/exec-sandbox/sbx-2"`, tier `"attested"`.

---

## Test cases

### TC-001: binding-mode config — default, opt-in, precedence, unknown value refused

- **Requirement:** REQ-002
- **Input:** the pure resolver `resolve_identity_binding(flag, env)` over: flag `"spiffe"` + env
  `"sandbox"`; flag absent + env `"spiffe"`; both absent; flag `"sandbox"`; and the invalid values
  `"SPIFFE"`, `"spiffee"`, `""`.
- **Expected output:** flag wins over env (`--identity-binding` > `VAULT_IDENTITY_BINDING` —
  mirrors `resolve_store_path`); both absent ⇒ `Sandbox` (the default: today's behavior);
  `"spiffe"` ⇒ `Spiffe`; any other value ⇒ `Err(String)` so `serve` refuses to start (non-zero
  exit, no panic, never a silent fallback to the weaker mode).
- **Edge cases:** values are case-sensitive lowercase exactly `"sandbox"` / `"spiffe"` (explicit
  over implicit — no fuzzy matching on a security mode).

### TC-002: spiffe mode happy path — handle binds to the verified spiffe_id at first use

- **Requirement:** REQ-001, REQ-003
- **Input:** vault seeded via `put` (fixed-key AES test backend); `resolve` → handle H; through
  `dispatch` in spiffe mode:
  `{"op":"inject","handle":H,"mode":"proxy","sandbox_identity":{"sandbox_id":"sbx-1","principal":{"spiffe_id":ID_A,"trust_tier":"attested"}}}`.
- **Expected output:** `{"ok":true,"delivery":"proxy","credential":"SK-SECRET","binding":{…}}` —
  the contract response byte-for-byte unchanged (no principal/SPIFFE type leaks into the
  response). Internally the handle's binding key is **ID_A (the spiffe_id), not `"sbx-1"`**:
  asserted via the vault's handle record (`bound_sandbox == Some(ID_A)`) — the load-bearing
  assertion that the binding moved from the opaque string to the verified identity.
- **Edge cases:** a replay of H with the identical principal → `handle_consumed` (single-use
  precedence unchanged); env-mode delivery also works in spiffe mode and fills `wiped_at`.

### TC-003: a different spiffe_id cannot use the bound handle — and same-id control succeeds

- **Requirement:** REQ-003
- **Input:** through `dispatch` in spiffe mode: inject handle H1 with principal ID_A
  (succeeds — H1 is now bound to ID_A and consumed), then inject H1 again with principal ID_B.
  Because first inject both binds and consumes, the pure binding check is additionally exercised
  at the `Vault` unit level below, exactly as the existing binding tests reach it today.
- **Expected output:** the second request returns an error and **never** the credential. Per the
  existing precedence (consumed is checked before binding — ADR-003), the code is
  `handle_consumed`; the test asserts the response carries no `credential` and no `ok`.
  Additionally, at the `Vault` unit level (same-module test, as the existing binding tests do),
  force a bound-but-unconsumed record (`bound_sandbox = Some(ID_A)`, `consumed = false`) and
  inject with binding key ID_B → exactly `handle_bound_to_other_sandbox`; with ID_A (the valid
  control) → delivers. This proves the spiffe_id is the discriminating key.
- **Edge cases:** ID_A vs ID_B differ only in the path segment (`sbx-1`/`sbx-2`) — the whole URI
  is the key, not a prefix; no partial/prefix matching.

### TC-004: fail-closed — missing principal and malformed spiffe_id rejected in spiffe mode

- **Requirement:** REQ-004, REQ-005
- **Input:** spiffe mode, valid handle. Through `dispatch`: (a) today's request shape with **no**
  `principal` member; (b) `principal` present with `spiffe_id` from the malformed table:
  `"http://x/y"` (wrong scheme), `"spiffe://"` (empty trust domain), `"spiffe://domain"` (no
  path), `"spiffe://UPPER.case/x"` (uppercase trust domain), `"spiffe://d/p?q=1"` (query),
  `"spiffe://d/p#f"` (fragment), `""`, and a >2048-byte id; (c) `principal` with valid `spiffe_id`
  but `trust_tier` missing or `""`.
- **Expected output:** (a) → `{"error":{"code":"principal_missing","retryable":false,…}}`; each
  (b) and (c) case → `{"error":{"code":"principal_invalid",…}}`. In every case: no credential in
  the response, `Vault::inject` never called, handle neither consumed nor bound — proven by the
  in-test valid control: after all rejections, a valid ID_A inject on the **same handle**
  delivers `"SK-SECRET"`.
- **Edge cases:** the malformed table is data-driven (one assertion per entry, labeled) so a
  future rule change shows exactly which case regressed; the valid control uses the same secret
  and handle so rejection is attributable to the principal alone.

### TC-005: resolver seam is drop-in swappable — agent-mesh lands as one new impl

- **Requirement:** REQ-007
- **Input:** run the identical TC-002 flow twice: once with `MockIssuerResolver`, once with
  `AltTestResolver` substituted behind the same `Box<dyn PrincipalResolver>` wiring (each
  supplying ID_A through its own mechanism).
- **Expected output:** both resolvers drive the identical bind-and-deliver round-trip with **no**
  change to `dispatch`'s spiffe arm, `Vault`, the contract, or any caller — only the trait object
  differs. This proves adopting agent-mesh task 008's real verified-principal delivery = **one
  new `PrincipalResolver` impl + a selection entry**, nothing else (the same drop-in bar task 006
  set for `SecretManagerClient`).
- **Edge cases:** the seam's doc-comment names the extension point and the agent-mesh contract it
  expects (`{spiffe_id, trust_tier}`), so the future impl has a single documented landing spot.

### TC-006: default sandbox mode is byte-for-byte today's behavior — prior tests all green

- **Requirement:** REQ-001 boundary, REQ-006
- **Input:** default mode (no flag, no env). Through `dispatch`: today's exact request
  `{"op":"inject","handle":H,"sandbox_identity":{"sandbox_id":"sbx-1"},"mode":"proxy"}`; and the
  same request WITH a `principal` block attached.
- **Expected output:** both deliver normally with the binding key `"sbx-1"` (the opaque
  sandbox_id) — in sandbox mode the principal member is ignored, not validated, not required:
  the v0/v1 opaque first-use binding exactly as documented in R1. All prior tests (tasks
  001–008, 74 tests) pass unmodified; `resolve` stays value-free; floor stays raise-only.
- **Edge cases:** replay → `handle_consumed`, other sandbox → `handle_bound_to_other_sandbox`,
  TTL expiry → `handle_expired`, rotation → `handle_invalidated` — all unchanged in both modes
  (the spiffe seam changes only which string is the binding key, never the precedence).
