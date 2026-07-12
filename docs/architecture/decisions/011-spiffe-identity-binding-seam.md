# ADR-011: SPIFFE identity binding seam (bind handles to a verified spiffe_id)

**Status:** Accepted
**Date:** 2026-07-12
**Addresses:** roadmap row 6 / Remaining-work **R1** ("bind handles to SPIFFE workload identities
instead of opaque `sandbox_id` strings"), the vault side.
**Relates to:** [ADR-002](002-socket-peercred-check.md) (the dispatch-edge gate this layers into),
[ADR-004](004-admin-verbs-rotation-invalidation.md) (the inject precedence this leaves untouched),
[ADR-010](010-verify-sandbox-attestation-binding.md) (the attestation gate this composes with at the
dispatch edge).
**Blocked-by (provenance half only):** agent-mesh task 008, its published identity-propagation
contract with verified principals `{spiffe_id, trust_tier}`. The seam, a mock issuer, config, and
binding semantics land NOW; the real agent-mesh-backed resolver is a later impl behind the same seam.

## Context

Before this task, `inject` binds a handle at first use to the `sandbox_id` string the caller presents
(post-ADR-010: the cryptographically-verified sandbox id when a trust root is configured, else the
opaque caller-asserted string). Roadmap R1 asked for the handle to bind to a **SPIFFE workload
identity** instead, so a handle first injected by
`spiffe://secure-agents.local/exec-sandbox/sbx-1` can never be presented by any other workload
identity. R1 was gated on agent-mesh publishing the workload-identity model; its task 008 publishes
verified principals `{spiffe_id, trust_tier}`, which is that model.

## Decision 1: a `PrincipalResolver` seam + a mock issuer

A new module `src/principal.rs` (house pattern: one module per concern):

- `struct VerifiedPrincipal { spiffe_id: String, trust_tier: String }`, the agent-mesh task 008
  contract shape, verbatim.
- `trait PrincipalResolver { fn resolve(&self, sandbox_identity: &Value) -> Result<VerifiedPrincipal, PrincipalError>; }`
- `enum PrincipalError { Missing, Invalid(String) }` → error codes `principal_missing` /
  `principal_invalid` in the standard `{error:{code,message,retryable:false}}` shape.
- `struct MockIssuerResolver`, reads `sandbox_identity.principal.{spiffe_id, trust_tier}`, validates
  the shape (Decision 3), returns the principal. It is the spiffe-mode default until agent-mesh task
  008 ships; its doc-comment states it validates **shape, not provenance** (provenance is agent-mesh's
  half). Adopting the real delivery is one new `PrincipalResolver` impl behind this seam.
- `fn validate_spiffe_id(s: &str) -> Result<(), String>`, the pure validator, unit-testable without a
  vault.

**The mock issuer trusts its input's shape, not its provenance.** A local run cannot claim a principal
actually verified by agent-mesh; that cross-repo end-to-end waits on task 008.

## Decision 2: opt-in mode, sandbox is the default

Configuration mirrors `resolve_store_path` / the ADR-010 trust-root config: flag `--identity-binding
sandbox|spiffe` wins over env `VAULT_IDENTITY_BINDING`; both absent ⇒ `sandbox` (today's opaque
binding, byte-for-byte); any other value ⇒ **refuse to start** (fail-fast, never a silent fallback on
a security mode). A pure `resolve_identity_binding(flag, env) -> Result<BindingMode, String>` makes the
precedence unit-testable.

- **sandbox mode (default):** the binding key is the ADR-010 verified/opaque `sandbox_id` exactly as
  before; the `principal` member is ignored.
- **spiffe mode:** the binding key is the resolved `principal.spiffe_id`; a handle first injected by
  one spiffe_id can never be presented by another (the whole URI is the key, no prefix matching).

`Vault::inject`'s signature, `HandleRec`, error codes, and the v1 contract response shapes are
**unchanged**, only *which string* flows in as the binding key changes. `handle_bound_to_other_sandbox`
keeps its name; in spiffe mode "sandbox" reads as "workload" (documented in `interfaces.md`).

## Decision 3: the deliberate minimal SPIFFE-ID subset

`validate_spiffe_id` enforces a documented subset, not full SPIFFE-spec conformance (issuance +
full conformance are agent-mesh's; vault only refuses obviously-invalid keys):

- scheme exactly `spiffe://`;
- non-empty trust domain of lowercase `[a-z0-9.-]`;
- non-empty path beginning `/`;
- no query (`?`) or fragment (`#`);
- total length ≤ 2048 bytes.

Anything else ⇒ `principal_invalid`. A missing/empty `trust_tier` is also `principal_invalid` (the
tier is carried and validated non-empty; mapping it to injection-floor policy is a separate future
task, and raise-only would still hold).

## Decision 4: composition with ADR-010 at the dispatch edge

Both tasks gate the inject at the dispatch edge. The pipeline is: **peer-uid (ADR-002) → attestation
verify (ADR-010) → principal resolve (ADR-011) → `Vault::inject`.** To keep `dispatch` a 3-argument
function as identity gates accrete, the inject-time policy is bundled into one `InjectGate { verifier,
binding_mode, resolver }` threaded into `dispatch` (replacing ADR-010's bare `verifier` parameter). In
sandbox mode the ADR-010 verified/opaque id is the binding key; in spiffe mode the resolved
`spiffe_id` is. Each gate guards its own opt-in config and works with the other absent.

## Decision 5: drop-in seam proven now (the task-006 bar)

A second `PrincipalResolver` impl (a test `AltTestResolver`) drives the identical bind-and-deliver
round-trip behind the same `Box<dyn PrincipalResolver>` wiring with no change to `dispatch`, `Vault`,
the contract, or any caller. This proves that adopting agent-mesh task 008's real verified-principal
delivery is **one new impl + a selection entry**, the same drop-in bar task 006 set for
`SecretManagerClient`.

## Honest residuals (NOT claimed closed)

- **Provenance is not claimed.** The mock issuer validates the principal's shape, not that agent-mesh
  actually issued/attested it. The real resolver (one impl behind this seam) lands when task 008 ships.
- **No new dependency.** The mock issuer and validator are std + `serde_json` only, no SPIFFE crate,
  no workload-API client (that would be a future ask-first event on agent-mesh's side).
- **`trust_tier` is carried, not yet policy.** Using it to raise the injection floor is future work.

## Consequences

- No new dependency; `Cargo.toml`/`Cargo.lock` unchanged.
- Contract v1 unchanged: response shapes byte-for-byte identical; `resolve` stays value-free; the
  raise-only floor, single-use, first-use binding, TTL, and rotation-invalidation are untouched.
- Default sandbox mode is byte-for-byte today's post-ADR-010 behavior; all prior tests pass unmodified.
- When agent-mesh task 008 lands, a follow-up swaps `MockIssuerResolver` for the real resolver behind
  `PrincipalResolver` plus a selection entry, nothing else.
