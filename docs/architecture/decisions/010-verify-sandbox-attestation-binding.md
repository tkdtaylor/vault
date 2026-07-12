# ADR-010: Verify the signed sandbox attestation when binding a handle at first use

**Status:** Accepted
**Date:** 2026-07-12
**Addresses:** the documented unverifiable-binding gap, `inject` binds a handle at first use to
whatever opaque `sandbox_id` string the caller presents; nothing proves the caller *is* that sandbox.
**Relates to:** [ADR-002](002-socket-peercred-check.md) (the dispatch-edge gate this layers beside),
[ADR-003](003-ttl-auto-wipe-clock.md)/[ADR-004](004-admin-verbs-rotation-invalidation.md) (the inject
precedence this leaves untouched), [ADR-009](009-secure-memory-zeroization.md) (the `zeroize` dep-scan
BLOCK that decides the crate choice below), [`docs/CONTRACT.md`](../../CONTRACT.md) (v1, response
shapes unchanged; the attestation member is additive on the request).
**Blocked-by (payload finalization only):** exec-sandbox tasks 020-021 (the final
`sandbox_identity.attestation` payload shape + published trust root). This ADR + task 010 ship the
vault-side seam NOW against a fixture; a small follow-up aligns one function when 020-021 land.

## Context

Today `inject(handle, sandbox_identity, mode)` extracts `sandbox_identity.sandbox_id` at the dispatch
edge (`src/main.rs`) and passes it straight to `Vault::inject` as a trusted string. First-use binding
records that string on the `HandleRec`; a replay is rejected (`handle_consumed`) and a different
sandbox is rejected (`handle_bound_to_other_sandbox`). But the string is caller-asserted, any caller
can claim any `sandbox_id`. The binding is therefore *unverifiable*: it enforces consistency, not
authenticity.

exec-sandbox (its tasks 020-021, in flight) is producing a **signed** `sandbox_identity.attestation`:
an Ed25519 signature by a host-held key over the sandbox identity, with a published trust root. This
ADR settles the vault side: verify that signature at the dispatch edge and fail closed on a
missing/invalid attestation **when a trust root is configured**, preserving today's behavior
byte-for-byte when none is.

## Decision 1: Ed25519 verify crate: `ed25519-compact` (default-features off), by measurement

Ed25519 verification needs a real crate. Curve arithmetic is **not** a hand-rollable primitive (unlike
task 008's byte-wipe): a wrong implementation is silently insecure. Both candidates the task named were
trial-added and run through `dep-scan check --lockfile Cargo.lock --lockfile-type crates`:

| Candidate | Added crates | `zeroize`? | new `getrandom`? | dep-scan |
|-----------|-------------|-----------|------------------|----------|
| `ed25519-dalek@2` (`--no-default-features --features std`) | **17** (60 total) | **YES**, `zeroize` 1.9.0 via `curve25519-dalek` 4.1.3 (a hard, non-optional dep) | no | disqualified |
| `ed25519-compact` (`--no-default-features`) | **1** (44 total) | no | no | **exit 0, all pass** |

`ed25519-dalek` is disqualified on the spot: even with defaults off it pulls **`zeroize`**, the exact
crate [ADR-009](009-secure-memory-zeroization.md) BLOCKED (a `maintainer_change` dep-scan hard-stop)
and the project hand-rolled `src/zeroize.rs` to avoid. `zeroize` is a **non-optional** dependency of
`curve25519-dalek` 4.x, so no feature juggling removes it. Adopting dalek would reintroduce the blocked
crate and regress task 008.

`ed25519-compact` with `default-features = false` adds exactly **one** crate (`ed25519-compact` 2.3.1)
and its `random`/`getrandom` default features are off, so it pulls **no `zeroize`, no `rand`, and no
new `getrandom`** (its keypair-generation RNG is what those defaults would bring; we do not need it,
since tests sign from a fixed seed and production only verifies). The verify-only + sign-from-seed API was
probe-compiled before adoption: `KeyPair::from_seed(Seed::new([u8;32]))` (deterministic test signer),
`sk.sign(msg, None)`, and `PublicKey::new([u8;32]).verify(msg, &Signature::new([u8;64]))`. The whole
tree clears dep-scan **exit 0** (`ed25519-compact` row: all checks pass). **Smaller clearing tree wins
→ `ed25519-compact`, pinned to 2.3.1.**

**Honest residual (dependency).** `getrandom` **0.2.17** is already in the committed baseline tree via
`aes-gcm` → `crypto-common` → `rand_core` → `getrandom` (since task 004); this task neither adds nor
removes it, and it passes dep-scan on the settled run. During measurement dep-scan's data was mid-cache
-refresh and transiently BLOCKED `getrandom` on a `maintainer_change` advisory; the settled scan passes
it. That advisory, if it re-fires, is a **pre-existing** condition on the `aes-gcm` tree, orthogonal to
this crate choice, and is left for a future dependency-audit pass. The grep proof this task asserts is:
`zeroize` absent, literal `rand` absent, no `getrandom` 0.4 (the version compact's defaults would add).

## Decision 2: verification at the dispatch edge, one payload-shape seam

A new module `src/attest.rs` (house pattern: one module per concern):

- `trait AttestationVerifier { fn verify(&self, sandbox_identity: &Value) -> Result<String, AttestError>; }`
  returns the **verified** sandbox id on success.
- `enum AttestError { Missing, Invalid(String) }` → error codes `attestation_missing` /
  `attestation_invalid` in the standard `{error:{code,message,retryable:false}}` shape.
- `struct Ed25519Verifier` holds the 32-byte trust-root public key; verifies the base64 signature
  over the raw decoded payload bytes against the root AND that the signed payload's `sandbox_id` equals
  the outer `sandbox_identity.sandbox_id`; returns the verified id.
- `struct PassthroughVerifier` is the transitional no-trust-root mode: extracts `sandbox_id` exactly as
  dispatch does today, ignores any `attestation` member. Doc-comment marks it transitional (the gap
  stays open in this mode).
- `fn attested_sandbox_id(payload_bytes: &[u8]) -> Result<String, AttestError>` is **the single
  payload-shape seam.** Today it parses the provisional fixture shape; when exec-sandbox 020-021 fix the
  real shape, **only this function (and the test fixture builder) changes**: no test, trait, config, or
  contract change.

Verification sits at the dispatch edge, **before any `Vault` call**, exactly like the SO_PEERCRED gate
(ADR-002). A rejected attestation returns the mapped error and `Vault::inject` is never called, so a
failed verification can never consume, bind, or expire-check a handle. `Vault::inject`'s signature,
binding logic, and precedence (unknown_handle → consumed → expired → invalidated → binding → deliver)
are **unchanged**.

### Provisional wire shape (superset of today's; old callers unchanged)

```json
{"op":"inject","handle":"<hex64>","mode":"proxy",
 "sandbox_identity":{
   "sandbox_id":"sbx-1",
   "attestation":{
     "alg":"ed25519",
     "payload":"<base64: canonical JSON {\"sandbox_id\":\"sbx-1\"}>",
     "signature":"<base64: 64-byte Ed25519 signature over the raw decoded payload bytes>",
     "key_id":"<optional, advisory only — never used to select a key>"
   }}}
```

The signed payload is base64 of the canonical JSON `{"sandbox_id":"…"}`, the ONE provisional constant,
isolated in `attested_sandbox_id`. The signature is over the **raw decoded payload bytes** (not the JSON
string, not the base64). `key_id` is carried but advisory: the key is always the single configured
trust root, never selected from the request.

## Decision 3: trust-root configuration (mirrors `resolve_store_path` exactly)

- `--attest-trust-root-file PATH` flag wins over `VAULT_ATTEST_TRUST_ROOT_FILE` env, via a pure
  `resolve_trust_root_path(flag, env)` (same shape as `resolve_store_path`).
- File contents: the 32-byte Ed25519 **public** key, hex (64 chars) or base64, whitespace-trimmed,
  decoded by reusing `crypto::decode_base64` (already `pub`) and `crypto::decode_hex` (promoted to
  `pub(crate)`), same accept-rules as `decode_key`.
- Configured-but-unusable (unreadable file, wrong length, not hex/base64) ⇒ `serve` **refuses to start**
  (stderr + non-zero exit, no panic), same posture as a corrupt `--store-path`.
- Unset ⇒ `PassthroughVerifier` (transitional; no verifier constructed, today's behavior byte-for-byte).

## Decision 4: transitional passthrough is an explicit, documented opt-in

With no trust root configured, the attestation member is ignored and the opaque first-use binding is
exactly today's behavior. This is **transitional**: the unverifiable-binding gap remains open in that
mode. The configured mode is the intended posture once exec-sandbox publishes its trust root. The spec
(`configuration.md`, `interfaces.md`, `behaviors.md`) states only the **as-built present** (the
provisional payload shape, the two new error codes, the verify-before-dispatch ordering); the pending
exec-sandbox alignment lives here and in the task, not the spec.

## Honest residuals (NOT claimed closed)

- **Cross-repo end-to-end is NOT claimed.** vault verifies against a **fixture** attestation signed by a
  deterministic test key. A real exec-sandbox attestation verified against exec-sandbox's published
  trust root is not achievable until their tasks 020-021 ship. Local L6 covers only the vault-side
  behavior (fail-closed rejections, passthrough, and the fixture-signed positive path).
- **Attestation freshness / anti-replay of the blob itself** (nonce/expiry) belongs to the final
  exec-sandbox payload; the handle's own single-use + TTL already bound the damage window.
- **Single trust root only.** Key rotation of the root, multi-root support, and `key_id`-based
  selection are out of scope; `key_id` is carried but advisory.

## Consequences

- One new pinned dependency (`ed25519-compact` 2.3.1, default-features off); `zeroize`/`rand`/new
  `getrandom` absent from `Cargo.lock`; the tree clears dep-scan exit 0.
- Contract v1 unchanged: response shapes byte-for-byte identical; the `attestation` member is additive
  on the request. `resolve` stays value-free; the raise-only floor, single-use, first-use binding, TTL,
  and rotation-invalidation are untouched (they live in `Vault::inject`, above the verify edge).
- When exec-sandbox 020-021 land, a small follow-up task changes only `attested_sandbox_id` + the test
  fixture builder to the final payload shape, and flips the deployment to configure the published root.
</content>
