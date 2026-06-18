# ADR-007 — Row 7 first backend target: cloud secret-manager (behind the StoreBackend seam)

**Status:** Accepted (direction) — execution deferred (credential-blocked)
**Date:** 2026-06-18
**Relates to:** [ADR-005](005-encrypted-at-rest-store.md) (the `StoreBackend` + `KeyProvider`
seams this backend plugs into), [ADR-006](006-vault-http-api-compat.md) (the Vault HTTP API
shape), [roadmap](../../plans/roadmap.md) Row 7 / Remaining work R2.

## Context

Roadmap Row 7 — "Cloud-KMS / HSM backends" — names three candidate first backends behind the
`vault://` / `StoreBackend` seam: a **PKCS#11 HSM**, a **cloud secret-manager** (AWS / GCP /
Azure), or an **OpenBao passthrough**. R2 records that "which to build first … is a
product/deployment-target call" — it is **not** derivable from the codebase or the scoping docs,
because it depends on where the operator deploys vault. The `/autopilot` run therefore stopped on
this decision rather than guessing.

The operator's decision: **build the cloud secret-manager backend first.**

## Decision

The next Row-7 increment implements a **cloud secret-manager `StoreBackend`** behind task 004's
seam: at the injection edge, `inject` resolves the plaintext credential by calling the cloud
provider's "get secret value" API instead of decrypting a local ciphertext. The contract is
unchanged — `resolve` still returns only a handle; the value still re-materialises only at the
`inject` edge, never to the agent.

To avoid coupling the seam to one vendor, the backend is split:

- a cloud-agnostic `SecretManagerBackend: StoreBackend` that owns the put/rotate/decrypt-at-inject
  flow and the zero-knowledge invariants, delegating the actual fetch/store to
- a `SecretManagerClient` trait (`get_value` / `put_value` / `rotate_value`) — **the single,
  documented pluggability seam** — with one concrete adapter per secret store behind it.

**Pluggability is a first-class requirement (operator directive).** The `SecretManagerClient`
trait is *the* extension point: adopting a different secret store means **dropping in one new
trait implementation and selecting it** — nothing in `SecretManagerBackend`, `Vault`, the
contract, or any caller changes. To prove this is real (not aspirational), the increment ships
**2–3 reference adapters** as worked examples, not a single one:

- **AWS Secrets Manager** (reference / first),
- **GCP Secret Manager**,
- **Azure Key Vault** (or HashiCorp Vault / OpenBao via the ADR-006 HTTP shape).

Each adapter is ~one file implementing `get_value`/`put_value`/`rotate_value` against that store's
API; they share zero secret-path logic (that all lives in `SecretManagerBackend`). Backend
selection is config-driven (e.g. `--secret-backend aws|gcp|azure` or a `vault://`-scheme hint). A
fourth store a user wants is a fourth file implementing the same trait + a registry/selection
entry — the documented "drop-in" path. A `SecretManagerClient` **mock** is the test double that
keeps the core unit-verifiable without any network or credentials.

This keeps the **load-bearing invariants** intact and vendor-pluggable: zero-knowledge `resolve`,
raise-only floor, single-use + first-use binding, TTL, fail-closed (a failed remote fetch →
structured error, never a plaintext fallback), and "the value crosses only the injection edge".

## Open items / blockers (why execution is deferred)

This decision settles the **direction**; two prerequisites must be supplied before the task can be
executed to ✅, and both are genuine blockers for a local, credential-free run:

1. **Confirm the primary cloud + which adapters ship in the first cut** (the directive is 2–3:
   AWS Secrets Manager + GCP Secret Manager + Azure Key Vault by default). This fixes which SDK /
   REST dependencies are pulled. The cloud-agnostic core + the mock adapter need no such pick; only
   the live adapters do.
2. **Live credentials + a reachable secret-manager** (per cloud being verified live) for L5/L6.
   The unit-level core (the seam + a mock `SecretManagerClient`) is verifiable locally — mirroring
   how task 004
   proved the `StoreBackend` seam with a test backend — but a real end-to-end inject against the
   live provider needs credentials and a provisioned secret, which a `--local` run does not have.

## Dependency note (ask-first, not yet added)

Each concrete adapter pulls that store's SDK (e.g. `aws-sdk-secretsmanager`,
`google-cloud-secretmanager`, an Azure Key Vault crate) or a hand-rolled REST + request-signing
path. These are **large** new dependency trees relative to vault's minimal floor, so **every
adapter's dependency tree clears `dep-scan` as a blocking gate and is version-pinned** before
adoption — the same gate applied to `nix`, `aes-gcm`, and `tiny_http`. Because shipping 2–3
adapters multiplies that surface, prefer the smallest viable per-adapter dependency (a shared REST
client + each provider's signing scheme can beat three full SDK trees), and gate each adapter
behind a Cargo **feature** so an operator compiles in only the stores they use (the mock + the
trait need no feature). Evaluate SDK-vs-REST under dep-scan per store when the set is confirmed.
No cloud SDK is added by this ADR.

## Consequences

- The seam proven in task 004 now has a second, remote-backed implementation target — validating
  the "backends swap without changing callers" design property.
- vault gains a network egress dependency for the secret path (to the cloud provider) — a new
  availability and trust consideration to capture in the spec when the adapter lands.
- PKCS#11 HSM (strongest key custody) and OpenBao passthrough remain available as later backends
  behind the same `StoreBackend` / `SecretManagerClient` seam; this ADR does not preclude them.
- Row 6 (SPIFFE identity binding) remains externally blocked (R1) and is independent of this choice.
