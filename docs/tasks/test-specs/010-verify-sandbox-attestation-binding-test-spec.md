# Test Spec 010: Verify the signed sandbox attestation when binding a handle at first use

**Linked task:** [`docs/tasks/backlog/010-verify-sandbox-attestation-binding.md`](../backlog/010-verify-sandbox-attestation-binding.md)
**Written:** 2026-07-11
**Addresses:** the documented unverifiable-binding gap — today `inject` binds a handle to whatever
opaque `sandbox_id` string the caller presents (first-use binding, `HandleRec.bound_sandbox` in
`src/vault.rs`); nothing proves the caller *is* that sandbox.
**Design:** ADR-010 (written by the executor — records the Ed25519 crate decision + the trust-root
config + the provisional payload shape pending exec-sandbox tasks 020-021)

> **Payload shape is provisional.** exec-sandbox (its tasks 020-021, in flight) owns the final
> `sandbox_identity.attestation` payload: an Ed25519 signature by a host-held key over the sandbox
> identity, with a published trust root. This spec tests the **vault-side seam** against a
> **fixture attestation** whose payload-shape knowledge is isolated in ONE function
> (`attested_sandbox_id` in `src/attest.rs`) plus one fixture constant — when exec-sandbox 020-021
> land, only that function/constant changes; every TC below stays valid. All TCs are locally
> verifiable now (the test signer derives a deterministic keypair from a fixed seed — no network,
> no exec-sandbox needed).

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002 | ✅ |
| REQ-003 | TC-003, TC-004, TC-005 | ✅ |
| REQ-004 | TC-002, TC-006 | ✅ |
| REQ-005 | TC-007 | ✅ |
| REQ-006 | TC-008 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous
- [ ] The negative cases (tampered signature, wrong key) are **mutation-tested inside the same
      test**: each rejection assertion sits next to a valid-control assertion on the same vault
      state, so a vacuous always-reject or always-accept implementation fails the test
      (agent-rules: no smoke tests; the task-148 retro — negative assertions must be provably
      attributable to the tampering, not to independent breakage)

---

## Test fixtures

- **Fixture keypair** — derived deterministically from a fixed 32-byte seed (e.g.
  `SigningKey::from_bytes(&[7u8; 32])` with ed25519-dalek, or the ed25519-compact equivalent).
  No `rand` crate, no OS entropy needed in tests. The verifying (public) half is the test's
  trust root.
- **Wrong keypair** — a second deterministic keypair from a different seed (`[8u8; 32]`) used by
  TC-004 to sign an otherwise-valid attestation.
- **`fixture_attestation(sandbox_id, signer)`** — a test helper that builds the provisional wire
  shape: `payload` = base64 of the canonical JSON `{"sandbox_id":"<sandbox_id>"}` (the ONE
  provisional constant), `signature` = base64 of the 64-byte Ed25519 signature over the raw
  decoded payload bytes, `alg` = `"ed25519"`. Every TC builds requests through this helper so the
  payload shape lives in exactly one test location, mirroring `attested_sandbox_id` in the
  implementation.
- **Dispatch-level harness** — TCs 002–006 drive `dispatch(&req, &vault, &verifier)` in
  `src/main.rs` (the live socket path minus the socket), NOT `Vault::inject` directly — the
  dead-wire retro: a verifier that exists but is not on the live path must fail these tests.

---

## Test cases

### TC-001: trust-root config — precedence, decode, fail-closed startup

- **Requirement:** REQ-001
- **Input:** the pure resolver `resolve_trust_root_path(flag, env)` (mirrors
  `resolve_store_path` in `src/main.rs`) over the four combinations of
  `--attest-trust-root-file` / `VAULT_ATTEST_TRUST_ROOT_FILE`; and `parse_trust_root(s)` over:
  a 64-char hex 32-byte key, the same key base64-encoded, a 31-byte key, a 33-byte key, an empty
  string, and a non-hex/non-base64 string.
- **Expected output:** flag wins when both set; env is the fallback; neither ⇒ `None`
  (transitional passthrough — no verifier constructed). `parse_trust_root` returns exactly the
  32 decoded bytes for the hex and base64 forms (byte-for-byte equal to each other) and
  `Err(String)` for every malformed case — never a panic, never a default/zero key.
- **Edge cases:** surrounding whitespace/newline in the key file is trimmed (mirrors
  `EnvKeyProvider`'s `raw.trim()`); a configured-but-unreadable file is an `Err` so `serve`
  refuses to start (asserted at the unit level on the loader function; the live refuse-to-start
  is the L6 observation).

### TC-002: valid signed attestation → verified, inject delivers, handle binds to the attested id

- **Requirement:** REQ-002, REQ-004
- **Input:** vault seeded via `put` (fixed-key AES test backend, as in `src/vault.rs::seeded()`);
  `resolve` → handle H. Build
  `{"op":"inject","handle":H,"mode":"proxy","sandbox_identity":{"sandbox_id":"sbx-1","attestation":{…fixture_attestation("sbx-1", fixture_key)…}}}`
  and run it through `dispatch` with an `Ed25519Verifier` built from the fixture trust root.
- **Expected output:** `{"ok":true,"delivery":"proxy","credential":"SK-SECRET","binding":{…}}` —
  byte-for-byte the existing contract response (no attestation type leaks into the response).
  Internally the handle is bound to `"sbx-1"` (the **attested** id): a second inject for the same
  handle returns `handle_consumed`, and a *fresh* handle first injected by attested `"sbx-1"`
  then presented with a valid attestation for `"sbx-2"` returns
  `handle_bound_to_other_sandbox` — first-use binding semantics unchanged, now over a verified id.
- **Edge cases:** unit-level, `Ed25519Verifier::verify(&sandbox_identity)` returns
  `Ok("sbx-1".to_string())` — the verified id comes from the **signed payload**, not trusted from
  the outer field.

### TC-003: tampered signature and tampered payload are rejected — fail-closed, handle not burned

- **Requirement:** REQ-003
- **Input:** same vault/handle setup as TC-002. Three requests through `dispatch`:
  (a) the valid control request; (b) the same request with one byte of the decoded `signature`
  flipped (re-encoded to base64); (c) the same request with one byte of the decoded `payload`
  flipped (signature left as originally computed).
- **Expected output:** run (b) FIRST: `{"error":{"code":"attestation_invalid",…}}` — no `ok`, no
  `credential`, no `binding` anywhere in the response. Run (c) next: `attestation_invalid`
  likewise. THEN run (a) — the valid control — against the **same handle**: it succeeds and
  delivers `"SK-SECRET"`. This ordering proves both that the rejection is attributable to the
  tamper (the untampered request works) and that a failed verification does **not** consume or
  bind the handle (verification precedes all handle mutation).
- **Edge cases:** the rejection response contains the substring `SK-SECRET` nowhere
  (`resp.to_string().find("SK-SECRET").is_none()`); `retryable` is `false`.

### TC-004: attestation signed by the wrong key is rejected

- **Requirement:** REQ-003
- **Input:** same setup; a structurally perfect attestation for `"sbx-1"` signed by the **wrong
  keypair** (seed `[8u8; 32]`), verified against the fixture trust root (seed `[7u8; 32]`).
- **Expected output:** `{"error":{"code":"attestation_invalid",…}}` — no credential, handle not
  consumed. Control in the same test: the identical request signed by the **correct** key
  succeeds against the same handle — so the rejection is attributable to the key, not the shape.
- **Edge cases:** a request signed by the correct key but verified by a vault configured with the
  *wrong-key* trust root also fails — verification is against the configured root, not any key
  material in the request (`key_id` is advisory only, never used to select a key).

### TC-005: missing / malformed attestation and sandbox_id mismatch are rejected

- **Requirement:** REQ-003
- **Input:** trust root configured. Through `dispatch`: (a) today's v1 request shape —
  `"sandbox_identity":{"sandbox_id":"sbx-1"}` with **no** `attestation` member; (b) `attestation`
  present but `signature` is not valid base64; (c) decoded `signature` is 63 bytes; (d) `payload`
  is valid base64 of non-JSON bytes; (e) a **valid** signature over payload
  `{"sandbox_id":"sbx-EVIL"}` presented with outer `"sandbox_id":"sbx-1"`.
- **Expected output:** (a) → `{"error":{"code":"attestation_missing",…}}`; (b)–(d) →
  `attestation_invalid`; (e) → `attestation_invalid` (the signed payload's id and the outer id
  must agree — a valid signature over a *different* identity must not bind as `sbx-1`). In every
  case: no credential, no state mutation — a follow-up valid inject on the same handle succeeds.
- **Edge cases:** `sandbox_identity` missing entirely, or `sandbox_id` empty, → fail-closed error
  (never a bind to `""`); `alg` other than `"ed25519"` → `attestation_invalid`.

### TC-006: transitional passthrough — no trust root configured ⇒ behavior byte-for-byte today's

- **Requirement:** REQ-004, REQ-005 boundary
- **Input:** no trust root (verifier is the `PassthroughVerifier`). Through `dispatch`: today's
  exact request shape `{"op":"inject","handle":H,"sandbox_identity":{"sandbox_id":"sbx-1"},"mode":"proxy"}`
  with no attestation; and the same request WITH a (garbage) attestation attached.
- **Expected output:** both deliver normally — with no trust root configured, the attestation
  member is ignored (not validated, not required), exactly today's opaque first-use binding. All
  prior `src/vault.rs` / `src/main.rs` tests (tasks 001–008, 74 tests) pass unmodified.
- **Edge cases:** replay → `handle_consumed` and other-sandbox → `handle_bound_to_other_sandbox`
  still hold in passthrough mode (not regressed).

### TC-007: transitional opt-in is documented, not silent

- **Requirement:** REQ-005
- **Input:** `docs/spec/configuration.md`, `docs/spec/interfaces.md`, ADR-010, and the
  `PassthroughVerifier` doc-comment.
- **Expected output:** the no-trust-root mode is explicitly documented as **transitional** (the
  unverifiable-binding gap remains open in that mode); the configured mode is documented as the
  intended posture once exec-sandbox publishes its trust root. The spec states the **current**
  provisional payload shape as-built (no future tense in spec files; the pending exec-sandbox
  alignment lives in the ADR + this task, not the spec).
- **Edge cases:** ADR-010 records the provisional-payload decision and the single-function seam
  (`attested_sandbox_id`) that absorbs the exec-sandbox 020-021 final shape.

### TC-008: dependency gate — Ed25519 crate pinned, dep-scan-cleared, `zeroize` still absent

- **Requirement:** REQ-006
- **Input:** `Cargo.toml` + `Cargo.lock` after the crate is added;
  `dep-scan check --lockfile Cargo.lock --lockfile-type crates`.
- **Expected output:** exactly ONE new direct dependency (the chosen Ed25519 verify crate —
  candidate A `ed25519-dalek` 2.x with `default-features = false`, candidate B `ed25519-compact`;
  whichever clears dep-scan with the smaller tree), version-pinned. dep-scan exits 0, all
  packages pass, stable across runs. **`zeroize` remains absent from `Cargo.lock`** — the crate is
  dep-scan-BLOCKED (ADR-009), and ed25519-dalek's *default* feature set pulls it, so defaults
  MUST be off; a test/assertion greps `Cargo.lock` for `name = "zeroize"` and finds nothing.
- **Edge cases:** no `rand`/`getrandom` enters the tree (tests sign from fixed seeds; production
  only verifies); if **neither** candidate clears dep-scan, the task **stops and escalates** —
  hand-rolling Ed25519 is forbidden (unlike task 008's byte-wipe, curve arithmetic is not a
  hand-rollable primitive).
