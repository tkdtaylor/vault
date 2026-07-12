# Task 010: Verify the signed sandbox attestation when binding a handle at first use

**Project:** vault
**Created:** 2026-07-11
**Status:** ready (seam + fixture attestation now; final payload shape blocked on exec-sandbox 020-021)

> **Blocked-by (partial): exec-sandbox tasks 020-021.** exec-sandbox is producing (ADR + implementation,
> in parallel) a SIGNED `sandbox_identity.attestation`: an Ed25519 signature by a **host-held key** over
> the sandbox identity, with a **published trust root** — replacing today's random-bytes identity. The
> final payload shape is theirs to fix. This task is **executable now**: it builds the vault-side seam
> and verifies against a **fixture attestation**, isolating all payload-shape knowledge in ONE function
> (`attested_sandbox_id`) + one fixture constant, so when 020-021 land only that constant/function
> changes — no test, seam, or contract change. Do NOT wait for exec-sandbox to start this task; do NOT
> claim the cross-repo end-to-end (real exec-sandbox attestation → vault verify) from a local run.

## Goal

Close the documented unverifiable-binding gap: today `inject(handle, sandbox_identity, mode)` binds a
handle at first use to whatever opaque `sandbox_id` string the caller presents
(`HandleRec.bound_sandbox` in `src/vault.rs`; extraction at
`src/main.rs::dispatch` — `req["sandbox_identity"]["sandbox_id"]`). Nothing proves the caller *is* that
sandbox. Add **Ed25519 verification of the sandbox attestation** at the dispatch edge: accept a
trust-root public key via config/flag, verify the signature over the attested sandbox identity, and
**fail closed** (reject the inject with a structured error, handle untouched) on a missing/invalid
signature **when a trust root is configured**. When none is configured, preserve current behavior
byte-for-byte — an explicit, documented **transitional** opt-in.

## Context

- Tech stack: Rust, minimal deps (`serde` + `serde_json` + `nix` + `aes-gcm` + `tiny_http`). RNG via
  `/dev/urandom`, no `rand` crate. Every dep addition is ask-first + dep-scan-gated + ADR-recorded.
- **Where the gap lives today:**
  - `src/main.rs::dispatch`, the `Some("inject")` arm — extracts
    `req["sandbox_identity"]["sandbox_id"].as_str().unwrap_or("")` and passes it straight to
    `Vault::inject` as a trusted string.
  - `src/vault.rs::inject(&mut self, handle: &str, sandbox_id: &str, requested: Option<Mode>)` —
    first-use binding (`rec.bound_sandbox = Some(sandbox_id.to_string())`), replay →
    `handle_consumed`, other sandbox → `handle_bound_to_other_sandbox`. **This function and its
    binding/precedence logic do not change** — verification happens upstream, and the verified id is
    what flows in as `sandbox_id`.
- **New module `src/attest.rs`** (house pattern: one module per concern, like `src/http.rs` /
  `src/store_file.rs` / `src/zeroize.rs`):
  - `pub trait AttestationVerifier: Send + Sync { fn verify(&self, sandbox_identity: &serde_json::Value) -> Result<String, AttestError>; }`
    — returns the **verified** sandbox id on success.
  - `pub enum AttestError { Missing, Invalid(String) }` → mapped to error codes
    `attestation_missing` / `attestation_invalid` in the standard shape
    `{error:{code,message,retryable:false}}` (reuse `err()` in `src/main.rs`).
  - `pub struct Ed25519Verifier { /* 32-byte trust-root VerifyingKey */ }` — verifies the signature
    over the attestation payload against the configured trust root AND that the signed payload's
    `sandbox_id` equals the outer `sandbox_identity.sandbox_id`.
  - `pub struct PassthroughVerifier` — the transitional no-trust-root mode: extracts
    `sandbox_id` exactly as `dispatch` does today, ignores any `attestation` member, doc-comment
    marks it transitional (the gap remains open in this mode).
  - `fn attested_sandbox_id(payload_bytes: &[u8]) -> Result<String, AttestError>` — the **single
    payload-shape seam**: today it parses the provisional fixture shape (base64-decoded payload is
    the canonical JSON `{"sandbox_id":"…"}`); when exec-sandbox 020-021 fix the real shape, only
    this function (and the test fixture builder) changes.
- **Wire shape (provisional, superset of today's — old callers unchanged):**

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

- **Trust-root configuration** (mirror the existing patterns exactly):
  - Flag `--attest-trust-root-file PATH` wins over env `VAULT_ATTEST_TRUST_ROOT_FILE` — a pure
    `resolve_trust_root_path(flag, env)` in `src/main.rs`, same shape as `resolve_store_path`.
  - File contents: the 32-byte Ed25519 **public** key, hex (64 chars) or base64, whitespace-trimmed
    — decode by reusing `src/crypto.rs::decode_base64` (already `pub`) and `decode_hex` (promote to
    `pub(crate)`), same accept-rules as `decode_key`.
  - Configured-but-unusable (unreadable file, wrong length, not hex/base64) ⇒ `serve` **refuses to
    start** (stderr message + non-zero exit, no panic) — same posture as a corrupt `--store-path`
    file. Unset ⇒ `PassthroughVerifier` (transitional).
- **Verification sits at the dispatch edge, before any Vault call** — same layering as the
  SO_PEERCRED gate (ADR-002): no op dispatches for a rejected peer; no inject reaches `Vault::inject`
  for a rejected attestation. So a failed verification can never consume, bind, or expire-check a
  handle, and `Vault`'s inject precedence (unknown_handle → consumed → expired → invalidated →
  binding → deliver, ADR-003/004) is untouched.
- **Dependency (ask-first, executor MUST write ADR-010):** Ed25519 verification needs a crate — do
  NOT hand-roll curve arithmetic (unlike task 008's byte-wipe, this is not a hand-rollable
  primitive; a wrong implementation is silently insecure). Candidates, both evaluated under
  dep-scan, smaller clearing tree wins, version-pinned:
  - **A (default): `ed25519-dalek` 2.x** with `default-features = false, features = ["std"]` —
    **defaults MUST be off**: the default feature set pulls the dep-scan-BLOCKED `zeroize` crate
    (ADR-009). Verify-only usage: `VerifyingKey::from_bytes(&[u8;32])`,
    `Signature::from_slice(&[u8;64])`, `verify_strict`.
  - **B (fallback): `ed25519-compact`** (small, self-contained tree).
  - Hard requirement either way: `zeroize` and `rand`/`getrandom` stay **absent from `Cargo.lock`**
    (tests sign from fixed seeds; production only verifies). If neither candidate clears dep-scan:
    **stop and escalate** — that is a blocker to report, not a license to hand-roll.
- Related: [roadmap](../../plans/roadmap.md) row 6 / R1 (SPIFFE binding — task 011 builds the
  *principal* seam; this task makes the *sandbox identity itself* verifiable; they compose at
  dispatch: attestation verify first, then principal resolve), ADR-002 (peer-uid gate layering),
  ADR-009 (`zeroize` BLOCK — the reason dalek defaults must be off),
  [`docs/CONTRACT.md`](../../CONTRACT.md) (v1 — response shapes unchanged; the attestation member is
  additive on the request).
- Sibling repos: **exec-sandbox tasks 020-021** (signed `sandbox_identity.attestation` + published
  trust root — the producer side), **agent-mesh task 008** (verified principals — task 011's
  producer). One task = one repo: this task touches only vault; the cross-repo end-to-end is a
  future sequenced task.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | Trust-root config seam: `--attest-trust-root-file` flag > `VAULT_ATTEST_TRUST_ROOT_FILE` env (pure precedence fn); file contents hex/base64-decoded + trimmed to exactly 32 bytes; configured-but-unusable ⇒ refuse to start (no panic); unset ⇒ `PassthroughVerifier`. | must have |
| REQ-002 | `src/attest.rs` seam: `AttestationVerifier` trait; `Ed25519Verifier` verifies the base64 signature over the raw decoded payload bytes against the trust root AND payload `sandbox_id` == outer `sandbox_id`, returning the verified id; ALL payload-shape knowledge isolated in `attested_sandbox_id` (one function + one test fixture builder). | must have |
| REQ-003 | Fail-closed on the live path: with a trust root configured, `dispatch` rejects inject with `attestation_missing` (no attestation member) or `attestation_invalid` (bad base64, wrong lengths, non-JSON payload, tampered payload or signature, wrong signing key, id mismatch, alg ≠ "ed25519") — structured error shape, `retryable:false`, no credential anywhere in the response, `Vault::inject` never called, handle neither consumed nor bound. | must have |
| REQ-004 | A valid attestation verifies and inject proceeds exactly as today with the **verified** id as the binding key: contract responses byte-for-byte unchanged; single-use, first-use binding, TTL, rotation-invalidation, raise-only floor all unchanged. | must have |
| REQ-005 | Transitional opt-in preserved and documented: no trust root ⇒ today's behavior byte-for-byte (attestation member ignored if present); all prior tests (tasks 001–008) pass unmodified; the transitional nature + provisional payload shape recorded in `docs/spec/configuration.md`, `docs/spec/interfaces.md`, and ADR-010 (spec states only the as-built present; the pending exec-sandbox alignment lives in the ADR/task). | must have |
| REQ-006 | Dependency gate: one new pinned Ed25519 verify crate (dalek-no-defaults or ed25519-compact), chosen by dep-scan (blocking, exit 0); `zeroize` and `rand`/`getrandom` absent from `Cargo.lock`; decision + rationale + provisional payload + trust-root design recorded in ADR-010. | must have |

## Implementation outline

1. `scripts/start-task.sh 010 verify-sandbox-attestation-binding` (branch or worktree; `cd` in if WORKTREE).
2. Run both candidate crates through dep-scan (`dep-scan check --lockfile Cargo.lock --lockfile-type crates` after a trial `cargo add ed25519-dalek@2 --no-default-features --features std` / `cargo add ed25519-compact`); pick the smaller clearing tree; pin it; grep `Cargo.lock` to prove `zeroize`/`rand`/`getrandom` absent. Write **ADR-010** (crate decision, trust-root config, provisional payload shape + the `attested_sandbox_id` seam, transitional passthrough). Commit (`docs: add ADR 010 — …`).
3. Create `src/attest.rs`: `AttestError`, `AttestationVerifier`, `attested_sandbox_id` (provisional shape), `Ed25519Verifier`, `PassthroughVerifier`; register `mod attest;` in `src/main.rs`. Promote `decode_hex` in `src/crypto.rs` to `pub(crate)`.
4. In `src/main.rs`: add `resolve_trust_root_path` + a `load_trust_root(path) -> Result<[u8;32], String>` loader; in `serve`, build `Box<dyn AttestationVerifier>` (Ed25519 when configured, refuse-to-start on unusable, passthrough when unset); thread the verifier into `dispatch` (extra parameter, mirroring how `v` is threaded); rewrite the `Some("inject")` arm: `verifier.verify(&req["sandbox_identity"])` → on `Err`, return the mapped error; on `Ok(verified_id)`, call `v.lock().unwrap().inject(handle, &verified_id, mode)`. `demo()` keeps the passthrough verifier.
5. Tests per the test spec (TC-001…TC-008), fixtures signed from fixed seeds, negative cases with in-test valid controls, all driven through `dispatch`.
6. Spec updates in the same feat commit: `docs/spec/configuration.md` (new flag/env row + refuse-to-start rule), `docs/spec/interfaces.md` (inject request superset + the two new error codes in the IPC table), `docs/spec/behaviors.md` (verify-before-dispatch ordering), `docs/architecture/diagrams.md` (inject flow gains the attestation gate; date bump).
7. `cargo build && cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`; move this file to `docs/tasks/completed/` (git mv), coverage-tracker row 🟡, `feat: complete task 010 — …`; then spec-verifier; then L5/L6 evidence and the separate `verify:` commit.

## Readiness gate

- [x] Test spec `010-verify-sandbox-attestation-binding-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] The provisional payload shape + the one-function seam that absorbs exec-sandbox 020-021's final shape are captured here and will be recorded in ADR-010
- [ ] Ed25519 crate candidate dep-scan-cleared + pinned (ask-first — done inside the task, step 2, before any implementation code)

## Acceptance criteria

- [ ] [REQ-001] Trust-root precedence (flag > env > unset), 32-byte hex/base64 decode + trim, refuse-to-start on unusable config, passthrough on unset (TC-001).
- [ ] [REQ-002] Valid fixture attestation → `Ok(verified_id)`; verified id comes from the signed payload; payload-shape knowledge lives only in `attested_sandbox_id` + the fixture builder (TC-002).
- [ ] [REQ-003] Tampered signature, tampered payload, wrong key, missing attestation, malformed base64/lengths, non-JSON payload, id mismatch, wrong alg — each rejected fail-closed with the right code, with an in-test valid control on the same handle proving attribution AND that the handle is not burned (TC-003, TC-004, TC-005).
- [ ] [REQ-004] Valid attestation delivers byte-for-byte the existing contract response; first-use binding/single-use/other-sandbox semantics hold over the verified id (TC-002).
- [ ] [REQ-005] No trust root ⇒ today's behavior exactly; 74 prior tests pass unmodified; transitional mode + provisional shape documented in spec + ADR-010 (TC-006, TC-007).
- [ ] [REQ-006] dep-scan exit 0 on the pinned tree; `zeroize`/`rand`/`getrandom` absent from `Cargo.lock`; ADR-010 written (TC-008).
- [ ] `cargo build && cargo test` green — all new TCs plus every prior test (tasks 001–008) passing.

## Verification plan

- **Highest level achievable:** **L6 locally** for the vault-side behavior (the fail-closed rejections
  and the passthrough mode are observable on a live socket; the positive signed path is observable via
  a fixture-signed request emitted by an ignored test). The **cross-repo** end-to-end (a real
  exec-sandbox attestation verified against exec-sandbox's published trust root) is NOT achievable
  until their tasks 020-021 ship — do not claim it.
- **Level 5 — validation harness command:**
  ```
  cargo build && cargo test
  ```
  Expected final assertion: `test result: ok` — TC-001…TC-006 through `dispatch` (valid → deliver +
  bind-to-verified-id; tampered sig/payload → `attestation_invalid` with valid control after; wrong
  key → `attestation_invalid`; missing → `attestation_missing`; id mismatch → `attestation_invalid`;
  passthrough unchanged), plus all 74 prior tests.
- **Level 6 — runtime observation:** write the fixture trust root (hex) to a temp file; run
  `cargo run -- serve --socket /tmp/v010.sock --attest-trust-root-file /tmp/v010.root`; over the
  socket: (a) inject with **no** attestation → observe `attestation_missing`; (b) inject with a
  garbage signature → observe `attestation_invalid`; (c) a **valid** signed request — obtained from
  the ignored fixture-emitter test (`cargo test print_fixture_inject -- --ignored --nocapture`,
  which prints a complete signed inject JSON line for a freshly resolved handle flow) → observe
  delivery; (d) restart WITHOUT the flag and replay today's plain request → observe delivery
  (transitional mode live). Also observe refuse-to-start with a malformed root file (non-zero exit).
  Quote the socket transcripts in the `Verified by` column.
- **Level 3 (supporting):** `dep-scan check --lockfile Cargo.lock --lockfile-type crates` exit 0;
  `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` clean; `grep 'name = "zeroize"'
  Cargo.lock` empty.
- **ADR owed:** `docs/architecture/decisions/010-verify-sandbox-attestation-binding.md` (use the next
  free ADR number at execution time; 010 is free as of writing).

## Out of scope

- The exec-sandbox side: producing/signing attestations, key custody, trust-root publication, and the
  final payload shape (exec-sandbox tasks 020-021 own these).
- Attestation freshness/anti-replay of the attestation blob itself (nonce/expiry semantics belong to
  the final exec-sandbox payload; the handle's own single-use + TTL already bound the damage window).
- Key rotation of the trust root, multi-root support, and `key_id`-based key selection (single
  configured root only; `key_id` is carried but advisory).
- SPIFFE/principal binding (task 011) and any change to `Vault::inject`'s signature, binding logic, or
  error precedence.
- Verifying identity at `resolve` (the agent-facing edge is unchanged; only the inject edge binds).

## Dependencies

- **Blocked-by (payload finalization only):** exec-sandbox tasks 020-021 — final
  `sandbox_identity.attestation` payload shape + published trust root. The seam, tests, config, and
  fail-closed behavior land NOW against the fixture; a small follow-up task aligns
  `attested_sandbox_id` + the fixture when 020-021 ship.
- **New crate (ask-first, in-task):** `ed25519-dalek` 2.x (no default features) or
  `ed25519-compact` — dep-scan-gated, pinned, ADR-010.
- Builds on: task 001 (dispatch-edge gate layering), task 004 (fixed-key test backend used by the
  test vaults), task 008 (`zeroize`-absent constraint). Independent of task 006 (blocked) and
  composable with task 011 (verify-then-resolve order at dispatch; neither blocks the other).
