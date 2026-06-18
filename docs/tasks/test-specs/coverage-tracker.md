# Test Coverage Tracker

**Project:** vault

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | SO_PEERCRED peer-uid check on the Unix socket | `001-socket-peercred-check-test-spec.md` | TC-001…TC-005 | ✅ | L6: same-uid `serve` round-trip observed (ping/put/resolve over live socket) + L2 unit tests (`peer_uid_allowed_is_equality_not_privilege`, `unreadable_peer_cred_is_denied`); different-uid rejection unit-proven (no 2nd uid in env) |
| 002 | TTL auto-wipe clock (enforce handle TTL + env wiped_at) | `002-ttl-auto-wipe-test-spec.md` | TC-001…TC-006 | ✅ | L5: `test result: ok. 15 passed; 0 failed` (TC-001..006 via injected clock, no sleep) + L6: live socket `resolve ttl=1` → wait 2s → `inject` → `handle_expired`; spec-verifier APPROVE (per-assertion TC-001..006) |
| 003 | Wire get/list/rotate admin verbs (metadata-only) | `003-admin-verbs-get-list-rotate-test-spec.md` | TC-001…TC-007 | ✅ | L5: `test result: ok. 24 passed; 0 failed` (TC-001..007, incl. value-absence, rotate-invalidates `handle_invalidated`, and TC-006 malformed-JSON→`bad_request`) + L6: live `serve` socket round-trip put→get→list→rotate (no value leaked; unknown ref→no_such_secret; unknown op→unknown_op); spec-verifier APPROVE after malformed-JSON gap closed |
| 004 | Encrypted-at-rest store (AES-256-GCM, key off-ciphertext) | `004-encrypted-at-rest-store-test-spec.md` | TC-001…TC-007 | ✅ | L5: `test result: ok. 38 passed; 0 failed` (TC-001..007 in `src/vault.rs`: ciphertext-not-plaintext, round-trip decrypt at edge, key-provider seam + missing-key fail-closed, unique nonces per put/rotate, tampered/truncated→`decrypt_failed`, at-rest negative, backend-swap; + 7 `src/crypto.rs` AEAD unit tests; 24 prior tests unchanged) + L3: `cargo fmt --check` + `cargo clippy` clean + dep-scan: aes-gcm 0.10.3 tree clears (37 crates pass, exit 0, stable) + L6: `cargo run -- demo` delivers `SK-DEMO-DO-NOT-LEAK` from an AES-256-GCM-encrypted store. spec-verifier APPROVE (all TC-001..007); security-auditor: SHIP — 0 Critical/High/Medium, nonce/key/integrity sound (2 Low hardening follow-ups: zeroize, key-less serve warning) |
| 006 | Cloud secret-manager backend — pluggable, 2–3 adapters (behind the StoreBackend seam) | `006-cloud-secret-manager-backend-test-spec.md` | TC-001…TC-009 (planned) | ❌ | Pending — backlog; **execution blocked on live cloud creds + adapter-set pick** (ADR-007). Core + pluggability (TC-001…TC-007, incl. ≥2-adapter drop-in proof) locally unit-verifiable against mock `SecretManagerClient`s (highest local level: L2); live adapters (TC-008) + per-adapter dep-scan gate (TC-009) credential-/dep-gated (L5/L6 with creds). Not started. |
| 005 | Vault HTTP API read surface (zero-knowledge, read-only, loopback) | `005-vault-http-api-read-surface-test-spec.md` | TC-001…TC-011 | ✅ | L5: `test result: ok. 48 passed; 0 failed` (10 new `src/http.rs` tests TC-002..010, incl. value-absence scans, mutation-unreachable + closed route table, shared-`Arc` read; 38 prior tests unchanged) + L3: `cargo fmt --check` clean + `cargo clippy --all-targets -- -D warnings` clean + dep-scan: `tiny_http` 0.12 tree clears (exit 0, all packages pass) + L6: live `serve --http-addr 127.0.0.1:8205` — `GET /v1/sys/health`→`{"initialized":true,"sealed":false}`, `GET /v1/secret/data/test/api_key`→KV-v2 handle envelope (no `SK-SECRET`), unknown→404, POST/DELETE→405, unroutable→404, over-long body→400, `--http-addr 0.0.0.0`→refused fail-closed (unix socket still serves), no flag→no HTTP listener. spec-verifier APPROVE (all TC-001..011); security-auditor: SHIP within loopback+read-only scope — 0 Critical/High, route table closed, zero-knowledge holds over HTTP (1 Medium follow-up: poison-tolerant mutex lock, shared w/ v0 unix path; not introduced here) |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | **Verified** — validation harness exercised the live runtime path, or operator observed the targeted behaviour |
| 🟡 | **Code merged** — feat-commit landed, unit tests + fitness + CI green, but runtime/live behaviour not yet observed |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

## Verification ladder

A task earns 🟡 at levels 1–4 and ✅ only at level 5 or 6. The `Verified by` column records which level the row reached.

| Level | Evidence | Status this earns |
|-------|----------|-------------------|
| 1 | Code merged | 🟡 |
| 2 | Unit tests pass (paste verbatim final line of `make check`) | 🟡 |
| 3 | `make fitness` passes (verbatim closing line) | 🟡 |
| 4 | CI passes (`gh run watch <id> --exit-status` → success) | 🟡 |
| 5 | **Validation harness** exercises the live runtime path end-to-end — paste the command and the final assertion line | ✅ |
| 6 | **Operator-observed** — operator (or executor via `cargo run` / `npm start` / etc.) saw the targeted behaviour in stdout / logs / UI | ✅ |

If the task targets runtime-observable behaviour (logging, CLI args, TUI, server endpoints, file outputs, side effects), level 5 or 6 is **required** before flipping to ✅. If the task only adds an internal helper covered by unit tests, level 2 may be sufficient — but in that case the row's `Verified by` should explicitly say "unit-test-only; no runtime surface" so future readers don't mistake silence for verification.

## Rule

**The task-executor commits at 🟡 by default.** Only the main session (after spec-verifier APPROVE + the appropriate level-5/6 evidence) updates the row to ✅, in a separate commit titled `verify: confirm task NNN — <level-5/6 evidence>`. This keeps the verification step visible in git history and prevents "merged ≠ done" drift.
