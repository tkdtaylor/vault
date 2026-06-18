# Task 005: Vault HTTP API read surface (zero-knowledge, read-only, loopback)

**Project:** vault
**Created:** 2026-06-18
**Status:** ready

## Goal

Expose vault's `vault://` read path over the **Vault (HashiCorp / OpenBao) HTTP API shape** so
existing Vault clients/backends interoperate through the seam — **without ever weakening the
zero-knowledge invariant**. Add an **opt-in, loopback-only, read-only** HTTP listener that serves
exactly two endpoints: a health endpoint and a KV-v2 read that maps `GET /v1/secret/data/:path` onto
`Vault::resolve` and returns the **handle** (plus ttl + injection_mode) packed into a Vault-shaped
envelope — **never the secret value**. This is roadmap v1 Row 5, bounded precisely by ADR-006: a
"safe HTTP read surface" as one cohesive responsibility (health + read→resolve + fail-closed
hardening), nothing beyond it.

## Context

- **Binding design:** [ADR-006](../../architecture/decisions/006-vault-http-api-compat.md)
  (Accepted, 2026-06-18) — the HTTP surface is zero-knowledge (read → `resolve` → handle in a
  Vault-shaped envelope, never the value), read-only (no `inject`/`put`/`rotate`/`get`/`list` over
  HTTP), loopback-only + opt-in, fail-closed, and uses `tiny_http = "0.12"` (sync,
  thread-per-connection — async stacks rejected). **This task IMPLEMENTS exactly what ADR-006
  specifies and nothing beyond it; it does NOT write a new ADR.**
- **Roadmap:** [v1 Row 5](../../plans/roadmap.md) — "Vault HTTP API compatibility … so existing
  Vault clients/backends interoperate through the seam." Sequenced after tasks 001–004 (all done on
  the `autopilot/vault-v1` integration branch).
- **Parallels existing code:** `src/main.rs::serve` / `handle_conn` is the `UnixListener`
  thread-per-connection accept loop the HTTP listener mirrors exactly, sharing the **same**
  `Arc<Mutex<Vault>>`. `src/main.rs::handle_line` (task 003) and `peer_uid_allowed` (task 001) are
  the precedent for **pure, unit-testable** helpers — this task factors its core logic the same way.
- **Maps onto:** `src/vault.rs::resolve(secret_ref, ttl) -> {handle, ttl, injection_mode}` — the
  value-free call the HTTP read targets; `no_such_secret` is the error it maps to a `404`.
- **Spec to update in the same commit (behaviour/interface/config change):**
  [`docs/spec/interfaces.md`](../../spec/interfaces.md) (new HTTP read surface — the second listener,
  its two endpoints, the KV-v2 envelope, the error→status mapping),
  [`docs/spec/configuration.md`](../../spec/configuration.md) (the new `--http-addr` flag, opt-in,
  loopback-only), [`docs/spec/SPEC.md`](../../spec/SPEC.md) (the two-listener asymmetry: Unix socket
  = `SO_PEERCRED`-gated full verbs; HTTP = unauthenticated loopback read-only), and
  [`docs/architecture/diagrams.md`](../../architecture/diagrams.md) (the new HTTP listener boundary
  beside the Unix socket).
- **Dependencies:** none beyond the `autopilot/vault-v1` integration branch (tasks 001–004 done).
  The `tiny_http` 0.12 tree was reported dep-scan-cleared by the requester; re-running dep-scan is a
  blocking gate on this task (below), not a precondition.

## Invariants this task MUST preserve (load-bearing)

- **Zero-knowledge:** the HTTP read returns a **handle**, never the value. `resolve` is value-free
  (`src/vault.rs::resolve`) and stays so — the envelope carries the handle/ttl/injection_mode only.
- **Value delivery stays at the `inject` edge** on the `SO_PEERCRED`-gated Unix socket — **never**
  over HTTP. `inject` is not routed on the HTTP listener.
- **Raise-only floor, single-use + first-use binding, TTL enforcement, peer-uid gate** — all
  untouched; the HTTP surface adds a read path only and changes none of them.
- **Fail-closed** on every non-read: non-GET → 405, unroutable → 404, malformed/over-long → 400,
  unknown secret → 404 `{"errors":[]}`. No request reaches `inject`/`put`/`rotate`/`get`/`list`.
- **Loopback-only, opt-in:** binds `127.0.0.1` only (a non-loopback bind is refused fail-closed);
  the listener starts only when `--http-addr` is passed; default `serve` posture unchanged.
- **Memory-safe Rust; never log a secret.** The existing **38 tests must still pass**.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `serve` gains an opt-in `--http-addr ADDR` flag. Absent → **no** HTTP listener starts and the Unix socket serves unchanged. Present → a thread-per-connection HTTP listener starts, sharing the **same** `Arc<Mutex<Vault>>` as the Unix socket (which still serves unconditionally). | must have |
| REQ-002 | The HTTP listener binds **`127.0.0.1` (loopback) only**. A non-loopback bind address (`0.0.0.0`, a LAN IP, `::`, or unparseable) is **refused fail-closed** — the listener does not start on a non-loopback interface. Bind validation is a pure, unit-testable function. | must have |
| REQ-003 | `GET /v1/sys/health` → `200` with body `{"initialized":true,"sealed":false}` (liveness only; no secret-store access). | must have |
| REQ-004 | `GET /v1/secret/data/:path` maps the KV path tail to a `vault://:path` secret_ref, calls `Vault::resolve`, and returns the **handle + ttl + injection_mode** in the Vault KV-v2 envelope `{"data":{"data":{…},"metadata":{…}}}` — **never the value**. The path→ref mapping and the envelope builder are pure, unit-testable functions. | must have |
| REQ-005 | A `resolve` `no_such_secret` → HTTP `404` body `{"errors":[]}` (Vault's not-found shape). | must have |
| REQ-006 | **Fail-closed routing:** any non-GET method → `405` `{"errors":["method not allowed"]}`; any unroutable path → `404` `{"errors":[]}`. `inject`, `put`, `rotate`, `get`, `list` are **unreachable over HTTP** — no route maps to them (assert it). The route/method decision is a pure, unit-testable function. | must have |
| REQ-007 | Malformed / over-long requests → `400` `{"errors":["bad request"]}`; a request-size bound is enforced (named constant). The secret **value** appears in **no** HTTP response, success or error (negative body scan). | must have |
| REQ-008 | Add `tiny_http = "0.12"` **pinned** as the only new runtime dependency (no async runtime, no second crate). After `cargo build`, `dep-scan check --lockfile Cargo.lock --lockfile-type crates` is a **blocking gate** and must pass. | must have |

## Readiness gate

- [x] Test spec `005-vault-http-api-read-surface-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID and TC
- [x] Binding ADR (ADR-006) is Accepted — no new ADR to write
- [x] No blocking tasks (001–004 done on `autopilot/vault-v1`); `tiny_http` 0.12 reported dep-scan-cleared

## Acceptance criteria

- [ ] [REQ-001] No `--http-addr` → no HTTP listener; Unix socket unchanged. With `--http-addr` → a
  loopback listener accepts connections, sharing the same `Arc<Mutex<Vault>>` (TC-001).
- [ ] [REQ-002] `loopback_only` is true only for literal `127.0.0.1`; a non-loopback `--http-addr`
  is refused fail-closed (no wildcard bind ever) (TC-002).
- [ ] [REQ-003] `GET /v1/sys/health` → `200 {"initialized":true,"sealed":false}`, no store access (TC-003).
- [ ] [REQ-004] `GET /v1/secret/data/test/api_key` on a seeded secret → `200` KV-v2 envelope carrying
  the handle/ttl/injection_mode; `SK-SECRET` is **absent** from the body (negative scan) (TC-004).
  Path→`vault://` mapping is correct, including a nested tail (TC-005).
- [ ] [REQ-005] Unknown secret → `404 {"errors":[]}` (TC-006).
- [ ] [REQ-006] Non-GET (POST/PUT/DELETE) → `405`; unroutable GET → `404`; `inject`/`put`/`rotate`/
  `get`/`list` are not routed over HTTP (TC-007, TC-008).
- [ ] [REQ-007] Malformed/over-long request → `400` with the size bound enforced (TC-009); the secret
  value appears in no HTTP response across read + error paths (negative scan) (TC-010).
- [ ] [REQ-008] `tiny_http = "0.12"` pinned, only new crate; `dep-scan check --lockfile Cargo.lock
  --lockfile-type crates` passes (blocking gate) (TC-011).
- [ ] `cargo build && cargo test` green; the existing **38 tests** unchanged and passing.

## Verification plan

- **Highest level achievable:** **L6** — the routing/mapping/envelope/bind decisions are pure and
  unit-observable (L5), and a live loopback listener answering real `GET`s is operator-observable (L6).
- **Level 5 — Validation harness command:**
  ```
  cargo build && cargo test && dep-scan check --lockfile Cargo.lock --lockfile-type crates
  ```
  Expected: `test result: ok` (incl. TC-001..011 — the pure `loopback_only`, `http_secret_ref`,
  `kv2_envelope`, `http_route`, `http_response_for` decisions, value-absence scans, and the
  unreachable-mutation assertions) **and** `dep-scan` exits 0 over the `tiny_http` 0.12 tree.
- **Level 6 — Operator observation:** start `cargo run -- serve --socket /tmp/v.sock --http-addr
  127.0.0.1:8200`; over the Unix socket `put` `vault://test/api_key = SK-SECRET`; then:
  - `curl -s 127.0.0.1:8200/v1/sys/health` → `200 {"initialized":true,"sealed":false}`;
  - `curl -s 127.0.0.1:8200/v1/secret/data/test/api_key` → `200` KV-v2 envelope showing a `handle`
    and **no** `SK-SECRET` in the body;
  - `curl -s 127.0.0.1:8200/v1/secret/data/nope` → `404 {"errors":[]}`;
  - `curl -sX POST 127.0.0.1:8200/v1/secret/data/test/api_key` → `405`;
  - a `serve … --http-addr 0.0.0.0:8200` invocation **refuses** to start the HTTP listener.
