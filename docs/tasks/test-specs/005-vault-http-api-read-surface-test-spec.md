# Test Spec 005: Vault HTTP API read surface (zero-knowledge, read-only, loopback)

**Linked task:** [`docs/tasks/backlog/005-vault-http-api-read-surface.md`](../backlog/005-vault-http-api-read-surface.md)
**Written:** 2026-06-18
**Binding design:** [ADR-006](../../architecture/decisions/006-vault-http-api-compat.md)

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002 | ✅ |
| REQ-003 | TC-003 | ✅ |
| REQ-004 | TC-004, TC-005 | ✅ |
| REQ-005 | TC-006 | ✅ |
| REQ-006 | TC-007, TC-008 | ✅ |
| REQ-007 | TC-009, TC-010 | ✅ |
| REQ-008 | TC-011 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

## Testability note

Per ADR-006 decision §5 and the precedent set by task 001 (`peer_uid_allowed` as a pure decision
function) and task 003 (`handle_line` as a pure parse→dispatch helper), the core logic of this
surface is factored into **pure, unit-testable functions** that need no live TCP:

- `http_secret_ref(path: &str) -> Option<String>` — maps a `/v1/secret/data/:path` URL path to a
  `vault://:path` secret_ref (or `None` for an unroutable path).
- `kv2_envelope(resolved: &Value) -> Value` — packs a value-free `resolve` response (handle / ttl /
  injection_mode) into the Vault KV-v2 `{"data":{"data":{…},"metadata":{…}}}` shape.
- `http_route(method: &str, path: &str) -> Route` — the method/route decision returning one of
  `Health`, `Read(secret_ref)`, `MethodNotAllowed`, or `NotFound`.
- `loopback_only(addr: &str) -> bool` — bind-address validation: true IFF the host is `127.0.0.1`
  loopback.
- `http_response_for(route, &Arc<Mutex<Vault>>) -> (u16, Value)` — maps a route + vault state to the
  `(status, body)` pair (the same mapping the live handler emits), so status/body/value-absence are
  asserted without binding a socket.

A live-loopback smoke (`--http-addr 127.0.0.1:PORT` then a `GET /v1/sys/health` and a
`GET /v1/secret/data/...`) is the **L6** evidence; the TCs below are the **L5** unit coverage.

---

## Test cases

### TC-001: --http-addr opt-in — no flag means no HTTP listener; flag means a loopback listener

- **Requirement:** REQ-001
- **Input:** (a) `serve --socket S` with **no** `--http-addr`; (b) `serve --socket S --http-addr
  127.0.0.1:0`.
- **Expected output:** (a) the Unix socket is served and **no** TCP listener is bound (a connect to
  any HTTP port fails / no port is opened); the default `serve` posture is byte-for-byte unchanged.
  (b) a TCP listener is bound on a loopback address and accepts a connection, while the Unix socket
  continues to serve unconditionally.
- **Edge cases:** the absence of the flag must not change any existing Unix-socket behaviour (the
  38 prior tests still pass); the HTTP listener shares the **same** `Arc<Mutex<Vault>>` as the Unix
  socket (a secret `put` over the Unix socket is readable as a handle over HTTP in the same process).

### TC-002: loopback-only bind — a non-loopback address is refused fail-closed

- **Requirement:** REQ-002
- **Input:** `loopback_only("127.0.0.1:8200")`, `loopback_only("127.0.0.1:0")`,
  `loopback_only("0.0.0.0:8200")`, `loopback_only("::")`, `loopback_only("192.168.1.10:8200")`,
  `loopback_only("0.0.0.0")`.
- **Expected output:** `true` for the two `127.0.0.1` cases; `false` for `0.0.0.0`, `::`, the LAN
  address, and the bare wildcard. A `serve --http-addr 0.0.0.0:8200` invocation refuses to start the
  HTTP listener (exits non-zero or logs a fail-closed refusal) — **no** wildcard bind ever happens.
- **Edge cases:** `localhost` hostname forms and IPv6 loopback are out of scope for this ADR
  (literal `127.0.0.1` only); anything not literal-`127.0.0.1` is refused. Fail-closed: an
  unparseable address is also refused, never bound.

### TC-003: GET /v1/sys/health → 200 with the liveness JSON, no secret access

- **Requirement:** REQ-003
- **Input:** `http_route("GET", "/v1/sys/health")` then `http_response_for(...)` (and the live
  smoke: `GET /v1/sys/health`).
- **Expected output:** status `200`; body exactly `{"initialized":true,"sealed":false}`. No secret
  store access occurs on this path (liveness only).
- **Edge cases:** health responds `200` even when the store is empty (it asserts liveness, not
  contents).

### TC-004: GET /v1/secret/data/test/api_key on a seeded secret → 200 KV-v2 envelope carrying the HANDLE; value ABSENT

- **Requirement:** REQ-004
- **Input:** seed `put("vault://test/api_key", "SK-SECRET", proxy, binding)` on the shared vault;
  `http_route("GET", "/v1/secret/data/test/api_key")` → `Read("vault://test/api_key")`; then
  `http_response_for(...)`.
- **Expected output:** status `200`; body is the Vault KV-v2 envelope
  `{"data":{"data":{…},"metadata":{…}}}` where `data.data` carries the **handle** and
  `injection_mode`, and `data.metadata` (or `data.data`) carries the `ttl` — sourced from
  `Vault::resolve`. **`resolve` is value-free, so the envelope carries no value.**
- **Edge cases (negative assertion — load-bearing):** the substring `SK-SECRET` does **not** appear
  anywhere in the serialized response body (scan the whole body string). A `handle` field is present
  and is the hex capability token, never the plaintext.

### TC-005: path → vault:// mapping correctness (incl. a nested path tail)

- **Requirement:** REQ-004
- **Input:** `http_secret_ref("/v1/secret/data/test/api_key")`,
  `http_secret_ref("/v1/secret/data/team/prod/db/password")`,
  `http_secret_ref("/v1/secret/data/single")`.
- **Expected output:** `"vault://test/api_key"`, `"vault://team/prod/db/password"`,
  `"vault://single"` respectively — the KV path tail after `/v1/secret/data/` becomes the
  `vault://`-scheme ref verbatim (nested segments preserved).
- **Edge cases:** an empty tail (`/v1/secret/data/` or `/v1/secret/data`) → `None` (unroutable, maps
  to a 404 by TC-008, not a `vault://` with an empty path).

### TC-006: unknown secret → 404 {"errors":[]}

- **Requirement:** REQ-005
- **Input:** `GET /v1/secret/data/nope/missing` against a vault with no such secret →
  `Read("vault://nope/missing")`; `Vault::resolve` returns `no_such_secret`.
- **Expected output:** status `404`; body exactly `{"errors":[]}` (Vault's not-found shape). No value,
  no handle minted for a missing secret.
- **Edge cases:** the `no_such_secret` structured error is mapped to the Vault HTTP shape, not echoed
  verbatim.

### TC-007: non-GET method (POST / PUT / DELETE) to any path → 405; mutation ops unreachable

- **Requirement:** REQ-006
- **Input:** `http_route("POST", "/v1/secret/data/test/api_key")`,
  `http_route("PUT", "/v1/secret/data/test/api_key")`,
  `http_route("DELETE", "/v1/secret/data/test/api_key")`,
  `http_route("POST", "/v1/sys/health")`.
- **Expected output:** each → `MethodNotAllowed`; `http_response_for` → status `405`, body
  `{"errors":["method not allowed"]}`. A non-GET request **never** reaches `put` or `rotate` — there
  is no route from any method+path to a mutation verb.
- **Edge cases:** even a POST to a path that *would* be a valid GET read still returns `405` (method
  is decided before the path's read semantics matter).

### TC-008: unroutable GET path → 404; inject / get / list unreachable over HTTP

- **Requirement:** REQ-006
- **Input:** `http_route("GET", "/v1/auth/login")`, `http_route("GET", "/v1/secret/metadata/x")`,
  `http_route("GET", "/")`, `http_route("GET", "/v1/sys/inject")`,
  `http_route("GET", "/v1/secret/data/")` (empty tail).
- **Expected output:** each → `NotFound`; `http_response_for` → status `404`, body `{"errors":[]}`.
  **No** route maps to `inject`, `get`, `list`, or `rotate` — only `/v1/sys/health` and
  `/v1/secret/data/:path` (non-empty tail) are routable, and the latter only to value-free `resolve`.
- **Edge cases:** the route table is closed — anything not explicitly `Health` or `Read` is
  `NotFound` (or `MethodNotAllowed` for non-GET), never a fall-through to an admin verb.

### TC-009: malformed / over-long request → 400; request-size bound enforced

- **Requirement:** REQ-007
- **Input:** (a) a request whose URL path / line is malformed beyond parse; (b) a request whose size
  (request line + headers + any body) exceeds the configured bound.
- **Expected output:** status `400`; body `{"errors":["bad request"]}`. The over-long request is
  rejected at/under the bound — the process does not buffer unbounded input. Fail-closed: a request
  that cannot be safely parsed yields `400`, never a panic and never a secret.
- **Edge cases:** the size bound is a named constant; a request exactly at the bound is handled, one
  byte over is `400`. (A pure test asserts the bound-check decision; the live smoke confirms a real
  over-long request is refused.)

### TC-010: value-absence negative scan across read + error paths

- **Requirement:** REQ-007, REQ-006
- **Input:** seed `put("vault://test/api_key", "SK-SECRET", …)`; collect the response bodies for
  the health route, the successful read route, the unknown-secret route, the 405 route, and the 404
  route.
- **Expected output:** the plaintext `SK-SECRET` appears in **none** of the bodies. The only
  secret-derived datum that ever crosses the HTTP boundary is the opaque handle (on the success read).
- **Edge cases:** confirms there is no HTTP path — success or error — on which a cleartext value
  leaves the process.

### TC-011: tiny_http dependency is pinned and dep-scan clears the tree

- **Requirement:** REQ-008
- **Input:** `Cargo.toml` declares `tiny_http = "0.12"` (pinned to 0.12, no other new crate); after
  `cargo build`, run `dep-scan check --lockfile Cargo.lock --lockfile-type crates`.
- **Expected output:** the only new runtime dependency tree is `tiny_http` 0.12 and its transitive
  deps (`ascii`/`chunked_transfer`/`httpdate`/`log`); `dep-scan` exits 0 (tree clears). This gate is
  **blocking** — the task is not done until it passes (recorded in the task's Verification plan).
- **Edge cases:** no async runtime (`tokio`) and no second new crate enters the lockfile.
