# ADR-006 — Vault HTTP API compatibility (zero-knowledge, read-only, localhost)

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** [ADR-001](001-foundational-stack.md) (foundational stack, the `vault://` backend
seam, RNG via `/dev/urandom`, zero-knowledge `resolve`), [ADR-002](002-socket-peercred-check.md)
(the `SO_PEERCRED` peer-uid gate on the Unix socket — the trust model the HTTP surface deliberately
does **not** share), [ADR-005](005-encrypted-at-rest-store.md) (encrypted-at-rest store — the value
re-materialises only at the `inject` edge).

## Context

Roadmap v1 row 5 asks vault to "expose the `vault://` path semantics over the **Vault HTTP API
shape** so existing Vault clients/backends interoperate through the seam." "Vault" here is the
HashiCorp Vault / OpenBao HTTP API — concretely the KV v2 read path `GET /v1/secret/data/:path`
returning the `{"data":{"data":{…}},…}` envelope, plus a health endpoint
(`GET /v1/sys/health`). The motivation is the adapter seam stated since ADR-001: a request/response
shape that existing Vault tooling already speaks lets vault sit in front of, or behind, that
ecosystem without bespoke clients.

There is a **hard collision** with vault's central invariant. A real Vault KV read returns the
secret **value** in the response body. vault's load-bearing rule (SPEC.md top-level invariants;
CLAUDE.md) is the exact opposite: **the agent core never receives plaintext; `resolve` returns a
handle, never the value.** A drop-in Vault-API server that returns plaintext would not be a
trade-off — it would *delete the product*. So full Vault read-compatibility is **off the table by
construction**. The design question is whether a *useful* compatibility subset exists that maps the
Vault read shape onto `resolve` and returns a **handle inside a Vault-shaped envelope**, never the
value.

A second collision is the **trust model**. The existing IPC is a `0600` Unix socket gated by a
kernel-verified `SO_PEERCRED` peer-uid check (admit iff `peer_uid == server_uid` — ADR-002). An
HTTP/TCP listener has **no kernel peer-credential equivalent**, and vault has **no token/auth model
at all** today (the roadmap's auth/SPIFFE work, row 6, is externally blocked). Adding an
unauthenticated TCP listener that can reach the secret path is a material new attack surface on the
crown-jewel block. Whatever we expose over HTTP must be safe to expose with **no authentication**,
because we have none to offer yet.

A third question is the **dependency**. An HTTP server needs a crate. `tiny_http = "0.12"` is a
sync, thread-per-connection server with a minimal tree (`ascii-canvas`/`chunked_transfer`/
`httpdate`/`log`) — it matches the existing `UnixListener` thread-per-connection model exactly and
pulls **no async runtime**. The async stacks (`hyper`/`axum`) pull `tokio`, a large transitive tree
and a runtime model vault does not otherwise use.

## Decisions

### 1. The HTTP surface is zero-knowledge: a Vault-API read maps to `resolve`, returns a HANDLE

`GET /v1/secret/data/:path` maps the requested path to a `vault://`-scheme `secret_ref`, calls the
existing `Vault::resolve`, and returns the **handle, ttl, and injection_mode** packed into a
Vault-KV-v2-shaped envelope — **never the value**:

```
GET /v1/secret/data/test/api_key
→  200 { "data": { "data": { "handle": "<hex>", "injection_mode": "proxy" },
                   "metadata": { "ttl": 300 } } }
```

The value never appears on this path because `resolve` itself is value-free (SPEC.md invariant 1;
`src/vault.rs::resolve`). The plaintext continues to re-materialise **only** at `inject`, over the
uid-restricted Unix socket (ADR-005 §6). This is the only invariant-preserving compatibility model:
the envelope shape is Vault's; the payload is vault's handle. A Vault client gets a syntactically
familiar response carrying a capability token instead of a secret.

### 2. Read-only: NO inject, NO admin writes, NO value over HTTP

The HTTP surface exposes exactly two endpoints:

| Method + path | Maps to | Returns |
|---|---|---|
| `GET /v1/secret/data/:path` | `Vault::resolve(secret_ref, default_ttl)` | handle + ttl + mode in the KV-v2 envelope — **never the value** |
| `GET /v1/sys/health` | (no secret access) | `200 {"initialized":true,"sealed":false}` — liveness only |

Explicitly **excluded from HTTP**, and why:

- **`inject`** — value delivery. It must stay on the uid-restricted, `SO_PEERCRED`-gated Unix socket
  (the injection edge, ADR-002/ADR-005). Exposing it over unauthenticated TCP would hand the
  plaintext to any local TCP client. **Never over HTTP.**
- **`put` / `rotate`** (`POST /v1/secret/data/:path`, `DELETE`) — admin **mutation**. With no auth
  model, an HTTP writer could seed or overwrite secrets unauthenticated. A `POST`/`PUT`/`DELETE` to
  any path returns **`405 Method Not Allowed`** (fail-closed). Admin mutation stays on the Unix
  socket.
- **The value on any read** — by §1, reads return a handle, never plaintext. There is no HTTP path
  on which a cleartext secret value leaves the process.
- **`get` / `list` metadata over HTTP** — deferred. They are value-free, so they are not *unsafe*,
  but `list` enumerates every secret ref to an unauthenticated caller (a reconnaissance surface).
  Kept off the initial surface under least-exposure; revisit if a concrete consumer needs them.

### 3. Bind localhost-only, fail-closed, and opt-in

The HTTP listener:

- **Binds `127.0.0.1` only** (loopback), never `0.0.0.0`. The bind address is **not operator-
  configurable to a non-loopback interface** in this ADR — a wildcard bind on an unauthenticated
  secret broker is a footgun we refuse to ship. Remote exposure waits on the auth model (row 6).
- Is **opt-in**: `serve` keeps serving the Unix socket unconditionally; the HTTP listener starts
  **only** when `--http-addr 127.0.0.1:PORT` is passed. No HTTP surface exists unless explicitly
  asked for. The default `serve` posture is unchanged from today.
- **Fail-closed on every non-read**: unknown paths → `404` (Vault's not-found shape
  `{"errors":[]}`), non-GET methods → `405`, malformed/over-long requests → `400`, an unknown
  `secret_ref` → Vault's `404 {"errors":[]}` (mapping `resolve`'s `no_such_secret`). No request can
  reach `inject`, `put`, or `rotate` through this listener — those ops are simply not routed.

### 4. Error mapping to the Vault HTTP shape

vault's structured error (`{error:{code,message,retryable}}`) maps to Vault's HTTP status + body so
existing clients see familiar shapes:

| vault condition | HTTP status | Body |
|---|---|---|
| `resolve` success | `200` | KV-v2 envelope with the handle (decision §1) |
| `no_such_secret` | `404` | `{"errors":[]}` (Vault's not-found) |
| unroutable path | `404` | `{"errors":[]}` |
| non-GET method | `405` | `{"errors":["method not allowed"]}` |
| malformed / over-long request | `400` | `{"errors":["bad request"]}` |
| `rng_error` (handle mint failed) | `500` | `{"errors":["internal error"]}` |

A `403` is **not** used in this ADR — there is no auth to fail. (When row 6 lands a token model, a
missing/invalid token maps to Vault's `403 {"errors":["permission denied"]}`.)

### 5. Crate: `tiny_http = "0.12"` (pinned), sync thread-per-connection — async stacks rejected

The HTTP server is `tiny_http`, **pinned to `0.12`**. It is synchronous and thread-per-connection,
mirroring the existing `UnixListener` + `std::thread::spawn(handle_conn)` model in `src/main.rs`
exactly — the HTTP accept loop is structurally the same code shape, sharing the same
`Arc<Mutex<Vault>>`. No async runtime, no `tokio`, no `Future` machinery enters the crate.

**dep-scan note.** The `tiny_http` 0.12 tree (`ascii-canvas`/`chunked_transfer`/`httpdate`/`log`
and their transitive deps) was reported dep-scan-cleared by the requester. As with every crate
adopted on this block (ADR-002 `nix`, ADR-005 `aes-gcm`), `dep-scan check --lockfile Cargo.lock
--lockfile-type crates` and a code-scanner pass over the new tree are **blocking gates** before this
dependency lands — to be re-run and recorded on the implementing task, not asserted here.

## Consequences

### Positive

- **The zero-knowledge invariant holds across an entirely new protocol.** An HTTP reader gets a
  handle in a Vault-shaped envelope; the value never crosses the TCP boundary. The seam claim from
  ADR-001 ("`vault://` + Vault HTTP API path semantics") becomes real without weakening the
  product's one promise.
- **Least attack surface.** The new TCP listener is loopback-only, opt-in, read-only, and cannot
  reach `inject`/`put`/`rotate`. The worst an unauthenticated local TCP client can do is mint a
  single-use handle for a known path — and a handle is useless without the `SO_PEERCRED`-gated
  Unix-socket `inject` and the correct first-use sandbox binding.
- **No async runtime, minimal dependency growth.** `tiny_http` matches the existing concurrency
  model; the dependency floor grows by one small, dep-scan-cleared tree.

### Negative / what gets harder

- **"Vault client interop" is intentionally weak — and this is inherent, not a bug.** A real Vault
  client that does `GET /v1/secret/data/...` expecting its secret receives a **handle**, not the
  value. Tooling that blindly treats `data.data` as the credential will not work. Interop means
  "speaks the Vault request/response *shape*," not "is a drop-in Vault that hands out secrets." This
  is the direct, documented cost of zero-knowledge and must be stated plainly to any integrator.
- **A second listener to reason about.** `serve` can now bind two surfaces with two different trust
  models (Unix socket: `SO_PEERCRED`-gated, full verbs; HTTP: unauthenticated, loopback, read-only).
  The asymmetry is deliberate but is a new thing reviewers must hold in mind. The fitness functions
  and spec must make the asymmetry explicit so it cannot drift.
- **No remote use until auth lands.** Loopback-only means the HTTP surface is useful only to
  same-host consumers. Cross-host Vault interop is blocked on the auth/token model (roadmap row 6,
  externally blocked) — this ADR does not unblock it and deliberately refuses to ship a wildcard
  bind as a shortcut.
- **Dependency / supply-chain surface grows.** One more crate tree to keep dep-scanned. dep-scan /
  code-scanner remain blocking gates for any future bump (consistent with ADR-005).

## Alternatives considered

- **Full Vault read-compatibility (return the value in `data.data`)** — **rejected: it violates the
  core invariant.** This is the blocker the roadmap flagged: a Vault read returns the value, vault's
  `resolve` must not. Returning the value would make vault a plaintext secret server — the exact
  thing it exists to prevent. Not a trade-off; a non-starter.
- **HTTP `inject` (deliver the value over TCP at the edge)** — rejected: moves plaintext off the
  `SO_PEERCRED`-gated Unix socket onto an unauthenticated TCP listener. The injection edge stays on
  the uid-restricted socket (ADR-002/005).
- **HTTP admin writes (`POST`/`DELETE` → `put`/`rotate`)** — rejected: unauthenticated mutation of
  the secret store. Returns `405`. Admin stays on the Unix socket until an auth model exists.
- **Bind `0.0.0.0` / operator-configurable interface** — rejected: a wildcard bind on an
  unauthenticated secret broker invites remote reconnaissance and handle-minting. Loopback-only,
  non-overridable, until row 6's auth model.
- **`hyper` / `axum`** — rejected: both pull `tokio` (a large async runtime + transitive tree) and
  an async model vault does not otherwise use. `tiny_http`'s sync thread-per-connection matches the
  existing `UnixListener` model with a far smaller tree.
- **Hand-rolled HTTP/1.1 parser (no new crate)** — rejected: parsing HTTP correctly and safely
  (chunked transfer, header limits, request smuggling) is exactly the kind of footgun a small,
  audited, dep-scan-cleared crate removes. On a crown-jewel block, a vetted parser beats bespoke
  parsing.
- **Defer row 5 until the auth model (row 6) lands** — considered. Rejected as the *default* because
  a zero-knowledge, read-only, loopback surface is safe to ship *without* auth (it exposes no value
  and no mutation). Auth is a prerequisite for *remote* and for *write* compatibility, not for this
  read-only loopback subset. (See the verdict below — this remains the honest fallback if review
  judges even handle-minting over unauthenticated loopback unacceptable.)
```
