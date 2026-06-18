# ADR-004 — Admin verbs (get / list / rotate) + rotate-invalidates-handles semantics

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** [ADR-001](001-foundational-stack.md) (foundational stack, in-memory store),
[ADR-003](003-ttl-auto-wipe-clock.md) (inject precedence order).

## Context

The v1 contract (`docs/CONTRACT.md` §Verbs) defines four admin verbs — `put | get | list | rotate`
— but only `put` was wired in the IPC dispatch (`src/main.rs::dispatch`). Task 003 wires the other
three, in both the in-process `Vault` API and the IPC dispatch.

Two of the three are read-only and uncontroversial: `get` returns a secret's metadata and `list`
returns the set of stored refs. The contract's load-bearing constraint is that **none of the three
ever returns the secret value** — they are metadata-only, fail-closed on unknown refs.

`rotate` raised one real semantics question that the others did not: **what happens to handles that
were already resolved against the old value when the value is replaced?** A handle is an opaque,
single-use capability minted at `resolve` time and consumed at `inject` time. Between those two
moments an admin could rotate the secret. If a pre-rotation handle still injected, it would deliver
the **new** value to a caller who was authorized against the **old** one — a confused-deputy /
stale-capability hazard on the crown-jewel path.

## Decisions

### 1. get / list / rotate are metadata-only and fail-closed

- `get{secret_ref}` → `{exists:true, injection_floor, binding}` — never the value. Unknown or empty
  `secret_ref` → `{error:{code:"no_such_secret",…}}`, no metadata.
- `list` → `{secrets:[{secret_ref, injection_floor}, …]}` — never any value. An empty store returns
  an empty list, **not** an error. Ordering is unspecified (HashMap iteration).
- `rotate{secret_ref, value}` → replaces the stored value **in place**, preserving `injection_floor`
  and `binding`, and returns `{ok:true, rotated:true, injection_floor, binding}` — the value is
  **never echoed back**. Unknown or empty `secret_ref` → `no_such_secret`, nothing rotated.

The value never appears in any of the three responses, including when the value contains
JSON-special characters (it is simply never placed into the response object).

### 2. rotate invalidates outstanding handles (the safe default)

**Rotating a secret invalidates every handle that was resolved against the prior value.** A
pre-rotation handle, injected after the rotation, is rejected — it can never deliver the
post-rotation value. A handle resolved **after** the rotation injects the new value normally.

This is the conservative, fail-closed choice: a capability is bound to the value generation it was
minted against. The alternative ("a live handle keeps working and silently starts delivering the new
value") was rejected — it would let an old authorization decision leak a freshly-rotated credential.

### 3. Mechanism — a per-secret generation counter

Implemented with a monotonic `generation: u64` on each `Secret` (starts at `0` on `put`, bumped on
each `rotate`) and a `generation` snapshot captured onto each `HandleRec` at `resolve` time. At
`inject`, if the handle's recorded generation does not equal the secret's current generation, the
handle is rejected. This is O(1), needs no handle-table sweep on rotate, and naturally also rejects
a handle whose secret was deleted-and-reput (a future verb) — any generation mismatch fails closed.

### 4. Error code — `handle_invalidated`

A handle rejected for a generation mismatch returns
`{error:{code:"handle_invalidated", message, retryable:false}}`. A distinct code (rather than
reusing `unknown_handle`) is chosen so the caller can distinguish "this handle never existed" from
"this handle was valid but the secret rotated underneath it" — useful for audit-trail and for a
client deciding whether to re-resolve.

### 5. Precedence placement in `inject`

The invalidation check slots into the existing precedence chain (ADR-003) as:

```
unknown_handle → handle_consumed → handle_expired → handle_invalidated → handle_bound_to_other_sandbox → deliver
```

It runs **after** consumed/expired (a handle already used or already timed out reports that prior
fact first) and **before** binding and delivery (an invalidated handle must never reach the delivery
branch, so no credential is ever produced for it).

## Consequences

- `get`/`list`/`rotate` are now reachable over the IPC socket and in-process; the contract's
  "only put is wired" gap is closed.
- A new fail-closed terminal state exists on `inject`: `handle_invalidated`. It joins the existing
  non-delivery error states (`unknown_handle`, `handle_consumed`, `handle_expired`,
  `handle_bound_to_other_sandbox`, `peer_uid_denied`, `no_such_secret`, `bad_request`, `unknown_op`,
  `rng_error`).
- The zero-knowledge invariant is preserved: `resolve` is unchanged and value-free; the value still
  appears only on the `inject` delivery to the injection edge, and never in an admin-verb response.
- The injection floor and single-use/binding semantics are unchanged — rotation only adds an
  invalidation gate, it does not relax any existing check.
