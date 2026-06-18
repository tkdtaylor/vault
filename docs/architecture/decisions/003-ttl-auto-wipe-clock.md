# ADR-003 — Injectable clock + TTL expiry / wiped_at semantics

**Status:** Accepted
**Date:** 2026-06-18
**Supersedes:** the v0 "TTL stored but not enforced" gap recorded in
[ADR-001](001-foundational-stack.md) and the `wiped_at: 0` placeholder.

## Context

`HandleRec.ttl` was stored at `resolve` time but never enforced (`#[allow(dead_code)] ttl`), and
the env-mode `inject` response carried a `wiped_at: 0` placeholder. Task 002 enforces the TTL: a
handle injected after its TTL has elapsed is rejected, and `wiped_at` becomes a real timestamp.

Three design questions had to be settled to do this without violating the existing invariants
(single-use, sandbox-binding, raise-only floor, zero-knowledge resolve):

1. How is "now" obtained so expiry is **testable deterministically** without sleeping?
2. What is the **boundary** of expiry, and what does `ttl=0` mean?
3. When a handle is **both consumed and expired**, which rejection wins?

## Decisions

### 1. Injectable clock seam

A `Clock` trait (`fn now_unix(&self) -> u64`, `Send + Sync`) is introduced.

- `SystemClock` is the production implementation, reading wall-clock seconds from
  `std::time::SystemTime` (`duration_since(UNIX_EPOCH)`, `.as_secs()`, `unwrap_or(0)` on the
  pre-epoch impossibility).
- `Vault` holds a `Box<dyn Clock>`. `Vault::new()` wires `SystemClock` (unchanged call site);
  `Vault::with_clock(Box<dyn Clock>)` is the seam tests use to inject a controllable clock.
- Tests advance an `Arc<AtomicU64>`-backed clock across an expiry boundary in **zero real time** —
  no `thread::sleep`, fully deterministic (REQ-005 / TC-005).

**Rationale:** no new crate (std-only), no global mutable clock, no userspace RNG-style attack
surface. The seam is the minimal abstraction that makes expiry unit-observable. This is the
second concrete use of "make a side-effect injectable for testing" in the codebase, so the
abstraction is justified, not premature.

`resolve` records an **absolute** `expires_at = now_unix() + ttl` (saturating add, so a huge `ttl`
cannot wrap) on the `HandleRec`. Storing the absolute instant — not the raw `ttl` — means `inject`
needs only a single comparison and never re-derives the resolve-time clock.

### 2. Expiry boundary and `ttl=0`

A handle is **expired IFF `now >= expires_at`** — exactly-at-expiry counts as expired (the
conservative, fail-closed choice on the secret path). Consequently `ttl=0` ⇒ `expires_at == now`
at resolve, so the handle is **expired on any subsequent inject** ("expires immediately"). This is
documented behaviour, not an accident, and is asserted in TC-001 / TC-002.

### 3. Precedence — consumed before expired

`inject` evaluates in this fixed order:

```
unknown_handle  →  consumed?  →  expired?  →  binding?  →  deliver
```

- An already-**consumed** handle returns `handle_consumed` **even if it is also expired** — the use
  already happened; single-use is the prior, stronger fact, and reporting expiry would leak that a
  consumed handle's clock had run out (a needless information difference).
- An **expired-but-unconsumed** handle returns `handle_expired` and is left **unconsumed** (no
  state mutation on a fail-closed rejection).

All paths remain fail-closed: every rejection delivers **no credential**. The single-use,
sandbox-binding, raise-only-floor, and zero-knowledge-`resolve` invariants are untouched — TTL is
an *additional* rejection layered before delivery, not a change to any of them.

### 4. `wiped_at` meaning

On an **env-mode** delivery, `wiped_at` is set to the inject-time clock value (`now_unix()`) — the
moment the credential is handed to the env-setter / its scheduled wipe instant — replacing the `0`
placeholder. **Proxy-mode** deliveries carry **no** `wiped_at` field (there is no in-sandbox value
to wipe; the proxy holds it out-of-band), so no spurious field is added.

## Consequences

- TTL is enforced end-to-end and observable over the live socket (`resolve ttl=1` → wait → `inject`
  → `handle_expired`).
- Records are still **not** garbage-collected — an expired handle stays in the table until process
  exit; it is simply un-injectable. A reaper is out of scope for this task.
- The clock is the single seam any future time-dependent behaviour (rotation windows, lease renewal)
  reuses.
