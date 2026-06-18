# ADR-002 — SO_PEERCRED peer-uid check on the IPC socket

**Status:** Accepted
**Date:** 2026-06-18
**Supersedes (in part):** the F-006 "known gap" note in ADR-001 §6 — the peer-uid check is now wired.

## Context

The vault→proxy handoff (D5) is secured by three properties together: a **uid-restricted Unix
socket**, an **unguessable single-use capability handle**, and **first-use sandbox binding**
(ADR-001 §6). The uid restriction was, until this ADR, enforced only by the socket file mode
(`0600`) — an *inference*: "the kernel won't let another uid open this path." That inference is
weaker than it looks. File permissions gate `open`/`connect` by the filesystem ACL, but they do not
let the server **assert who the connected peer actually is**: a passed file descriptor, a permission
race on socket setup, or a misconfigured parent directory can all decouple "the file is 0600" from
"the connected peer shares my uid." For a block whose entire job is holding secrets, the credential
handoff must be gated on a fact the **kernel** vouches for, not on a filesystem inference.

ADR-001 §6 recorded this as a known gap and fitness rule F-006 tracked it. This ADR closes it.

## Decision

### 1. Kernel-verified peer-uid gate on every accepted connection

On each accepted connection, before any op is dispatched, vault reads the connecting peer's
credential from the kernel via **`SO_PEERCRED`** (`getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`,
exposed by `nix` as `getsockopt(&stream, PeerCredentials)`), extracts the peer **uid**, and admits
the connection **only if** it equals vault's own effective uid (`geteuid`). A denied connection
receives the structured error `{"error":{"code":"peer_uid_denied",...}}` and is closed —
**no `resolve` / `inject` / `put` runs** for it. (`src/main.rs::handle_conn`.)

This is the **kernel-verified** half of the D5 uid restriction; `0600` remains as defense in depth
(it stops the connect before it reaches accept), but the peer-uid assertion is now the authoritative
check.

### 2. Equality, not privilege

The admission rule is **`peer_uid == server_uid`** — strict equality, not a privilege comparison.
Root (uid 0) connecting to a non-root vault is **denied** unless 0 is vault's own uid. vault does
not grant "more privileged ⇒ allowed"; the credential handoff is for the *same* principal that runs
vault (the agent stack's service uid), and nobody else — not even root. This is the deliberate
choice: a privilege-based rule would let any local root process drain the broker, which is precisely
the local-compromise path D5 exists to narrow.

### 3. Pure decision function + fail-closed read (the split)

The check is split into two pieces so the security-relevant logic is unit-testable without a live
socket or a second uid:

- **`peer_uid_allowed(peer_uid: u32, server_uid: u32) -> bool`** — a pure, total function of the two
  uids (`peer_uid == server_uid`). No I/O. This is the unit-testable core (TC-005): `(1000,1000) →
  allow`, `(1000,1001) → deny`, `(0,1000) → deny`.
- **`read_peer_uid(&UnixStream) -> Option<u32>`** — the I/O half. It returns `None` on **any**
  `getsockopt` failure, and the caller treats `None` as a **denial** (fail-closed, TC-004). vault
  never admits a connection because "we couldn't read the credential" — an unreadable peer
  credential is exactly the case where admitting would be a leak.

The split means REQ-002/004/005 are provable at the unit level without spawning a second-uid process
(which requires root/sudo and is often unavailable in CI). The same-uid acceptance path is verified
end-to-end over a live socket (TC-003).

### 4. Dependency — `nix = "0.31"`, minimal features

Reading `SO_PEERCRED` portably from safe Rust needs `getsockopt` + the `PeerCredentials` sockopt and
`geteuid`. The standard library does not expose either. The options were: (a) a raw `libc` +
`unsafe` call, or (b) the `nix` crate's safe wrappers.

We chose **`nix`**, with `default-features = false, features = ["socket", "user"]` — the smallest
feature set that compiles (`socket` for `getsockopt`/`PeerCredentials`, `user` for `geteuid`). This
keeps the secret-handling path in **safe Rust** (no `unsafe` block on the gate — preserving the
ADR-001 §2 / F-005 commitment), at the cost of a transitive tree (`nix`, `libc`, `bitflags`,
`cfg-if`, `cfg_aliases`, `memoffset`, `autocfg`, `zmij`).

- **Pin:** `nix = "0.31"`, resolved to **0.31.3**.
- **Supply-chain clearance:** `dep-scan check --lockfile Cargo.lock --lockfile-type crates` returns
  **pass** for every crate in the resolved tree (18 crates, 0 BLOCK) — recorded as the blocking gate
  for this dependency add per CLAUDE.md → Recommended tooling.

`nix` is the second non-`serde` dependency. The minimal-dependency property of ADR-001 §2 is
deliberately relaxed here for a load-bearing kernel primitive that has no safe-std equivalent; the
alternative (`unsafe` libc on the crown-jewel path) is the worse trade.

## Alternatives considered

- **`0600` permissions only (status quo).** Rejected: an inference, not an assertion. It cannot
  defend against fd-passing or a setup race, and it gives the server no kernel-vouched peer identity.
- **Raw `libc` + `unsafe`.** Rejected: puts an `unsafe` block on the secret path, the exact class
  ADR-001 §2 / F-005 commit to keeping out. `nix`'s safe wrapper is worth the dependency.
- **Privilege-based admission (allow root).** Rejected: equality is the tighter rule; admitting root
  widens the local-compromise surface D5 narrows.
- **`pull nix default features`.** Rejected: unnecessary attack surface; `socket` + `user` is all the
  gate needs.

## Consequences

- The D5 uid restriction is now **kernel-verified**, not file-mode-inferred. Fitness rule F-006
  graduates from "partially enforced — gap" to enforced on the peer-uid dimension.
- vault gains a transitive dependency tree (`nix` → `libc` etc.). dep-scan / code-scanner are now
  live gates on any version bump of this tree (already true once a crypto crate lands; this brings
  the date forward).
- A genuine different-uid **rejection** is not exercised end-to-end in environments without a second
  uid (root/sudo); it is proven at the unit level (TC-004/005). The same-uid **acceptance** is
  verified over a live socket (TC-003). This split is the spec's accepted verification posture.
- The gate runs on **every** accept, before dispatch — denied peers never reach `resolve`/`inject`/
  `put`. This is the fail-closed posture of ADR-001 §8 extended to the connection-admission layer.
