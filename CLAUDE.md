# vault

JIT zero-knowledge secret store + credential broker for autonomous agents. Answers one question
— *does the agent core ever see a credential in plaintext?* — and the answer is **no**. The agent
holds only an opaque, single-use **handle**; the plaintext is injected **at the host boundary,
into `exec-sandbox`, at the moment of execution**, then wiped. vault sits beside `policy-engine`
(it honors the raise-only injection floor policy-engine emits), `exec-sandbox` (the injection
edge), and `audit-trail` in the secure-agent ecosystem.

## Invariants

These are load-bearing — violating one breaks the security model, not just style:

- **The agent core never receives plaintext.** `resolve` returns a handle, a TTL, and the
  injection mode — **never the value**. Plaintext lives only in vault's own memory and at the
  injection edge (`inject` → exec-sandbox's egress proxy or env-setter). *(Enforced in
  `src/vault.rs::resolve`.)*
- **Raise-only injection floor.** `inject`'s effective mode is `max(secret_floor, requested)` —
  vault may **raise** the floor (env→proxy), **never lower** it (fail-closed). *(Enforced in
  `src/vault.rs::inject`; test `floor_cannot_be_lowered`.)*
- **Single-use handles + first-use sandbox binding.** A handle is consumed on first `inject` and
  bound to that sandbox; a replay → `handle_consumed`, a different sandbox →
  `handle_bound_to_other_sandbox`. *(Enforced in `src/vault.rs::inject`; test `replay_is_rejected`.)*
- **Fail-closed.** An unknown handle, unknown secret, or unsupported op returns the structured
  error shape; nothing is delivered. *(Enforced in the `err()` paths of `src/vault.rs` / `src/main.rs`.)*
- **Memory-safe language for the secret path.** vault is Rust — the crown-jewel secret-handling
  path is memory-safe by construction (no buffer overruns leaking adjacent memory). *(Enforced by
  the language.)*
- **Plaintext crosses only the uid-restricted socket.** The vault→proxy handoff (D5) travels a
  `0600` Unix socket **plus** a kernel-level `SO_PEERCRED` peer-uid assertion: each accepted
  connection's uid must equal the server's effective uid or it is rejected fail-closed
  (`peer_uid_denied`) before any op dispatches. *(Enforced in `src/main.rs::handle_conn`; task 001.)*

## Contract (v1 — don't break without a contracts bump)

```
resolve(secret_ref, requester_identity) -> { handle, ttl, injection_mode }       # NOT the value
inject(handle, sandbox_identity, mode)  -> proxy: { ok, delivery, credential, binding{host,header,scheme} }
                                           env:   { ok, delivery, credential, var_name, wiped_at }
put | get | list | rotate (admin)        # all four wired in the IPC dispatch (get/list/rotate are metadata-only)
```

- **Fail-closed:** effective mode = `max(secret_floor, requested)`. vault may RAISE the injection
  floor (env→proxy), **never lower** it.
- **Single-use + first-use binding:** a handle is consumed on first inject and bound to that
  sandbox; replays / other sandboxes are rejected (D5).
- The `credential` + `binding` on the `inject` response is the v0→v1 change the tracer-bullet
  surfaced (A7): exec-sandbox's proxy needs them to actually inject. They cross only the
  uid-restricted vault socket — the injection edge.

All four admin verbs (`put`/`get`/`list`/`rotate`) are wired in the IPC dispatch
(`src/main.rs::dispatch`). `get`/`list`/`rotate` are **metadata-only** — they never echo the
secret value — and `rotate` invalidates outstanding handles for the rotated ref via a
per-secret generation counter (`handle_invalidated`). See ADR-004.

An **opt-in, loopback-only, read-only Vault HTTP API surface** (`src/http.rs`, `--http-addr
127.0.0.1:PORT`) exposes `GET /v1/sys/health` and `GET /v1/secret/data/:path` → `resolve` → a
**handle** in the Vault KV-v2 envelope — **never the value**. Value delivery and every mutation
(`inject`/`put`/`get`/`list`/`rotate`) stay on the `SO_PEERCRED` Unix socket, unreachable over
HTTP. See ADR-006.

The store is **in-memory and encrypted at rest** (ciphertext in RAM); an **opt-in persistent
on-disk store** (`src/store_file.rs`, `--store-path` / `VAULT_STORE_PATH`) lets secrets survive a
restart as an atomic `0600` JSON of **ciphertext + metadata only** — the master key is **never
written to disk** and **handles never persist** (a restart invalidates every outstanding handle).
Key/plaintext buffers vault controls are best-effort **zeroized** on drop (`src/zeroize.rs`,
hand-rolled — the `zeroize` crate is dep-scan-blocked on a maintainer changeover; the cipher's
internal key copy is a documented residual). See ADR-008 / ADR-009.

The full as-built record is [ADR-001](docs/architecture/decisions/001-foundational-stack.md); the
v1 increment is recorded in ADR-002 (peer-uid), ADR-003 (TTL clock), ADR-004 (admin verbs),
ADR-005 (encrypted-at-rest store), ADR-006 (Vault HTTP API read surface), ADR-007 (cloud
secret-manager backend — planned), ADR-008 (persistent encrypted disk store), and ADR-009
(secure-memory zeroization).

## Project structure

```
src/
  main.rs    ← entrypoint: serve / demo dispatch; IPC server (ping/put/get/list/rotate/resolve/inject) + SO_PEERCRED gate; opt-in --http-addr
  vault.rs   ← Vault core: store + resolve/inject broker, admin verbs, injectable Clock, StoreBackend/KeyProvider seams, inline tests
  crypto.rs  ← AES-256-GCM StoreBackend + KeyProvider seam (encrypt-on-put / decrypt-at-inject), /dev/urandom nonces
  store_file.rs ← opt-in persistent encrypted store: atomic 0600 JSON of ciphertext+metadata (key off disk, handles never persist)
  zeroize.rs ← hand-rolled best-effort memory wipe (write_volatile + compiler_fence) for key/plaintext buffers — no zeroize crate
  http.rs    ← loopback-only, read-only Vault HTTP API read surface (resolve → handle envelope; never the value)
  handle.rs  ← capability-handle generation (32 random bytes from /dev/urandom, hex-encoded)
Cargo.toml   ← crate manifest (serde + serde_json + nix + aes-gcm + tiny_http)
docs/        ← spec + planning + history (the source-of-truth side)
  spec/           authoritative current-state snapshot — SPEC.md, behaviors, architecture, data-model, interfaces, configuration, fitness-functions
  architecture/   overview, diagrams.md, ADRs (decisions/)
  CONTRACT.md     the v1 interface contract (mirrors the ecosystem's v1 interface contract §2)
  plans/          roadmap
  tasks/          active, backlog, completed task files
    test-specs/   TDD specs — always written before implementation
```

This repo is a **single Rust binary crate** (`vault`, edition 2021) — a `src/` with `main.rs` +
two modules, not a workspace. The layout is established; new work documents and extends it, it
does not restructure it. `docs/` is the input side (read before you act, the artifact that
survives a rewrite); the `src/*.rs` files are the output side.

`docs/spec/` is **dual-natured** — output of every task that changes externally-visible behavior,
the data model, an interface, or configuration; and input to onboarding, drift audits, and (in the
limit) regenerating the codebase. Spec and code that disagree means one of them is wrong; fix it in
the same change.

## Tech stack

Rust (edition 2021). Single static binary. Minimal dependency floor: `serde` + `serde_json`
(JSON over the socket), `nix` (kernel `SO_PEERCRED` peer-uid check, task 001), `aes-gcm` 0.10.3
(encrypted-at-rest store, task 004), and `tiny_http` 0.12 (the loopback HTTP read surface, task
005). Each addition clears dep-scan and is recorded in an ADR. Randomness — handles **and**
AES-GCM nonces — comes from the OS CSPRNG via `/dev/urandom` — **no `rand` crate**. License:
**PolyForm Noncommercial 1.0.0**.

## Commands

```bash
cargo build                                       # compile
cargo test                                        # run tests (inline #[cfg(test)] mod tests)
cargo fmt                                          # format
cargo clippy                                       # lint

# run it
cargo run -- demo                                  # put -> resolve -> inject -> replay-rejected, in-process
cargo run -- serve --socket /run/vault.sock       # IPC daemon (newline-delimited JSON)
```

There is no `make check` / `make fitness` target yet — `cargo build && cargo test` (plus
dep-scan / code-scanner for the supply chain) is the verification gate today. Fitness functions
are seeded as `proposed` in `docs/spec/fitness-functions.md`; wiring a runner is future work.

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant design decision is made
- Rust: standard `rustfmt` layout; tests live beside source as `#[cfg(test)] mod tests`.
  Keep dependencies minimal (currently `serde` + `serde_json`; RNG via `/dev/urandom`, no `rand`).
- **Never log a secret value. Never return it from `resolve`.** Error shape is
  `{error:{code,message,retryable}}`.
- **Spec is updated in the same commit as the code change.** A task that changes
  externally-visible behavior, the data model, an interface, or configuration is not done until the
  matching `docs/spec/` file reflects the new state. Stale spec entries are rewritten in place —
  never appended to. The ADR carries the history; the spec carries the truth.
- **Diagrams update with the code.** When a component boundary moves or a runtime flow changes,
  update `docs/architecture/diagrams.md` in the same commit.

## Design principles

This project follows **Unix philosophy** as its default — composability over monolithic design.
Complex behavior emerges from combining small, independent components communicating through
standardized interfaces.

Four structural properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on their own (the
  handle generator, the store, the broker are separable concerns)
- **Interface standardization** — stable, well-defined contracts (the `vault://` scheme + Vault
  HTTP API path semantics are the adapter seam that lets backends swap behind it)
- **Maintainability** — changes in one module should not cascade across unrelated ones
- **Reusability** — components should be liftable into another project without entanglement

Derived working rules:

- **One thing, well** — each module and function has a single clear responsibility
- **Small, composable pieces** over large configurable ones
- **Plain text** for configs, intermediate artifacts, and data interchange (JSON over the socket)
- **Explicit over implicit** — surface assumptions in code and types, not in comments
- **Fail fast, crash loudly** on unexpected state — and **fail closed** on the secret path
- **Test in isolation** — every component runnable without the whole stack
- **Defer premature decisions** — no abstractions until the second or third concrete use demands them

**Monolithic is a legitimate choice when deliberate** — a cryptographic primitive or the
secret-handling core can be monolithic for good reasons (tight coupling that plug-ins would
undermine, correctness on the hot path). The principle is "prefer composability at user-facing or
cross-module boundaries, and document any deviation with an ADR." The `vault://` backend seam is
exactly the kind of cross-module boundary that stays composable.

## Working in this project

Every task lives on its own branch (or worktree under concurrent sessions). Working directly on the
default branch (`main`) is blocked by the `no-commit-on-main.py` hook — `scripts/start-task.sh` is
how you pick the right isolation.

1. Start each session by reading the relevant task file (including its **Verification plan**) and its test spec
2. Check `docs/architecture/overview.md` for system context
3. Write the test spec before any implementation code
4. Use the **task-executor** agent to implement. Its Step 0 runs `scripts/start-task.sh <NNN> <slug>` to set up either:
   - `BRANCH task/NNN-<slug>` (solo session — the common case), or
   - `WORKTREE .claude/worktrees/NNN-<slug>/` (concurrent session detected; the executor `cd`s in)

   The executor commits at status **🟡 (code merged)** on the task branch.
5. After the executor returns, use **spec-verifier** on the task — it returns APPROVE or BLOCK based on per-assertion evidence
6. If spec-verifier APPROVEs **and** the verification plan's L5/L6 evidence is recorded, promote the row to **✅ (verified)** in `coverage-tracker.md` in a **separate commit** titled `verify: confirm task NNN — <evidence>` (still on the task branch)
7. **Merge to main** when ready: `git checkout main && git merge task/NNN-<slug>`. The cleanup hook then deletes the task branch and removes the worktree (if any).
8. **Commit after each milestone** — never start the next task without committing the current one first

The separation between the task branch and `main` is the load-bearing rule for multi-session
safety. The separation between 🟡 (feat commit) and ✅ (verify commit) is the load-bearing rule for
verification honesty: **never** mark ✅ in the same commit as the feature work.

## Commit rules

**Commit after every milestone.** Do not batch multiple tasks into one commit. Do not continue to
the next task until the current one is committed.

All commits below land on the **task branch** (`task/NNN-<slug>`), never on `main` directly.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries | `docs: add ADR NNN — <decision title>` |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` |
| Task code merged (🟡) | `src/` changes, moved task file, `coverage-tracker.md` row set to 🟡, affected `docs/spec/` files | `feat: complete task NNN — <name>` |
| Task verified (✅) | `coverage-tracker.md` row promoted 🟡 → ✅ with `Verified by` filled | `verify: confirm task NNN — <evidence>` |
| Diagram updated | `docs/architecture/diagrams.md` (with date bump) | `docs: refresh diagrams — <what changed>` |
| Merged into main | (after `git merge task/NNN-<slug>` on `main`) | (default `Merge branch …` message) |

This repo is **public** (PolyForm Noncommercial); push after each milestone if a remote is configured.

## Plan mode

When you exit plan mode, a hook restructures the plan: each step becomes a task file in
`docs/tasks/backlog/`, test-spec stubs are created, and the full plan is backed up to
`docs/plans/`. Use the **task-executor** agent to work through tasks one at a time.

```
use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
```

### End handoffs with a resume command

When a response completes a milestone that leaves follow-on work, end with a **fenced code block**
containing the exact resume command. Verify the path exists before writing it (glob
`docs/tasks/backlog/NNN-*.md` and the matching test-spec). Skip the block when there is genuinely
nothing to resume.

## Hook profiles

```bash
export CLAUDE_HOOK_PROFILE=minimal    # Safety hooks only
export CLAUDE_HOOK_PROFILE=standard   # + workflow hooks — default
export CLAUDE_HOOK_PROFILE=strict     # + formatting, notifications
export CLAUDE_DISABLED_HOOKS=desktop-notify,batch-format-typecheck
```

## Boundaries

### Always
- Write the test spec before any implementation code
- Fill in the **Verification plan** of the task file *before* writing code
- Commit after every milestone (task completed, spec written, ADR written)
- Read the task file (including its Verification plan) and test spec before starting
- Create an ADR for significant design decisions
- **Update `docs/spec/` in the same commit** as any code change altering behavior, data model, interfaces, or configuration
- **Update `docs/architecture/diagrams.md` in the same commit** as any change moving a component boundary or diagrammed flow
- **Default new task status to 🟡 on the feat commit; ✅ only after spec-verifier APPROVE + recorded L5/L6 evidence**, in a separate `verify:` commit
- **Run `spec-verifier` on every task** before promoting to ✅
- **Start every task on its own branch via `scripts/start-task.sh <NNN> <slug>`**
- **Preserve the zero-knowledge invariant** — every change keeps `resolve` value-free and the
  injection floor raise-only

### Ask first
- Modifying files in `docs/plans/`, `docs/tasks/`, or `docs/architecture/decisions/`
- Deleting or renaming existing source files (`src/main.rs`, `src/vault.rs`, `src/handle.rs`)
- Adding dependencies not already in the tech stack (currently `serde` + `serde_json` only — a
  crypto crate for encrypted-at-rest is a future ADR, not a casual add)
- Changing the project structure beyond what a task requires
- Reorganizing `docs/spec/` (splitting files, renaming sections)

### Never
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Run `git checkout -- <path>` over a dirty working tree — it silently overwrites uncommitted work. `git stash` first, or use `git diff`/`git show` to compare.
- **Append to spec entries instead of rewriting them.** The ADR keeps history — the spec is a snapshot.
- **Add future-tense statements to the spec.** Planned work goes in `docs/plans/` and `docs/tasks/`.
- **Mark a task ✅ on the same commit as the feature work.**
- **Claim a verification level you did not actually reach.**
- **Commit directly to `main`.** Use `[allow-main]` in the message for genuine main-only doc fixes.
- **Return a secret value from `resolve`, or log a credential anywhere** — it breaks the zero-knowledge invariant.
- **Lower the injection floor** — `inject` raises only (`max(secret_floor, requested)`).

## Common rationalizations

These are the excuses that precede a broken invariant. Catch them in yourself:

- *"It's just a debug log of the resolved value to trace a bug."* — No. The value must never leave
  vault's memory or the injection edge. A logged credential is exactly the leak vault exists to prevent.
- *"The caller asked for env, so I'll deliver env even though the floor is proxy."* — No. Effective
  mode is `max(secret_floor, requested)`. Raising is allowed; lowering is the failure mode.
- *"The handle was already validated once, replaying it is harmless."* — No. Single-use is absolute;
  a consumed handle is rejected (`handle_consumed`), and a handle bound to one sandbox never serves another.
- *"`/dev/urandom` is fine, I'll just seed a faster userspace RNG."* — No. The OS CSPRNG with no
  userspace state to seed is the deliberate choice (D4); a third-party RNG crate is attack surface.
- *"Tests pass, so it's verified."* — No. Tests passing earns 🟡. ✅ needs L5/L6 runtime evidence.

## Agent rules and retros

Process-level rules, common rationalizations, and project-specific retros live in
`docs/architecture/agent-rules.md` (when present). The `inject-retros.py` SessionStart hook surfaces
relevant entries at session start — adding an entry there is how a one-time mistake becomes a
permanent guard.

When dispatching parallel agents in one message, run
`scripts/verify-worktree-isolation.sh <agent-id> …` afterward to confirm none bypassed the worktree flag.

## Recommended tooling

This is a **Rust cryptographic / secret-handling block** — the crown-jewel path of the
secure-agent ecosystem. Wire the supply-chain and security gates before building on or running
anything new:

- **dep-scan** — supply-chain CVE scan of Rust crates. Critical the moment encrypted-at-rest pulls
  a crypto crate (AES-GCM, age) and its transitive tree. Use `cargods` for Rust (Cargo lockfile).
  Install: `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`
- **code-scanner** — scan any new crate (and the repo itself) for malware / backdoors / credential
  harvesting before adoption — doubly important for a block whose whole job is holding secrets.
  Trigger: "scan this repo for malware".
- **code-review** — review diffs before merge, especially anything touching `resolve`/`inject`, the
  handle generator, or the socket. Trigger: `/code-review`.
- **security-auditor agent** — run a security pass on any change to the secret path before ship.
  Invoke: "use the security-auditor on the inject path". It checks for leaked plaintext, lowered
  floors, replayable handles, and insecure socket defaults.

### Hooks

Wired via `.claude/settings.json` (standard profile): `no-commit-on-main`, `protect-secrets`,
`block-no-verify`, plan→tasks restructuring, compaction guards, spec-coverage-check. Control with
`CLAUDE_HOOK_PROFILE` (minimal/standard/strict).
