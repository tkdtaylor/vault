# vault — JIT zero-knowledge secret store & credential broker

Answers one question: *does the agent core ever see a credential in plaintext?* The answer
is **no** — not in logs, not in context, not in memory, not in the audit trail. The agent
holds only an opaque, single-use **handle**; the plaintext is injected **at the host
boundary, into `exec-sandbox`, at the moment of execution**, then wiped.

- **Handle indirection** — the agent's reference is structurally un-loggable (Threat A: total prevention)
- **Tiered injection** — `env` (value into sandbox) vs `proxy` (value never enters the sandbox; Threat B: structural prevention)
- **Pull-triggered push** — exec-sandbox presents `{handle, sandbox_identity}` at spawn; vault validates the binding, then delivers
- **Single-use + first-use binding** — a replayed handle, or a second sandbox, is rejected (the secured vault→proxy handoff, D5)

> Prior-art verdict: **BUILD (clean-room)** — store + resolve/inject broker + handle/identity binding. OpenBao / HashiCorp Vault (Vault HTTP API semantics) and AgentSecrets are reference designs + pluggable backends behind the `vault://` seam. The egress proxy lives in `exec-sandbox`, not here. **Language: Rust** (memory safety for the crown-jewel crypto/secret-handling path). **License: PolyForm Noncommercial 1.0.0.**

## Contract (interface-contracts.md §2, v1)

```
resolve(secret_ref, requester_identity) -> { handle, ttl, injection_mode }       # NOT the value
inject(handle, sandbox_identity, mode)  -> proxy: { ok, delivery, credential, binding{host,header,scheme} }
                                           env:   { ok, delivery, credential, var_name, wiped_at }
put | get | list | rotate (admin)
```

The `credential` + `binding` on the `inject` response is the v0→v1 change the tracer-bullet
surfaced (A7): exec-sandbox's proxy needs them to actually inject. They cross only the
uid-restricted vault socket — the injection edge.

## Build & run

```sh
cargo build
cargo test
cargo run -- demo                       # put -> resolve -> inject -> replay-rejected, in-process
cargo run -- serve --socket /run/vault.sock   # IPC daemon
```

IPC (newline-delimited JSON): `{"op":"resolve","secret_ref":"vault://test/api_key"}`,
`{"op":"inject","handle":"…","sandbox_identity":{"sandbox_id":"…"},"mode":"proxy"}`,
`{"op":"put",…}`, `{"op":"ping"}`.

## Status

🚧 **v0 skeleton, v1 contract.** Working resolve/inject with single-use capability handles,
first-use sandbox binding, fail-closed floor (`max(secret_floor, policy_raised)`), and the
proxy/env delivery split. **Deferred (v1):** encrypted-at-rest store (AES-256-GCM + age /
client-side encryption for store-level zero-knowledge), TTL auto-wipe clock, SPIFFE identity
binding, SO_PEERCRED peer-uid check on the socket, Vault HTTP API compatibility, cloud-KMS /
HSM backends. The v0 store is in-memory plaintext (per scoping).

## Adapter seam & standards

`vault://<scope>/<key>` scheme + Vault HTTP API path semantics. Pluggable backends: local
encrypted store (default), OpenBao, HashiCorp Vault, AWS/GCP/Azure secret managers, PKCS#11
HSM. See [docs/CONTRACT.md](docs/CONTRACT.md) and the scoping doc.
