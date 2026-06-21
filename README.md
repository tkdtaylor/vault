# vault — JIT zero-knowledge secret store & credential broker

Answers one question: *does the agent core ever see a credential in plaintext?* The answer is **no** — not in logs, not in context, not in memory, not in the audit trail. The agent holds only an opaque, single-use **handle**; the plaintext is injected **at the host boundary, into `exec-sandbox`, at the moment of execution**, then wiped.

- **Handle indirection** — the agent's reference is structurally un-loggable (Threat A: total prevention)
- **Tiered injection** — `env` (value into sandbox) vs `proxy` (value never enters the sandbox; Threat B: structural prevention)
- **Pull-triggered push** — exec-sandbox presents `{handle, sandbox_identity}` at spawn; vault validates the binding, then delivers
- **Single-use + first-use binding** — a replayed handle, or a second sandbox, is rejected (the secured vault→proxy handoff, D5)

> Prior-art verdict: **BUILD (clean-room)** — store + resolve/inject broker + handle/identity binding. OpenBao / HashiCorp Vault (Vault HTTP API semantics) and AgentSecrets are reference designs + pluggable backends behind the `vault://` seam. The egress proxy lives in `exec-sandbox`, not here. **Language: Rust** (memory safety for the crown-jewel crypto/secret-handling path). **License: Apache-2.0.**

## Scope

**What vault does:** a zero-knowledge secret store + just-in-time credential injection at the execution boundary — the agent never sees plaintext.

**What it does *not* do (and which sibling owns it instead):**
- Own the egress proxy, network allowlist, or isolation boundary → **exec-sandbox** (vault hands the credential to that boundary at spawn)
- Decide whether a secret may be released → **policy-engine**
- Cache credentials across task boundaries — injection is single-use with a raise-only floor

`vault` is one block in a composable secure-agent ecosystem — each block is standalone and independently usable, and composes with its siblings over published contracts rather than absorbing their responsibilities (no central "god object").

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

## Documentation

- [docs/architecture/overview.md](docs/architecture/overview.md) — system design and design principles
- [docs/architecture/diagrams.md](docs/architecture/diagrams.md) — C4 diagrams and runtime flows
- [docs/spec/SPEC.md](docs/spec/SPEC.md) — authoritative spec
- [docs/plans/roadmap.md](docs/plans/roadmap.md) — roadmap and current status
- [docs/CONTRACT.md](docs/CONTRACT.md) — the published interface contract

## Status

🚧 **v1 in progress.** Working resolve/inject with single-use capability handles, first-use sandbox binding, fail-closed floor (`max(secret_floor, policy_raised)`), the proxy/env delivery split, TTL auto-wipe clock (ADR-003), the `SO_PEERCRED` peer-uid check on the socket (ADR-002), the `get`/`list`/`rotate` admin verbs with rotate-invalidation (ADR-004), and an **AES-256-GCM encrypted-at-rest store** with the master key held off the ciphertext behind a backend seam (ADR-005). The store is encrypted at rest in process memory — no on-disk persistence yet.

See the [roadmap](docs/plans/roadmap.md) for deferred work and planned features.

## Adapter seam & standards

`vault://<scope>/<key>` scheme + Vault HTTP API path semantics. Pluggable backends: local
encrypted store (default), OpenBao, HashiCorp Vault, AWS/GCP/Azure secret managers, PKCS#11
HSM. See [docs/CONTRACT.md](docs/CONTRACT.md) and the scoping doc.

## License

vault is licensed under the **Apache License 2.0** — free to use, modify, and distribute, including in commercial and proprietary products. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

> **Security notice:** vault is a security tool provided **as-is, without warranty**. It does not guarantee the security of any system. See the disclaimer in [NOTICE](NOTICE).

## Enterprise Support

Need hardened deployments, integration help, or a support SLA? **Commercial support and consulting are available.**

📧 Contact **[tools@taylorguard.me](mailto:tools@taylorguard.me)**

## Sponsorship

vault is independent, open-source security tooling. If it saves you time or risk, consider sponsoring continued development:

- 💜 [GitHub Sponsors](https://github.com/sponsors/tkdtaylor)

## Contributing

Contributions are welcome and become part of the project under Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). We use the **Developer Certificate of Origin (DCO)** — sign off your commits with `git commit -s`. No CLA required.
