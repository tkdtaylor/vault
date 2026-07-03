# vault v1 contract

Validated by the ecosystem tracer-bullet (A2/A3 + the vault→proxy handoff
micro-test, D5).

## Verbs

### `resolve(secret_ref, requester_identity) -> { handle, ttl, injection_mode }`
Mints an opaque **single-use** handle bound to the requester. Returns the secret's floor as
`injection_mode`. **Never returns the value.** `secret_refs` downstream carries the handle,
never the `vault://` ref (D4).

### `inject(handle, sandbox_identity, mode) -> { ok, delivery, … }`
Pull-triggered push (D1): exec-sandbox presents `{handle, sandbox_identity}` at spawn.
- `proxy` → `{ ok, delivery:"proxy", credential, binding:{host,header,scheme} }` — value to
  exec-sandbox's egress proxy only; never into the sandbox.
- `env` → `{ ok, delivery:"env", credential, var_name, wiped_at }`.
- effective mode = `max(secret_floor, mode)`; vault RAISES, never lowers (fail-closed).
- single-use: a replayed handle → `error.code = handle_consumed`; a different sandbox →
  `handle_bound_to_other_sandbox`.

### `put | get | list | rotate` (admin)
`put{secret_ref, value, injection_floor, binding}` seeds a secret. **All four admin verbs are wired**
in the IPC dispatch and the in-process `Vault` API. get/list/rotate return metadata, **never the
value**:
- `get{secret_ref}` → `{exists, injection_floor, binding}`; unknown ref → `no_such_secret`.
- `list` → `{secrets:[{secret_ref, injection_floor},…]}`; empty store → `[]`.
- `rotate{secret_ref, value}` → replaces the value in place (floor + binding preserved), echoes no
  value; unknown ref → `no_such_secret`. **Rotation invalidates outstanding handles** for that ref:
  a handle resolved before the rotate is rejected `handle_invalidated` on inject (ADR-004).

## The vault→proxy handoff (D5)

Secured by three properties together: uid-restricted Unix socket (0600 now; SO_PEERCRED
peer-uid check is v1) + unguessable single-use capability handle + first-use sandbox
binding. The plaintext lives only at the injection edge.
