# Security Policy

## Supported versions

vault has not yet cut a tagged release. Until a `v1.0.0` ships, only the current
`main` branch receives security fixes. This table will be filled in once releases
begin.

| Version | Security fixes |
|---------|---------------|
| `main` (pre-release) | ✅ Yes |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/vault/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (the `vault://` ref / inject flow involved)
- The commit or `main` state you observed it on
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

Encrypt with PGP if you prefer — open an issue requesting a public key and
we will publish one.

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

vault is the crown-jewel secret-handling path; secret disclosure is the
highest-severity class of bug here.

**In scope:**

- Secret disclosure: any path that returns a stored secret to a caller not
  authorized for that `vault://` ref, or that leaks it in logs/errors/memory
- Handle/identity-binding bypass: resolving or injecting a secret under an
  identity or handle that should not have access
- Inject-floor bypass: lowering an injection floor that policy raised, or
  injecting where proxy-mode should keep the secret out of the consumer entirely
- Memory-handling flaws in the secret path (secrets not wiped, copied into
  long-lived buffers, or recoverable after use)
- The admin verbs and the `vault://` resolve/inject API surface (parsing,
  injection, authorization)

**Out of scope:**

- Bugs in pluggable backends (OpenBao, HashiCorp Vault, AgentSecrets) themselves
  — report upstream (we will help coordinate)
- The egress proxy / network-exfil path, which lives in `exec-sandbox`, not here
- Vulnerabilities in the ecosystem blocks consumed over their contracts
  (`policy-engine`, `exec-sandbox`, `audit-trail`) — report to their repositories
- Findings that require an already-compromised host or operator-supplied
  malicious configuration

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.
