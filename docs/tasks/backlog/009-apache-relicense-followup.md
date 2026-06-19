# Task 009: Apache-2.0 relicense follow-up — SPDX headers + push

**Project:** vault
**Created:** 2026-06-19
**Status:** backlog

## Context

Relicensed PolyForm Noncommercial → Apache-2.0 in commit `8d71262`.

**Done in `8d71262`:**
- `LICENSE`, `NOTICE`
- `Cargo.toml` `license` field
- `README.md` adoption sections
- `CONTRIBUTING.md` (DCO)
- `.github/FUNDING.yml` + `.github/dco.yml`
- PolyForm references fixed in `README.md`, `CLAUDE.md`, `ADR-001`

## Remaining

a. **SPDX headers** — add `// SPDX-License-Identifier: Apache-2.0` as the **first line** of every
   first-party Rust source file under `src/`. Skip `target/`, generated, and vendored files. Land as
   its **own commit**.

b. **Push** — push the relicense once public/private visibility is confirmed.

## Acceptance criteria

- [x] SPDX header (`// SPDX-License-Identifier: Apache-2.0`) is the first line of every first-party
      `.rs` file under `src/`.
- [ ] Relicense is pushed to the GitHub remote.
