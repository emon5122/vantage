# Security Policy

## Scope

This policy covers vulnerabilities **in Vantage itself** (the framework code).
For vulnerabilities you discover in a *third-party application* while using
Vantage, follow coordinated disclosure with that vendor — see
[docs/ethics-and-responsible-research.md](docs/ethics-and-responsible-research.md).

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` (latest) | ✅ |
| older pre-releases | ❌ |

## Reporting a vulnerability

Please report privately — do **not** open a public issue for security problems.

- Use **GitHub Security Advisories** ("Report a vulnerability") on this
  repository, or
- open a minimal private channel with the maintainers as listed in
  [`.github/CODEOWNERS`](.github/CODEOWNERS).

Include: affected version/commit, a description, reproduction steps, and impact.

We aim to acknowledge within **72 hours** and to provide a remediation timeline
after triage. We follow a **90-day** coordinated-disclosure window by default and
will credit reporters who wish to be credited.

## What we consider in scope

- Code execution, path traversal, or unsafe deserialization in the import/parse
  pipeline (e.g. a crafted `frames.jsonl`/artifact).
- SQL injection in the knowledge base (all queries are parameterised; report any
  gap).
- The read-only viewer serving or embedding untrusted content unsafely.
- Any code path that violates the **observation-only** guarantee (this is treated
  as a security-severity defect).

## Out of scope

- Requests to add offensive capability (automation, injection, replay, memory
  modification, protection bypass). These are permanently rejected by design.
- Findings that require running Vantage against software you are not authorised to
  analyse.
