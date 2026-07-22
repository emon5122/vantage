# Threat model & security posture

Vantage is an **analysis** tool. This document states what it does and does not
do to a target, what it protects, and what a reviewer should verify.

## Assets & actors

- **Analyst** — an authorised researcher running Vantage against software they are
  permitted to analyse (their own build, a client engagement, a CTF, academic
  study, or an application whose terms permit interoperability research in the
  applicable jurisdiction).
- **Target** — a Unity IL2CPP application, typically hardened with anti-tamper /
  packing / anti-debug.
- **Observations** — the structured artifacts and knowledge base produced.

## Non-goals (explicit exclusions)

Vantage **does not**:

- bypass, disable, or weaken anti-cheat, anti-tamper, anti-debug, integrity
  checks, certificate pinning, request signing, or packing;
- extract cryptographic keys, or decrypt anything the runtime has not already
  decrypted in memory for its own use;
- generate, replay, inject, delay, drop, or modify network traffic;
- modify target memory or patch code;
- provide gameplay automation, bots, or cheats.

These exclusions are architectural: the codebase contains no primitive that would
enable them, and CI review rejects contributions that add one.

## Interaction surface with the target

| Surface | What Vantage does | What it never does |
|---|---|---|
| Process memory | reads (via Frida) for enumeration/logging | writes / patches |
| Native functions | attaches read-only interceptors | replaces / trampolines that alter behaviour |
| Sockets | reads `send`/`recv` buffers post-call | modifies buffers / injects / replays |
| Files | reads paths/sizes of metadata/asset opens | writes to the target's files |

## Detection & degradation

Vantage does **not** attempt to evade a target's Frida/anti-analysis detection.
A hardened target may detect instrumentation and terminate; this is expected,
logged, and in-scope. The offline analysis, knowledge base, and documentation
never touch the device and carry no such risk.

## Data handling

- Recovered artifacts may contain **client-side identifiers** (e.g. app config
  values). Treat capture sessions and knowledge bases as sensitive; they are
  gitignored by default (`vantage_data/`, `captures/`, `*.db`).
- Target-specific research (real class inventories, real endpoints) belongs in a
  private, gitignored `research/` directory — never in the public core.

## What a reviewer should verify

- `grep -R "Interceptor.replace\|Memory.write\|Memory.protect" src/vantage/agent`
  → no behaviour-altering hooks.
- Socket hooks read `args[buf]` and never write it.
- No module constructs and sends application-level requests.

See [ethics-and-responsible-research.md](ethics-and-responsible-research.md) for
the authorisation and disclosure expectations.
