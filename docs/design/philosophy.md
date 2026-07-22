# Design philosophy, decisions & trade-offs

## Principles

1. **Observation over interaction.** The framework reads state the runtime has
   already produced for its own purposes — decrypted metadata, decoded packets,
   established sockets. It never causes the target to do anything it would not do
   during normal, user-driven execution. This is a hard architectural boundary,
   not a policy toggle: there is no `Interceptor.replace`, no memory write, no
   packet mutation, and no request generation anywhere in the codebase.

2. **Evidence before assertion.** Every recovered fact carries a grade and a
   provenance record. The system prefers to say *"Unknown"* over guessing. See
   [evidence-model.md](evidence-model.md).

3. **Cumulative knowledge.** Each authorised observation is merged into a durable
   store that only ever grows more accurate. Re-running analysis never regresses
   confidence and never duplicates records. See
   [confidence-engine.md](confidence-engine.md).

4. **Reusability over specificity.** The core is generic to Unity IL2CPP and to
   the FPNN/MessagePack protocol family. Anything target-specific lives in
   isolated case studies or plugins, never in the core.

5. **Offline-first.** The analysis, knowledge base, documentation, and viewer
   have **zero third-party runtime dependencies** and run without a device. Only
   the live-instrumentation layer needs Frida, and it is an optional extra.

## Key design decisions & trade-offs

| Decision | Rationale | Trade-off accepted |
|---|---|---|
| **Socket-level protocol capture** (vs. managed hooks) | Robust, low-touch, decoder-agnostic; works before the managed API is located | Sees ciphertext for TLS transports; plaintext only for the raw-TCP protocol |
| **Packet deduplication by fingerprint** | Scales to millions of frames; distinct *shapes* are bounded even when frame *count* is not | Loses per-instance payloads (a bounded sample is retained) |
| **Layered locator for the IL2CPP API** | Works on stock builds *and* hardened builds where export names are stripped | Hardened targets need researcher-supplied offsets or an opt-in behavioural probe |
| **Confidence never downgrades** | Cumulative correctness; later weak evidence cannot erase earlier strong evidence | A one-off mis-graded strong observation persists (mitigated by provenance journaling) |
| **SQLite single-file store** | Zero-ops, portable, transactional, indexes + WAL scale well | Not a distributed store; extreme scale needs sharding (see [performance](../performance-and-scalability.md)) |
| **JS agent concatenated by the host** | No bundler dependency; each module is an independent IIFE | Manual module ordering; mitigated by a fixed load list and CI parse checks |
| **Framing from the public FPNN standard** | The framing is a documented fact, not a guess; graded `spec` until magic-confirmed | Requires a live capture to promote framing to `observed` |
| **Frida as an optional dependency** | Offline analysis + tests run anywhere; CI needs no device | Instrumentation subcommands error clearly if Frida is absent |

## What the framework deliberately does **not** do

- It does not defeat, disable, or weaken anti-tamper, anti-debug, integrity, or
  packing protections. Where a target is hardened, the framework degrades
  gracefully and documents what it cannot see.
- It does not extract cryptographic keys, and it does not decrypt anything the
  runtime has not already decrypted in memory for itself.
- It does not generate, replay, inject, or modify network traffic.
- It contains no gameplay automation, bot, or cheat logic.

These are covered normatively in the [threat model](../threat-model.md) and
[ethics](../ethics-and-responsible-research.md) documents and enforced socially
by `CONTRIBUTING.md` and mechanically by CI review.
