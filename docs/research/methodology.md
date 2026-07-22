# Research methodology

Vantage encodes a repeatable, evidence-first method for analysing a hardened Unity
IL2CPP application. The method is **target-agnostic**; concrete, target-specific
findings belong in private case studies, never in this public repository.

## The loop: observe → grade → correlate → accumulate

1. **Static reconnaissance** — inventory native libraries, the IL2CPP data
   directory, and the managed type surface. Grade what is *proven* (class names,
   file layout) vs. *inferred*.
2. **Read-only instrumentation** — attach and observe: library load order,
   `JNI_OnLoad`/`RegisterNatives`, socket/DNS activity, runtime strings, Lua VM,
   and (where authorised and located) the in-memory IL2CPP type system.
3. **Protocol capture** — record raw frames off the socket layer during
   *user-driven* gameplay, one labelled action at a time. Never synthesise or
   replay traffic.
4. **Decode & correlate** — frame → MessagePack → quest/answer correlation →
   per-command schema inference. Grade each field `Verified/Likely/Unknown`.
5. **Accumulate** — import every session into the versioned knowledge base. The
   confidence engine promotes fields as evidence accrues; nothing regresses.
6. **Compare across versions** — diff opcodes, schemas, and classes between
   releases to understand protocol evolution.

## Evidence discipline

- Every fact carries a grade, a source, an observation count, a version, and a
  reason. See [../design/evidence-model.md](../design/evidence-model.md).
- Framing is grounded in public standards (`spec`) and only promoted to
  `observed` once seen on the wire.
- Opcodes, field names/types, and endpoints are emitted **only** when observed —
  never guessed.

## One action at a time

To attribute packets to behaviour, capture a single gameplay action per session
and label it (`--label`). Because only one action is exercised, the frames that
appear are attributable to it — with no automation and no synthetic requests.

## Reproducibility

- Use synthetic inputs (`vantage.protocol.synthetic`) to validate tooling.
- Keep the knowledge base and its `confidence_history` as the durable record; the
  change log and reports regenerate deterministically from it.

## Authorisation & ethics

Only analyse software you are permitted to. Follow coordinated disclosure for any
third-party vulnerability. See
[../ethics-and-responsible-research.md](../ethics-and-responsible-research.md).
