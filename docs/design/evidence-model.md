# Evidence model

Every fact Vantage records is tagged with **where it came from** and **how
strongly it is supported**. This is what separates the framework from ad-hoc
reverse-engineering notes: a reviewer can always ask *"why do you believe this?"*
and get a precise, reproducible answer.

## Evidence grades

Grades are ordered from strongest to weakest. The confidence engine maps each to
a numeric score (see [confidence-engine.md](confidence-engine.md)).

| Grade | Meaning | Typical source |
|---|---|---|
| `verified(class)` | Proven from a recovered managed type/class name | IL2CPP metadata traversal / MonoScript names |
| `spec` | Defined by a public, documented standard | FPNN/MessagePack specifications |
| `Verified` | Field observed consistently across ≥ *N* samples with a stable type | schema inference over captures |
| `runtime_metadata` | Read from the in-memory type system via the read-only API | metadata recovery |
| `observed` | Directly seen in captured bytes/events | protocol capture, network hooks |
| `Likely` | Stable type but few samples, or present in a majority | schema inference |
| `inferred` | Reasoned from verified evidence + platform convention | framing auth/version notes |
| `Unknown` | Not yet observed sufficiently | default for unpopulated fields |

## Three-tier field confidence

For protocol **schema fields**, a simplified public-facing tier is used:

- **Verified** — present in *every* sample of a command, single stable type, and
  at least `min_samples` (default 3) observations.
- **Likely** — a stable type but too few samples, or present in a majority.
- **Unknown** — sparse, mixed types, or below the sample threshold.

Fields are automatically promoted `Unknown → Likely → Verified` as more captures
accumulate — no re-analysis or manual intervention required.

## Provenance

Every confidence change is journaled append-only to `confidence_history` with:

- entity type + id, and (for fields) the field name
- old score → new score, and the resulting grade
- **source** (capture, protocol.json, classifier, request_map, …)
- **version** of the target the evidence came from
- **timestamp**
- a human-readable **reason** string
- the **observation count** that produced the change

This makes the knowledge base auditable and reproducible: a `CHANGELOG` is
generated directly from this journal.

## The "never guess" rule

Unpopulated protocol details render as `Unknown` or "(none yet)", never as
fabricated values. Framing fields are graded `spec` (a documented standard) and
only promote to `observed` once a live capture magic-matches. Schema field names,
types, and opcode↔command links are **only** emitted when actually observed.
