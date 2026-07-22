# Confidence engine

Module: [`vantage.kb.confidence`](../../src/vantage/kb/confidence.py)

The confidence engine assigns a numeric score in `[0, 1]` to every observation
and guarantees a single invariant that makes the knowledge base *cumulative*:

> **A new, weaker observation can corroborate existing evidence, but it can never
> downgrade a stronger prior belief.**

## Scoring

```
score(grade, count) = min(1.0, base(grade) + count_boost(count))
```

- `base(grade)` maps an [evidence grade](evidence-model.md) to a floor score
  (e.g. `verified(class)` → 0.95, `observed` → 0.75, `Unknown` → 0.20).
- `count_boost(count)` adds a diminishing bonus for repeated observation, capped
  at `+0.10`, so a heavily-observed `observed` fact can approach — but not
  exceed — a single `spec`/`verified` fact.

## Merge semantics

`merge(old_score, old_grade, new_grade, new_count, source)` returns
`{score, grade, changed, reason}`:

1. The **stronger grade** is kept (`old` vs `new` by base score).
2. The **score is monotonic non-decreasing**: `max(old_score, candidate)`.
3. A human-readable `reason` records whether this was first evidence, a
   corroboration, or a strengthening — and by how much.

Every call is journaled to `confidence_history`, so the full provenance of any
belief is queryable and a change log can be regenerated deterministically.

## Field promotion

`field_confidence(present_in, of_samples, min_samples, type_stable)` computes the
three-tier grade for a schema field from **cross-session accumulated counts**.
Because `present_in` and `of_samples` accumulate as more captures are imported,
the same field naturally climbs `Unknown → Likely → Verified` over time. This is
the mechanism by which the system "gets more accurate with more gameplay,
without additional reverse engineering."

## Worked example

| Event | present/of | grade |
|---|---|---|
| First capture: field seen once | 1/1 | Unknown (below min_samples) |
| Three more captures, same type | 4/4 | Verified |
| A later capture where the field is absent | 4/5 | Likely (now optional) |

The engine never regresses the *command's* other Verified fields when one field
becomes optional; each field is scored independently.

## Testing

The invariants are covered by
[`tests/test_confidence.py`](../../tests/test_confidence.py):
grade ordering, diminishing count boost, the never-downgrade guarantee, and field
promotion thresholds.
