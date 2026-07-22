"""
kb/confidence.py — the confidence engine.

Assigns a numeric score to every observation, driven by (evidence-grade,
observation-count). Core rule: NEVER downgrade — a new, weaker observation may
only add corroboration; it can never overwrite stronger existing evidence.
Every change is journaled to confidence_history with a human reason.
"""
import math

# Evidence grades -> base score. Higher = stronger.
GRADE_SCORE = {
    "verified(class)": 0.95,
    "spec": 0.90,
    "Verified": 0.90,
    "verified": 0.90,
    "runtime_metadata": 0.88,
    "static_monoscript": 0.85,
    "observed": 0.75,
    "spec+observe": 0.80,
    "Likely": 0.55,
    "inferred": 0.45,
    "capture-derived": 0.60,
    "Unknown": 0.20,
    "heuristic": 0.35,
    None: 0.10,
    "": 0.10,
}

# Provenance ranking for tie-breaks / journaling.
SOURCE_RANK = {
    "capture": 5, "runtime": 5, "protocol.json": 4, "classifier": 3,
    "request_map": 3, "opcode_map": 3, "static": 2, "import": 1,
}


def grade_score(grade):
    return GRADE_SCORE.get(grade, 0.10)


def count_boost(count):
    """Diminishing returns bonus for repeated observation (max +0.10)."""
    if not count or count <= 1:
        return 0.0
    return min(0.10, 0.03 * math.log2(count + 1))


def score_for(grade, count=1):
    return round(min(1.0, grade_score(grade) + count_boost(count)), 4)


def merge(old_score, old_grade, new_grade, new_count=1, source="import"):
    """Combine an existing (score,grade) with a new observation.

    Returns dict {score, grade, changed, reason}. Never lowers the score or
    replaces a stronger grade with a weaker one.
    """
    old_score = old_score or 0.0
    cand = score_for(new_grade, new_count)
    # keep the stronger grade
    if grade_score(new_grade) > grade_score(old_grade or ""):
        grade = new_grade
    else:
        grade = old_grade or new_grade
    score = max(old_score, cand, score_for(grade, new_count))
    changed = score > old_score + 1e-9 or grade != (old_grade or "")
    if not changed:
        reason = f"corroborated by {source} (grade={new_grade}, +{new_count} obs); no upgrade"
    elif old_score == 0.0:
        reason = f"first evidence from {source} (grade={new_grade})"
    else:
        reason = f"strengthened by {source}: {old_grade or 'none'}({old_score:.2f}) -> {grade}({score:.2f}), +{new_count} obs"
    return {"score": round(score, 4), "grade": grade, "changed": changed, "reason": reason}


def field_confidence(present_in, of_samples, min_samples=3, type_stable=True):
    """Confidence grade for a schema field from accumulated counts (matches
    fpnn/schema_infer semantics, applied to cross-session totals)."""
    if of_samples < min_samples:
        return "Unknown"
    optional = present_in < of_samples
    if not optional and type_stable:
        return "Verified"
    if type_stable or present_in >= max(2, of_samples * 0.6):
        return "Likely"
    return "Unknown"
