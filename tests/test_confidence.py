"""Unit tests for the confidence engine (never-downgrade invariant)."""
from vantage.kb import confidence as C


def test_grade_ordering():
    assert C.grade_score("verified(class)") > C.grade_score("observed") > C.grade_score("Unknown")


def test_count_boost_diminishing():
    assert C.count_boost(1) == 0.0
    assert 0 < C.count_boost(4) <= 0.10
    assert C.count_boost(1_000_000) <= 0.10


def test_merge_never_downgrades():
    # start strong, then a weaker observation arrives
    m1 = C.merge(0.0, None, "verified(class)", 1, "static")
    assert m1["grade"] == "verified(class)"
    m2 = C.merge(m1["score"], m1["grade"], "Unknown", 1, "capture")
    assert m2["score"] >= m1["score"]          # never lower
    assert C.grade_score(m2["grade"]) >= C.grade_score("verified(class)")


def test_merge_strengthens_on_stronger_evidence():
    m1 = C.merge(0.0, None, "Unknown", 1, "import")
    m2 = C.merge(m1["score"], m1["grade"], "observed", 5, "capture")
    assert m2["score"] > m1["score"] and m2["changed"] is True


def test_field_confidence_promotion():
    assert C.field_confidence(1, 1, min_samples=3) == "Unknown"    # too few samples
    assert C.field_confidence(5, 5, min_samples=3) == "Verified"   # all samples, stable
    assert C.field_confidence(4, 5, min_samples=3) in ("Likely", "Unknown")  # optional field
