"""Integration tests for the knowledge base: import, dedup, opcode learning."""
from vantage.kb import importer


def test_import_capture(kb, synth_session):
    res = importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    assert res["frames"] == 13 and res["commands"] == 5
    assert kb.q1("SELECT COUNT(*) n FROM commands")["n"] == 5
    assert kb.q1("SELECT COUNT(*) n FROM sessions")["n"] == 1


def test_dedup_idempotent(kb, synth_session):
    importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    before = kb.q1("SELECT COALESCE(SUM(obs_count),0) o FROM packets")["o"]
    res = importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    after = kb.q1("SELECT COALESCE(SUM(obs_count),0) o FROM packets")["o"]
    assert "skipped" in res and after == before  # unchanged re-import is a no-op


def test_packet_fingerprint_dedup(kb, synth_session):
    importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    # 5 ping frames share one shape -> one packet row with obs_count 5
    row = kb.q1("SELECT p.obs_count AS obs_count FROM packets p JOIN commands c ON c.id=p.command_id "
                "WHERE c.command_key='method:ping'")
    assert row["obs_count"] == 5


def test_opcode_learning_and_relationships(kb, synth_session):
    importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    # gameplay action linked to commands
    n = kb.q1("SELECT COUNT(*) n FROM relationships WHERE src_type='action' AND dst_type='command'")["n"]
    assert n == 5
    # confidence journalled
    assert kb.q1("SELECT COUNT(*) n FROM confidence_history")["n"] > 0


def test_schema_field_confidence(kb, synth_session):
    importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    row = kb.q1("""SELECT sf.confidence FROM schema_fields sf
                   JOIN schemas s ON s.id=sf.schema_id
                   JOIN commands c ON c.id=s.command_id
                   WHERE c.command_key='method:ping' AND sf.field='#1'""")
    assert row["confidence"] == "Verified"


def test_classes_import(kb, tmp_path):
    import json
    p = tmp_path / "ranked.json"
    p.write_text(json.dumps([
        {"assembly": "Assembly-CSharp", "namespace": "com.fpnn", "class": "TCPClient",
         "role": "Network", "confidence": 0.9, "tier": "high", "verified": "static_monoscript"},
    ]))
    res = importer.import_classes_ranked(kb, str(p), version="1.0.0")
    assert res["classes"] == 1
    assert kb.q1("SELECT role FROM classes WHERE name='TCPClient'")["role"] == "Network"
