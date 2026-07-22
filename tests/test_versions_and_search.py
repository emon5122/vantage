"""Version comparison + search engine + classifier tests."""
import json

from vantage.kb import importer, versions, search
from vantage.metadata.classifier import score_one
from vantage.protocol.synthetic import write_session


def test_version_diff_detects_new_opcode_and_schema_change(kb, tmp_path):
    # v1: login {#1,#2,#3}
    d1 = str(tmp_path / "v1"); write_session(d1, label="login")
    importer.import_capture(kb, d1, version="1.0.0", label="login")

    # v2: a NEW command 'newcmd' + login with an extra field #9
    from vantage.protocol.synthetic import frame
    from vantage.protocol.fpnn import iter_stream
    import os
    d2 = str(tmp_path / "v2"); os.makedirs(d2, exist_ok=True)
    tx = bytearray()
    tx += frame(1, 1, {1: "u", 2: "t", 3: 1, 9: "extra"}, method="login")
    tx += frame(1, 2, {1: 5}, method="newcmd")
    rx = bytearray()
    rx += frame(2, 1, {1: 1}, status=0)
    rx += frame(2, 2, {1: 1}, status=0)
    with open(os.path.join(d2, "frames.jsonl"), "w") as f:
        for buf, dr in [(tx, "tx"), (rx, "rx")]:
            for rec, a, b in iter_stream(bytes(buf)):
                if rec.get("desync_skipped"):
                    continue
                rec["_dir"] = dr; rec["_ts"] = 0.0; rec["_fd"] = 1; rec["_peer"] = {"ip": "x", "port": 1}
                f.write(json.dumps(rec) + "\n")
    open(os.path.join(d2, "connections.json"), "w").write('{"label":"login","connections":{}}')
    importer.import_capture(kb, d2, version="2.0.0", label="login")

    d = versions.diff(kb, "1.0.0", "2.0.0")
    assert "method:newcmd" in d["new_opcodes"]
    changed = {c["command"]: c for c in d["schema_changes"]}
    assert "method:login" in changed and "#9" in changed["method:login"]["added_fields"]


def test_search_field_and_command(kb, synth_session):
    importer.import_capture(kb, synth_session, version="1.0.0", label="login")
    rows = search.packets_using_field(kb, "#1")
    assert any(r["command_key"] == "method:ping" and r["confidence"] == "Verified" for r in rows)
    detail = search.command_detail(kb, "method:ping")
    assert detail["schema"]["overall_confidence"] == "Verified"


def test_search_rejects_non_select(kb):
    import pytest
    with pytest.raises(ValueError):
        search.run_sql(kb, "DROP TABLE commands")


def test_classifier_and_library_internal_bucketing():
    assert score_one("Assembly-CSharp", "com.fpnn", "TCPClient")["role"] == "Network"
    assert score_one("Assembly-CSharp", "com.example.framework", "CheckAppVersion")["role"] == "Version"
    lib = score_one("A", "Best.HTTP.SecureProtocol.Org.BouncyCastle.Tls", "TlsSession")
    assert lib["role"] == "TlsCryptoInternal" and lib["library_internal"] is True
