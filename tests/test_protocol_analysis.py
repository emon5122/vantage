"""Integration tests for correlation + schema inference over synthetic frames."""
import json
import os

from vantage.protocol.correlate import load_frames, correlate
from vantage.protocol.schema import infer, command_key
from vantage.protocol.synthetic import write_session


def _frames(tmp_path):
    d = str(tmp_path / "s")
    write_session(d, label="login")
    return load_frames(d)


def test_correlation_pairs_and_timing(tmp_path):
    corr = correlate(_frames(tmp_path))
    assert corr["stats"]["pairs"] == 6
    assert corr["stats"]["pushes"] == 1
    assert corr["stats"]["rtt_ms"]["min"] > 0


def test_heartbeat_detected(tmp_path):
    corr = correlate(_frames(tmp_path))
    hb = {h["method"]: h for h in corr["heartbeats"]}
    assert "ping" in hb
    assert abs(hb["ping"]["interval_s_median"] - 1.0) < 0.01


def test_schema_confidence_tiers(tmp_path):
    frames = _frames(tmp_path)
    schemas = infer(frames, min_samples=3)
    assert "method:ping" in schemas
    ping = schemas["method:ping"]
    # 5 samples, single field, stable type => Verified
    assert ping["fields"][0]["confidence"] == "Verified"
    # login has 1 sample => Unknown
    assert schemas["method:login"]["overall_confidence"] in ("Unknown", "Likely")


def test_command_key_from_method_and_opcode():
    assert command_key({"method": "login", "header": {}, "payload": {}}) == "method:login"
    k = command_key({"method": None, "header": {"mtype_name": "answer"}, "payload": {"#1": 12345}})
    assert k in ("op:12345", "anon:answer")


def test_build_writes_artifacts(tmp_path):
    d = str(tmp_path / "s")
    write_session(d, label="login")
    from vantage.protocol.build import build
    out = str(tmp_path / "protocol")
    res = build([d], out, target="synthetic")
    assert res["frames"] == 13 and res["commands"] == 5
    proto = json.load(open(os.path.join(out, "protocol.json")))
    assert proto["target"] == "synthetic"
    assert proto["framing"]["encoding"]["confidence"] == "verified(class)"
    assert os.path.isdir(os.path.join(out, "schemas"))
