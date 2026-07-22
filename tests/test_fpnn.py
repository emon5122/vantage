"""Unit tests for the FPNN frame parser + stream reassembly."""
from vantage.protocol.fpnn import parse_message, iter_stream, parse_header, looks_like_fpnn
from vantage.protocol.synthetic import frame, mp, synthetic_session


def test_header_fields():
    f = frame(1, 7, {1: "x"}, method="login")
    h = parse_header(f)
    assert h["magic"] == "FPNN" and h["mtype"] == 1 and h["mtype_name"] == "twoway_quest"
    assert h["flag_msgpack"] is True and h["ss"] == len("login")


def test_parse_quest_roundtrip():
    f = frame(1, 42, {1: "user", 2: 99}, method="login")
    rec, total = parse_message(f)
    assert total == len(f)
    assert rec["method"] == "login" and rec["seq"] == 42
    assert rec["payload"]["#1"] == "user" and rec["payload"]["#2"] == 99
    assert rec["confidence"]["payload_decoded"] == "observed"


def test_parse_answer_has_status():
    f = frame(2, 42, {1: 1}, status=0)
    rec, _ = parse_message(f)
    assert rec["header"]["mtype_name"] == "answer" and rec["status"] == 0 and rec["method"] is None


def test_stream_splits_multiple_frames():
    tx, _, _, _ = synthetic_session()
    recs = [r for r, a, b in iter_stream(tx) if not r.get("desync_skipped")]
    methods = [r["method"] for r in recs]
    assert methods[0] == "login"
    assert methods.count("ping") == 5


def test_incomplete_frame_waits():
    f = frame(1, 1, {1: "x"}, method="login")
    # feed only part of the frame: parser must not yield a complete record
    partial = f[:-3]
    recs = list(iter_stream(partial))
    assert all(r.get("desync_skipped") or False for r, a, b in recs) or recs == []


def test_desync_resync_to_next_magic():
    good = frame(1, 1, {1: "x"}, method="a")
    stream = b"\x00\x01\x02garbage" + good
    got = [r for r, a, b in iter_stream(stream)]
    assert any(r.get("desync_skipped") for r in got)
    assert any(r.get("method") == "a" for r in got)


def test_looks_like_fpnn():
    assert looks_like_fpnn(b"FPNN\x01") is True
    assert looks_like_fpnn(b"HTTP") is False
