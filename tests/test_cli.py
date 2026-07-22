"""Smoke tests for the unified CLI dispatch (observation-only)."""
import json
import os

from vantage.cli import main


def test_version(capsys):
    assert main(["version"]) == 0
    assert "vantage" in capsys.readouterr().out


def test_plugins_list(capsys, monkeypatch, tmp_path):
    # point plugin discovery at the repo's example plugin dir
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    monkeypatch.setenv("VANTAGE_PLUGINS_DIR", os.path.join(repo, "plugins"))
    assert main(["plugins", "list"]) == 0
    assert "example-classifier-rules" in capsys.readouterr().out


def test_protocol_synth_and_build(tmp_path, capsys):
    sess = str(tmp_path / "sess")
    assert main(["protocol", "synth", sess, "--label", "login"]) == 0
    assert os.path.exists(os.path.join(sess, "frames.jsonl"))
    out = str(tmp_path / "proto")
    assert main(["protocol", "build", sess, "--out", out, "--target", "t"]) == 0
    proto = json.load(open(os.path.join(out, "protocol.json")))
    assert proto["target"] == "t"


def test_kb_pipeline_via_cli(tmp_path, capsys):
    db = str(tmp_path / "kb.db")
    sess = str(tmp_path / "sess")
    main(["protocol", "synth", sess, "--label", "login"])
    capsys.readouterr()
    assert main(["kb", "--db", db, "import", sess, "--version", "1.0.0", "--label", "login", "--no-docs"]) == 0
    assert "imported" in capsys.readouterr().out
    assert main(["kb", "--db", db, "search", "field", "#1"]) == 0
    out = capsys.readouterr().out
    assert "method:ping" in out and "Verified" in out
