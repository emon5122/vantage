import os
import sys

# Allow running the suite without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import pytest  # noqa: E402


@pytest.fixture
def synth_session(tmp_path):
    """A synthetic FPNN capture session directory (frames.jsonl + connections.json)."""
    from vantage.protocol.synthetic import write_session
    d = tmp_path / "session"
    write_session(str(d), label="login")
    return str(d)


@pytest.fixture
def kb(tmp_path):
    from vantage.kb.db import open_db
    db = open_db(str(tmp_path / "kb.db"))
    yield db
    db.close()
