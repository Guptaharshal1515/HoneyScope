import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def client(tmp_path, monkeypatch):
    import app as honeyscope

    monkeypatch.setattr(honeyscope, "DATABASE", str(tmp_path / "test.db"))
    monkeypatch.setattr(honeyscope, "LOG_DIR", str(tmp_path / "logs"))
    honeyscope.init_db()
    honeyscope.app.config["TESTING"] = True
    c = honeyscope.app.test_client()
    c.log_file = tmp_path / "logs" / "access.log"
    return c


@pytest.fixture
def set_level(monkeypatch):
    return lambda level: monkeypatch.setenv("HONEYSCOPE_LEVEL", level)


@pytest.fixture(autouse=True)
def _reset_lab_state(monkeypatch):
    """Keep tests independent: no lab mode and no runtime level override."""
    import scenarios

    monkeypatch.delenv("HONEYSCOPE_LAB", raising=False)
    monkeypatch.delenv("HONEYSCOPE_LEVEL", raising=False)
    scenarios.set_level(None)
    from scenarios import flags
    flags.reset()
    yield
    scenarios.set_level(None)
    flags.reset()
