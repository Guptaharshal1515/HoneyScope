import json
import os

import pytest

import scenarios
from scenarios import flags

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOADS = json.load(open(os.path.join(BASE, "scenarios", "sqli_login", "scenario.json")))["payloads"]
IDS = [s["id"] for s in scenarios.load_scenarios()]


@pytest.fixture(autouse=True)
def _clean_scores():
    flags.reset()
    yield
    flags.reset()


def _dash(client, creds):
    client.post("/login", data=creds)
    return client.get("/dashboard").get_data(as_text=True)


def test_flags_are_stable_and_unique():
    seen = {flags.flag_for(i, l) for i in IDS for l in flags.FLAG_LEVELS}
    assert len(seen) == len(IDS) * len(flags.FLAG_LEVELS)
    assert flags.flag_for("sqli-login", "low") == flags.flag_for("sqli-login", "low")


def test_secret_changes_flags(monkeypatch):
    before = flags.flag_for("sqli-login", "low")
    monkeypatch.setenv("HONEYSCOPE_FLAG_SECRET", "another")
    assert flags.flag_for("sqli-login", "low") != before


def test_no_flag_for_impossible_level():
    assert "impossible" not in flags.FLAG_LEVELS
    assert flags.submit(flags.flag_for("sqli-login", "impossible"), IDS) is None


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_appears_after_real_bypass_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    assert flags.flag_for("sqli-login", level) in _dash(client, PAYLOADS[level])


def test_no_flag_for_a_normal_login(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    assert "HS{" not in _dash(client, {"username": "admin", "password": "admin123"})


def test_no_flag_when_lab_mode_is_off(client, set_level):
    set_level("low")  # the honeypot must never hand out flags
    assert "HS{" not in _dash(client, PAYLOADS["low"])


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    assert "HS{" not in _dash(client, PAYLOADS["low"])


def test_submit_flow_updates_scoreboard(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    good = flags.flag_for("sqli-login", "medium")
    assert client.post("/lab/flag", data={"flag": "HS{nope}"}).headers["Location"].endswith("msg=bad")
    assert client.post("/lab/flag", data={"flag": good}).headers["Location"].endswith("msg=new")
    assert client.post("/lab/flag", data={"flag": good}).headers["Location"].endswith("msg=dup")
    html = client.get("/lab").get_data(as_text=True)
    assert "1 / 3 flags" in html and "✅" in html
    client.post("/lab/reset")
    assert "0 / 3 flags" in client.get("/lab").get_data(as_text=True)


def test_scoreboard_endpoints_hidden_when_lab_off(client):
    assert client.post("/lab/flag", data={"flag": "x"}).status_code == 404
    assert client.post("/lab/reset").status_code == 404


def test_lab_page_never_prints_flags(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    html = client.get("/lab").get_data(as_text=True)
    assert all(flags.flag_for(i, l) not in html for i in IDS for l in flags.FLAG_LEVELS)
