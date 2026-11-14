import html as htmllib
import json
import os

import pytest

import scenarios

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_lab_is_hidden_by_default(client):
    assert client.get("/lab").status_code == 404
    assert client.post("/lab/level", data={"level": "high"}).status_code == 404
    assert scenarios.get_level() == "low"  # the POST must not have changed anything


def test_lab_page_lists_scenarios_and_hints(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    resp = client.get("/lab")
    assert resp.status_code == 200
    html = htmllib.unescape(resp.get_data(as_text=True))
    for meta in scenarios.load_scenarios():
        assert meta["title"] in html
        for level in scenarios.LEVELS:
            assert meta["hints"][level] in html


def test_lab_page_does_not_leak_solutions(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    html = htmllib.unescape(client.get("/lab").get_data(as_text=True))
    for meta in scenarios.load_scenarios():
        for payload in meta.get("payloads", {}).values():
            for value in payload.values():
                if len(value) > 3:
                    assert value not in html


@pytest.mark.parametrize("level", scenarios.LEVELS)
def test_switching_level_changes_behaviour(client, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    assert client.post("/lab/level", data={"level": level}).status_code == 302
    assert scenarios.get_level() == level
    assert f'value="{level}" aria-pressed="true"' in client.get("/lab").get_data(as_text=True)


def test_runtime_override_beats_env_var(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    monkeypatch.setenv("HONEYSCOPE_LEVEL", "low")
    client.post("/lab/level", data={"level": "impossible"})
    payload = json.load(open(os.path.join(BASE, "scenarios", "sqli_login", "scenario.json")))["payloads"]["low"]
    resp = client.post("/login", data=payload)
    assert not (resp.status_code == 302 and resp.headers["Location"].endswith("/dashboard"))


def test_unknown_level_is_rejected(client, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    assert client.post("/lab/level", data={"level": "banana"}).status_code == 400
    assert scenarios.get_level() == "low"


def test_every_scenario_json_has_required_fields():
    for meta in scenarios.load_scenarios():
        for key in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints"):
            assert key in meta, f"{meta.get('id')} is missing {key}"
        assert set(meta["levels"]) == set(scenarios.LEVELS) == set(meta["hints"])
