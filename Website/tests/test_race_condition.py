"""Tests for the race-condition scenario."""
import concurrent.futures
import json
import os
import re
import xml.etree.ElementTree as ET
import pytest
import yaml

import scenarios
from scenarios.race_condition.vuln import get_balance, reset_user

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "race_condition")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


def _apply(client, coupon, user_id=1):
    return client.post("/api/coupon/apply", data=json.dumps({"coupon": coupon, "user_id": user_id}), content_type="application/json")


def _run_concurrent_applies(client, coupon="PROMO50", count=5, user_id=1):
    reset_user(user_id)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as ex:
        futures = [ex.submit(_apply, client, coupon, user_id) for _ in range(count)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
    return results


def test_metadata_complete():
    for k in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Level low ---
def test_low_race_condition_succeeds(client, set_level):
    set_level("low")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    successes = [r for r in results if r.status_code == 200]
    # At low, at least 2 requests pass the check
    assert len(successes) >= 2
    assert get_balance(1) >= 200


# --- Level medium ---
def test_medium_race_condition_succeeds(client, set_level):
    set_level("medium")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    successes = [r for r in results if r.status_code == 200]
    assert len(successes) >= 2
    assert get_balance(1) >= 200


# --- Level high ---
def test_high_race_condition_succeeds(client, set_level):
    set_level("high")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    successes = [r for r in results if r.status_code == 200]
    assert len(successes) >= 2
    assert get_balance(1) >= 200


# --- Level impossible ---
def test_impossible_race_condition_fails(client, set_level):
    set_level("impossible")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    successes = [r for r in results if r.status_code == 200]
    # At impossible, exactly 1 request succeeds
    assert len(successes) == 1
    assert get_balance(1) == 150


def test_legitimate_single_coupon(client, set_level):
    for lvl in LEVELS:
        set_level(lvl)
        reset_user(1)
        r = _apply(client, "WELCOME10", 1)
        assert r.status_code == 200
        assert r.get_json()["balance"] == 110


def test_invalid_coupon(client, set_level):
    set_level("low")
    r = _apply(client, "INVALID_CODE_999", 1)
    assert r.status_code == 400


# --- Detection regex ---
def test_detect_promo_coupon():
    assert DETECT.search("PROMO50")
    assert DETECT.search("SAVE50")
    assert DETECT.search("double spend")


def test_detect_ignores_benign():
    for b in META["benign"]:
        assert not DETECT.search(b["coupon"])


# --- Wazuh & Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_race_condition.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100522, 100523}


def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_race_condition.yml")))
    assert "race" in str(r).lower() or "coupon" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flags_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    flags_found = [r.get_json().get("flag") for r in results if r.get_json() and "flag" in r.get_json()]
    assert len(flags_found) > 0, f"No flag found at level {level}"
    assert flags_found[0].startswith("HS{race-condition:")


def test_no_flag_in_honeypot_mode(client, set_level):
    set_level("low")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    flags_found = [r.get_json().get("flag") for r in results if r.get_json() and "flag" in r.get_json()]
    assert len(flags_found) == 0


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    results = _run_concurrent_applies(client, "PROMO50", count=5, user_id=1)
    flags_found = [r.get_json().get("flag") for r in results if r.get_json() and "flag" in r.get_json()]
    assert len(flags_found) == 0


# --- Containment ---
def test_containment_no_real_exec():
    import inspect
    import scenarios.race_condition.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "eval(" not in src
    assert "exec(" not in src
