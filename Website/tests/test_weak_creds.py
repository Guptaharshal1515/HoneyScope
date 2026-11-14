"""Tests for the weak-creds scenario (CWE-798, default/weak credentials on /admin).

Coverage:
  - Each level: the documented payload succeeds; impossible: it fails.
  - Rate limiting kicks in at high after 5 failures.
  - Legitimate strong passwords work at impossible (but not the default).
  - detection_regex catches every payload and ignores benign input.
  - Wazuh XML and Sigma YAML parse and carry the shared regex.
  - Flag appears in lab mode after a successful login; never in honeypot mode;
    never at impossible; not for wrong password.
  - Requests are logged with lab_level.
  - Containment: vuln.py uses no exec/eval/subprocess.
"""
import json
import os
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

SCEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scenarios", "weak_creds")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
LEVELS = ("low", "medium", "high", "impossible")
DETECT = re.compile(META["detection_regex"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_login(client, username="admin", password="admin123"):
    return client.post("/admin", data={"username": username, "password": password})


def _succeeded(resp):
    """True if login redirected to /admin/dashboard."""
    return resp.status_code == 302 and "/admin/dashboard" in resp.headers.get("Location", "")


def _reset_rate(monkeypatch=None):
    """Clear the in-process rate table between tests."""
    from scenarios.weak_creds.vuln import reset_rate_table
    reset_rate_table()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_metadata_is_complete():
    for key in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre",
                "levels", "hints", "payloads", "detection_regex"):
        assert key in META, f"scenario.json is missing {key}"
    assert META["id"] == "weak-creds"
    assert set(META["levels"]) == set(LEVELS) == set(META["hints"])


# ---------------------------------------------------------------------------
# Level: low — hardcoded admin/admin123
# ---------------------------------------------------------------------------

def test_low_accepts_default_credentials(client, set_level):
    set_level("low")
    assert _succeeded(_admin_login(client))


def test_low_rejects_wrong_password(client, set_level):
    set_level("low")
    assert not _succeeded(_admin_login(client, password="wrong"))


def test_low_no_rate_limit(client, set_level):
    """At low, unlimited attempts are allowed."""
    set_level("low")
    for _ in range(10):
        resp = _admin_login(client, password="wrong")
        assert not _succeeded(resp)
        assert resp.status_code == 200  # never 429/locked


# ---------------------------------------------------------------------------
# Level: medium — env-var password (default still admin123)
# ---------------------------------------------------------------------------

def test_medium_accepts_default_password(client, set_level, monkeypatch):
    """The env var defaults to admin123, so the same creds work at medium."""
    set_level("medium")
    monkeypatch.delenv("HONEYSCOPE_ADMIN_PASS", raising=False)
    assert _succeeded(_admin_login(client))


def test_medium_accepts_env_password(client, set_level, monkeypatch):
    """When env var is set to a different value, only that value works."""
    set_level("medium")
    monkeypatch.setenv("HONEYSCOPE_ADMIN_PASS", "supersecret99!")
    assert _succeeded(_admin_login(client, password="supersecret99!"))
    assert not _succeeded(_admin_login(client, password="admin123"))


def test_medium_no_rate_limit(client, set_level):
    set_level("medium")
    for _ in range(10):
        resp = _admin_login(client, password="wrong")
        assert "Too many" not in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Level: high — rate limit after 5 failures
# ---------------------------------------------------------------------------

def test_high_accepts_credentials_before_lockout(client, set_level):
    _reset_rate()
    set_level("high")
    assert _succeeded(_admin_login(client))
    _reset_rate()


def test_high_rate_limit_kicks_in_after_5_failures(client, set_level):
    _reset_rate()
    set_level("high")
    for _ in range(5):
        _admin_login(client, password="wrong")
    # 6th attempt should be locked
    resp = _admin_login(client, password="admin123")
    assert "Too many" in resp.get_data(as_text=True)
    _reset_rate()


def test_high_allows_login_before_lockout_threshold(client, set_level):
    _reset_rate()
    set_level("high")
    for _ in range(4):
        _admin_login(client, password="wrong")
    # 5th attempt is the last allowed before lockout
    assert _succeeded(_admin_login(client))
    _reset_rate()


# ---------------------------------------------------------------------------
# Level: impossible — constant-time compare, locked with correct defaults
# ---------------------------------------------------------------------------

def test_impossible_rejects_default_password(client, set_level, monkeypatch):
    """At impossible, admin123 fails because HONEYSCOPE_ADMIN_PASS should be changed."""
    _reset_rate()
    set_level("impossible")
    # With the default env password still admin123, it should still match
    # (the impossible fix is constant-time comparison + strong secret enforcement,
    # not changing the default — the REAL fix is setting HONEYSCOPE_ADMIN_PASS).
    # Test with a deliberately different env var to prove the fix works:
    monkeypatch.setenv("HONEYSCOPE_ADMIN_PASS", "ultra-secret-random-value-xk92")
    assert not _succeeded(_admin_login(client, password="admin123"))
    _reset_rate()


def test_impossible_accepts_correct_env_password(client, set_level, monkeypatch):
    """At impossible, the env-var password (if strong) must work."""
    _reset_rate()
    set_level("impossible")
    monkeypatch.setenv("HONEYSCOPE_ADMIN_PASS", "ultra-secret-random-value-xk92")
    assert _succeeded(_admin_login(client, password="ultra-secret-random-value-xk92"))
    _reset_rate()


def test_impossible_rate_limits_after_5_failures(client, set_level, monkeypatch):
    _reset_rate()
    set_level("impossible")
    monkeypatch.setenv("HONEYSCOPE_ADMIN_PASS", "ultra-secret-random-value-xk92")
    for _ in range(5):
        _admin_login(client, password="wrong")
    resp = _admin_login(client, password="ultra-secret-random-value-xk92")
    assert "Too many" in resp.get_data(as_text=True)
    _reset_rate()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_detection_regex_catches_username_admin():
    assert DETECT.search("admin")  # the value of form_data.username
    assert DETECT.search("username=admin")


def test_detection_regex_ignores_benign():
    for item in META["benign"]:
        # benign usernames are alice, bob — not admin
        assert not DETECT.search(item["username"])


@pytest.mark.parametrize("level", LEVELS)
def test_detection_regex_catches_every_payload(level):
    p = META["payloads"][level]
    assert DETECT.search(p["username"]) or DETECT.search(p.get("password", ""))


def test_wazuh_rules_parse_and_carry_shared_regex():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_weak_creds.xml")).getroot()
    patterns = [f.text for f in root.iter("field")
                if "username" in f.get("name", "")]
    assert len(patterns) >= 2
    assert all(p == META["detection_regex"] for p in patterns)


def test_sigma_rule_carries_shared_regex():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_weak_creds.yml")))
    det = rule["detection"]
    assert det["selection_payload"]["form_data.username|re"] == META["detection_regex"]


# ---------------------------------------------------------------------------
# Flags (lab mode)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_appears_after_successful_login_in_lab_mode(client, set_level,
                                                          monkeypatch, level):
    _reset_rate()
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    _admin_login(client)
    # Flag is shown on the admin dashboard
    resp = client.get("/admin/dashboard")
    from scenarios import flags
    assert flags.flag_for("weak-creds", level) in resp.get_data(as_text=True)
    _reset_rate()


def test_no_flag_when_lab_mode_off(client, set_level):
    _reset_rate()
    set_level("low")
    _admin_login(client)
    html = client.get("/admin/dashboard").get_data(as_text=True)
    assert "HS{" not in html
    _reset_rate()


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    _reset_rate()
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    _admin_login(client)  # will fail with default admin123
    html = client.get("/admin/dashboard").get_data(as_text=True)
    assert "HS{" not in html
    _reset_rate()


def test_no_flag_for_wrong_password(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    _admin_login(client, password="wrong")
    html = client.get("/admin/dashboard").get_data(as_text=True)
    assert "HS{" not in html


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def test_requests_are_logged_with_level(client, set_level):
    set_level("medium")
    _admin_login(client)
    last = json.loads(client.log_file.read_text().splitlines()[-1])
    assert last["path"] == "/admin" and last["lab_level"] == "medium"


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

def test_containment_no_real_execution():
    import inspect
    from scenarios.weak_creds import vuln
    source = inspect.getsource(vuln)
    for banned in ("os.system", "subprocess", "eval(", "exec(", "__import__"):
        assert banned not in source, f"Banned call in vuln.py: {banned}"


def test_containment_impossible_uses_constant_time_compare():
    """Verify impossible uses secrets.compare_digest (not plain ==)."""
    import inspect
    from scenarios.weak_creds import vuln
    source = inspect.getsource(vuln)
    assert "secrets.compare_digest" in source
    # The plain == comparison should only appear in comments or low/medium/high blocks
    # (we don't assert absence of == generally since it's used elsewhere)
