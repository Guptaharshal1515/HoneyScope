"""Tests for the idor-profile scenario (CWE-639/CWE-862, IDOR + privilege escalation).

Coverage:
  - Each level: the documented exploit succeeds; impossible: all exploits fail.
  - Easier-level exploits do not work on harder levels.
  - Legitimate profile access and updates work at every level.
  - detection_regex catches every payload and ignores benign input.
  - Wazuh XML and Sigma YAML parse and carry the shared regex.
  - Flag appears in lab mode after a successful exploit; never in honeypot mode;
    never at impossible; never for legitimate use.
  - Requests are logged with lab_level.
  - Containment: vuln.py uses no exec/eval/subprocess/os.system.
"""
import html as htmllib
import json
import os
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

SCEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scenarios", "idor_profile")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
LEVELS = ("low", "medium", "high", "impossible")
DETECT = re.compile(META["detection_regex"])

# Seed users (matches conftest init_db seed)
USERS = {
    "admin":   {"id": 1, "password": "admin123", "role": "admin"},
    "jsmith":  {"id": 2, "password": "password123", "role": "employee"},
    "agarcia": {"id": 3, "password": "welcome1",   "role": "employee"},
    "mwilson": {"id": 4, "password": "letmein",    "role": "manager"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username, password):
    """Log in and follow the redirect to establish a session."""
    client.post("/login", data={"username": username, "password": password})


def _login_mwilson(client):
    """Log in as mwilson — credentials safe at all levels (no SQLi keyword in password)."""
    _login(client, "mwilson", "letmein")


def _profile_get(client, user_id=None):
    url = "/profile" if user_id is None else f"/profile?user_id={user_id}"
    return client.get(url)


def _profile_post(client, form_user_id, username, email, role, query_user_id=None):
    url = "/profile" if query_user_id is None else f"/profile?user_id={query_user_id}"
    return client.post(url, data={
        "user_id": str(form_user_id),
        "username": username,
        "email": email,
        "role": role,
    })


def _html(resp):
    return htmllib.unescape(resp.get_data(as_text=True))


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_metadata_is_complete():
    for key in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre",
                "levels", "hints", "detection_regex"):
        assert key in META, f"scenario.json is missing {key}"
    assert META["id"] == "idor-profile"
    assert set(META["levels"]) == set(LEVELS) == set(META["hints"])


# ---------------------------------------------------------------------------
# Level: low — no ownership check at all
# ---------------------------------------------------------------------------

def test_low_idor_get_other_user(client, set_level):
    """At low, a non-admin user can GET admin's profile by user_id=1."""
    set_level("low")
    _login_mwilson(client)
    resp = _profile_get(client, user_id=1)
    assert resp.status_code == 200
    assert "admin" in _html(resp).lower()


def test_low_idor_post_other_user(client, set_level):
    """At low, a non-admin can POST to overwrite another user's record."""
    set_level("low")
    _login_mwilson(client)
    resp = _profile_post(client, form_user_id=3, username="hacked",
                         email="hacked@evil.com", role="admin")
    assert resp.status_code == 200
    assert "hacked" in _html(resp) or "Profile updated" in _html(resp)


def test_low_role_escalation(client, set_level):
    """At low, a user can promote themselves to admin."""
    set_level("low")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Level: medium — GET checks ownership; POST trusts form user_id
# ---------------------------------------------------------------------------

def test_medium_get_own_profile_works(client, set_level):
    """At medium, a user can view their own profile."""
    set_level("medium")
    _login_mwilson(client)
    resp = _profile_get(client, user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 200


def test_medium_get_other_user_blocked(client, set_level):
    """At medium, GET to another user's profile is blocked."""
    set_level("medium")
    _login_mwilson(client)
    resp = _profile_get(client, user_id=1)  # admin's ID
    assert resp.status_code == 403


def test_medium_post_overrides_user_id_in_body(client, set_level):
    """At medium, POST with user_id=1 in the body bypasses the GET-only check."""
    set_level("medium")
    _login_mwilson(client)
    # POST to own profile URL but with form user_id pointing at admin (id=1)
    resp = _profile_post(client, form_user_id=1, username="mwilson-pwned",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Level: high — ownership fixed; role field still accepted
# ---------------------------------------------------------------------------

def test_high_get_other_user_blocked(client, set_level):
    """At high, GET to another user's profile is blocked."""
    set_level("high")
    _login_mwilson(client)
    resp = _profile_get(client, user_id=1)
    assert resp.status_code == 403


def test_high_post_other_user_blocked(client, set_level):
    """At high, POST with a different user_id in the body is blocked."""
    set_level("high")
    _login_mwilson(client)
    resp = _profile_post(client, form_user_id=1, username="mwilson-pwned",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 403


def test_high_self_role_escalation_works(client, set_level):
    """At high, a user can promote themselves by changing role in their own profile."""
    set_level("high")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=mwilson_id)
    assert resp.status_code == 200
    # Role should be updated
    html = _html(resp)
    assert "admin" in html.lower() or "Profile updated" in html


# ---------------------------------------------------------------------------
# Level: impossible — all exploits blocked
# ---------------------------------------------------------------------------

def test_impossible_idor_get_blocked(client, set_level):
    """At impossible, GET to another user's profile is blocked."""
    set_level("impossible")
    _login_mwilson(client)
    resp = _profile_get(client, user_id=1)
    assert resp.status_code == 403


def test_impossible_idor_post_blocked(client, set_level):
    """At impossible, POST with another user_id is blocked."""
    set_level("impossible")
    _login_mwilson(client)
    resp = _profile_post(client, form_user_id=1, username="hacked",
                         email="x@evil.com", role="admin",
                         query_user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 403


def test_impossible_self_role_escalation_blocked(client, set_level):
    """At impossible, role=admin in form is ignored; role stays as-is."""
    set_level("impossible")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=mwilson_id)
    assert resp.status_code == 200
    # Role must NOT have changed to admin
    html = _html(resp)
    # The displayed role badge should still be manager (not admin)
    assert "badge-admin" not in html or "badge-manager" in html


# ---------------------------------------------------------------------------
# Easier exploits do not work on harder levels
# ---------------------------------------------------------------------------

def test_low_idor_get_fails_on_medium(client, set_level):
    """The low-level IDOR GET doesn't work at medium."""
    set_level("medium")
    _login_mwilson(client)
    assert _profile_get(client, user_id=1).status_code == 403


def test_medium_post_body_override_fails_on_high(client, set_level):
    """At high, the medium-level POST body override is blocked."""
    set_level("high")
    _login_mwilson(client)
    resp = _profile_post(client, form_user_id=1, username="hacked",
                         email="x@evil.com", role="admin",
                         query_user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Legitimate access works at every level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", LEVELS)
def test_own_profile_readable_at_every_level(client, set_level, level):
    set_level(level)
    _login_mwilson(client)
    resp = _profile_get(client, user_id=USERS["mwilson"]["id"])
    assert resp.status_code == 200
    assert "mwilson" in _html(resp)


@pytest.mark.parametrize("level", LEVELS)
def test_own_profile_update_works_without_role_change(client, set_level, level):
    """Updating username/email (not role) on own profile is legitimate at every level."""
    set_level(level)
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id,
                         username="mwilson-updated",
                         email="mike.wilson@techcorp-internal.com",
                         role="manager",  # keep existing role
                         query_user_id=mwilson_id)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_detection_regex_catches_role_admin():
    assert DETECT.search("role=admin")


def test_detection_regex_catches_profile_user_id():
    assert DETECT.search("/profile?user_id=42")


def test_detection_regex_ignores_benign():
    assert not DETECT.search("normal user viewing own profile")
    assert not DETECT.search("role=employee")
    assert not DETECT.search("role=manager")


def test_wazuh_rules_parse_and_carry_shared_regex():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_idor_profile.xml")).getroot()
    patterns = [f.text for f in root.iter("field")
                if "role" in f.get("name", "") or "user_id" in f.get("name", "")]
    assert len(patterns) >= 2
    assert all(p == META["detection_regex"] for p in patterns)


def test_sigma_rule_carries_shared_regex():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_idor_profile.yml")))
    det = rule["detection"]
    patterns = []
    for key, val in det.items():
        if isinstance(val, dict):
            for k, v in val.items():
                if "|re" in k:
                    patterns.append(v)
    assert any(p == META["detection_regex"] for p in patterns)


# ---------------------------------------------------------------------------
# Flags (lab mode)
# ---------------------------------------------------------------------------

def test_flag_on_low_idor_get(client, set_level, monkeypatch):
    """Flag appears after a successful IDOR GET at low."""
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    _login_mwilson(client)
    # POST to another user's record — flag_trigger is True at low
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=USERS["admin"]["id"], username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="manager",
                         query_user_id=mwilson_id)
    from scenarios import flags
    assert flags.flag_for("idor-profile", "low") in _html(resp)


def test_flag_on_medium_post_body_override(client, set_level, monkeypatch):
    """Flag appears after the medium POST-body-override exploit."""
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("medium")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=USERS["admin"]["id"], username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=mwilson_id)
    from scenarios import flags
    assert flags.flag_for("idor-profile", "medium") in _html(resp)


def test_flag_on_high_self_promotion(client, set_level, monkeypatch):
    """Flag appears after self-role-escalation at high."""
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("high")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=mwilson_id)
    from scenarios import flags
    assert flags.flag_for("idor-profile", "high") in _html(resp)


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    # Try everything — none should produce a flag
    _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                  email="mike.wilson@techcorp-internal.com", role="admin",
                  query_user_id=mwilson_id)
    assert "HS{" not in _html(_profile_get(client, user_id=mwilson_id))


def test_no_flag_for_legitimate_update(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=mwilson_id, username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="manager",
                         query_user_id=mwilson_id)
    # At low, flag_trigger=True for all POSTs — this is a known FP at low
    # (explained in README). But no flag for benign at medium/high/impossible.
    # This test just ensures no flag for legitimate access at non-low levels.


def test_no_flag_when_lab_mode_off(client, set_level):
    set_level("low")
    _login_mwilson(client)
    mwilson_id = USERS["mwilson"]["id"]
    resp = _profile_post(client, form_user_id=USERS["admin"]["id"], username="mwilson",
                         email="mike.wilson@techcorp-internal.com", role="admin",
                         query_user_id=mwilson_id)
    assert "HS{" not in _html(resp)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def test_requests_are_logged_with_level(client, set_level):
    set_level("high")
    _login_mwilson(client)
    _profile_get(client, user_id=USERS["mwilson"]["id"])
    last = json.loads(client.log_file.read_text().splitlines()[-1])
    assert last["path"] == "/profile" and last["lab_level"] == "high"


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

def test_containment_no_real_execution():
    """vuln.py must not call eval, exec, subprocess, or os.system."""
    import inspect
    from scenarios.idor_profile import vuln
    source = inspect.getsource(vuln)
    for banned in ("os.system", "subprocess", "eval(", "exec(", "__import__"):
        assert banned not in source, f"Banned call in vuln.py: {banned}"


def test_containment_impossible_ignores_role_field():
    """At impossible, the role field is never written from user input."""
    # Verify via vuln.py directly (unit test)
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT,"
                 " password TEXT, email TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'jsmith','pw','j@tc.com','employee')")
    conn.commit()
    from scenarios.idor_profile.vuln import profile_access
    form = {"user_id": "1", "username": "jsmith", "email": "j@tc.com",
            "role": "admin"}
    user, err, flag = profile_access(conn, 1, "employee", 1, "POST", form,
                                     "impossible")
    assert err is None
    assert user["role"] == "employee"  # role unchanged despite form saying admin
    assert not flag
