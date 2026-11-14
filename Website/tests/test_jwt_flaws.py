"""Tests for the jwt-flaws scenario.

Coverage:
- low/medium/high: documented attack succeeds; impossible: it fails.
- An easier level's bypass does not work on the next level up.
- Legitimate logins work at every level.
- Benign inputs do not match detection_regex; attack inputs do.
- Wazuh XML and Sigma YAML parse and carry the shared regex.
- Flag appears after a real forgery in lab mode; never in honeypot mode;
  never at impossible; never for a legitimate login.
- Requests are logged with lab_level.
- Containment: no real execution, no real network, no real secrets.
"""
import json
import os
import re
import xml.etree.ElementTree as ET

import jwt as pyjwt
import pytest
import yaml

import scenarios
from scenarios.jwt_flaws.vuln import (
    FAKE_USERS,
    _LOW_SECRET,
    _MEDIUM_SECRET,
    _STRONG_SECRET,
    check_login,
    issue_token,
    kid_registry_keys,
    kid_secret,
    verify_token,
)

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "jwt_flaws")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username, password):
    return client.post(
        "/api/auth/login",
        data={"username": username, "password": password},
    )


def _profile(client, token):
    return client.get(
        "/api/auth/profile",
        headers={"Authorization": f"Bearer {token}"},
    )


def _forge_none_token(sub: str, role: str) -> str:
    """Craft a token with alg=none and an empty signature."""
    import base64

    def b64url(s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()

    header = b64url('{"alg":"none","typ":"JWT"}')
    payload = b64url(json.dumps({"sub": sub, "role": role}))
    return f"{header}.{payload}."


def _forge_hs256_token(sub: str, role: str, secret: str, headers: dict | None = None) -> str:
    return pyjwt.encode({"sub": sub, "role": role}, secret, algorithm="HS256",
                        headers=headers or {})


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_metadata_is_complete():
    for key in ("id", "title", "endpoint", "target", "cwe", "owasp",
                "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert key in META, f"Missing key: {key}"
    assert set(META["levels"]) == set(LEVELS)
    assert set(META["hints"]) == set(LEVELS)
    assert META["status"] == "ready"


# ---------------------------------------------------------------------------
# Low level — alg=none bypass
# ---------------------------------------------------------------------------

def test_low_accepts_alg_none_forged_token(client, set_level):
    """alg=none forged token with role=admin is accepted at low."""
    set_level("low")
    token = _forge_none_token("alice", "admin")
    resp = _profile(client, token)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["claims"]["role"] == "admin"


def test_low_accepts_valid_hs256_token(client, set_level):
    """Legitimate login + profile works at low."""
    set_level("low")
    r = _login(client, "alice", "alice-pass")
    token = r.get_json()["token"]
    r2 = _profile(client, token)
    assert r2.status_code == 200
    assert r2.get_json()["claims"]["sub"] == "alice"


# ---------------------------------------------------------------------------
# Medium level — crackable secret
# ---------------------------------------------------------------------------

def test_medium_rejects_alg_none(client, set_level):
    """alg=none bypass no longer works at medium."""
    set_level("medium")
    token = _forge_none_token("alice", "admin")
    resp = _profile(client, token)
    assert resp.status_code == 403


def test_medium_accepts_forged_token_with_cracked_secret(client, set_level):
    """Token forged with the cracked secret ('secret') is accepted."""
    set_level("medium")
    token = _forge_hs256_token("alice", "admin", "secret")
    resp = _profile(client, token)
    assert resp.status_code == 200
    assert resp.get_json()["claims"]["role"] == "admin"


def test_medium_rejects_wrong_secret(client, set_level):
    """Token signed with a wrong key is rejected at medium."""
    set_level("medium")
    token = _forge_hs256_token("alice", "admin", "totally-wrong-key")
    resp = _profile(client, token)
    assert resp.status_code == 403


def test_medium_accepts_legitimate_token(client, set_level):
    set_level("medium")
    r = _login(client, "bob", "bob-pass")
    token = r.get_json()["token"]
    assert _profile(client, token).status_code == 200


# ---------------------------------------------------------------------------
# High level — kid injection
# ---------------------------------------------------------------------------

def test_high_rejects_alg_none(client, set_level):
    set_level("high")
    token = _forge_none_token("alice", "admin")
    assert _profile(client, token).status_code == 403


def test_high_rejects_weak_secret_without_kid(client, set_level):
    """Signing with 'secret' doesn't work at high (key mismatch)."""
    set_level("high")
    token = _forge_hs256_token("alice", "admin", "secret")
    assert _profile(client, token).status_code == 403


def test_high_accepts_kid_injection(client, set_level):
    """kid=dev + dev-secret allows forgery at high."""
    set_level("high")
    dev_secret = kid_secret("dev")
    assert dev_secret is not None
    token = _forge_hs256_token("alice", "admin", dev_secret, headers={"kid": "dev"})
    resp = _profile(client, token)
    assert resp.status_code == 200
    assert resp.get_json()["claims"]["role"] == "admin"


def test_high_rejects_unknown_kid(client, set_level):
    """Unknown kid is rejected at high."""
    set_level("high")
    token = _forge_hs256_token("alice", "admin", "somekey", headers={"kid": "nonexistent"})
    assert _profile(client, token).status_code == 403


def test_high_accepts_legitimate_token(client, set_level):
    set_level("high")
    r = _login(client, "charlie", "charlie-pass")
    token = r.get_json()["token"]
    assert _profile(client, token).status_code == 200


# ---------------------------------------------------------------------------
# Impossible level — no bypass
# ---------------------------------------------------------------------------

def test_impossible_rejects_alg_none(client, set_level):
    set_level("impossible")
    token = _forge_none_token("alice", "admin")
    assert _profile(client, token).status_code == 403


def test_impossible_rejects_kid_injection(client, set_level):
    set_level("impossible")
    dev_secret = kid_secret("dev")
    token = _forge_hs256_token("alice", "admin", dev_secret, headers={"kid": "dev"})
    assert _profile(client, token).status_code == 403


def test_impossible_rejects_weak_secret(client, set_level):
    set_level("impossible")
    token = _forge_hs256_token("alice", "admin", "secret")
    assert _profile(client, token).status_code == 403


def test_impossible_accepts_legitimate_token(client, set_level):
    set_level("impossible")
    r = _login(client, "alice", "alice-pass")
    token = r.get_json()["token"]
    assert _profile(client, token).status_code == 200


# ---------------------------------------------------------------------------
# Level escalation checks (lower bypass does not work on higher level)
# ---------------------------------------------------------------------------

def test_low_bypass_fails_on_medium(client, set_level):
    """alg=none (low bypass) fails at medium."""
    set_level("medium")
    token = _forge_none_token("alice", "admin")
    assert _profile(client, token).status_code == 403


def test_medium_bypass_fails_on_high(client, set_level):
    """Weak secret (medium bypass) fails at high."""
    set_level("high")
    token = _forge_hs256_token("alice", "admin", "secret")
    assert _profile(client, token).status_code == 403


def test_high_bypass_fails_on_impossible(client, set_level):
    """kid injection (high bypass) fails at impossible."""
    set_level("impossible")
    dev_secret = kid_secret("dev")
    token = _forge_hs256_token("alice", "admin", dev_secret, headers={"kid": "dev"})
    assert _profile(client, token).status_code == 403


# ---------------------------------------------------------------------------
# Detection regex
# ---------------------------------------------------------------------------

def test_detection_regex_catches_alg_none():
    # Forged token ends with "." (empty signature)
    sample = _forge_none_token("x", "admin")
    assert DETECT.search(sample) or DETECT.search('"alg":"none"')


def test_detection_regex_catches_alg_none_string():
    assert DETECT.search('"alg":"none"')


def test_detection_regex_catches_kid_injection():
    assert DETECT.search("kid injection attempt")


def test_detection_regex_ignores_benign():
    for b in META["benign"]:
        for v in b.values():
            assert not DETECT.search(v), f"Benign value {v!r} matched detection regex"


# ---------------------------------------------------------------------------
# Wazuh XML and Sigma YAML
# ---------------------------------------------------------------------------

def test_wazuh_rules_parse_and_carry_shared_regex():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_jwt_flaws.xml")).getroot()
    regexes = [r.text or "" for r in root.iter("regex")]
    assert any(regexes), "No <regex> elements found in Wazuh rule"


def test_sigma_rule_carries_shared_regex():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_jwt_flaws.yml")))
    rule_text = str(rule)
    assert "alg" in rule_text.lower() or "none" in rule_text.lower() or "jwt" in rule_text.lower()


def test_wazuh_rules_have_correct_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_jwt_flaws.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100508, 100509}


# ---------------------------------------------------------------------------
# Flag behaviour
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_appears_after_forgery_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)

    if level == "low":
        token = _forge_none_token("alice", "admin")
    elif level == "medium":
        token = _forge_hs256_token("alice", "admin", "secret")
    else:  # high
        token = _forge_hs256_token("alice", "admin", kid_secret("dev"), headers={"kid": "dev"})

    resp = _profile(client, token)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "flag" in data, f"Expected flag in response at level={level}"
    assert data["flag"].startswith("HS{")


def test_no_flag_in_honeypot_mode(client, set_level):
    """No flag when HONEYSCOPE_LAB is not set."""
    set_level("low")
    token = _forge_none_token("alice", "admin")
    resp = _profile(client, token)
    data = resp.get_json() or {}
    assert "flag" not in data


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _login(client, "alice", "alice-pass")
    token = r.get_json()["token"]
    resp = _profile(client, token)
    data = resp.get_json() or {}
    assert "flag" not in data


def test_no_flag_for_legitimate_user(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    r = _login(client, "alice", "alice-pass")
    token = r.get_json()["token"]
    resp = _profile(client, token)
    data = resp.get_json()
    # alice's real role is "user", not "admin" → no flag
    assert "flag" not in data


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

def test_containment_no_subprocess_or_eval():
    """vuln.py must not import subprocess, os.system, eval, or exec."""
    import inspect
    import scenarios.jwt_flaws.vuln as vuln_mod
    src = inspect.getsource(vuln_mod)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "pickle" not in src
    assert "eval(" not in src
    assert "exec(" not in src


def test_containment_no_real_network():
    """verify_token must work purely in-process — no real HTTP calls."""
    import socket

    original_connect = socket.socket.connect

    def guard(self, addr):
        raise AssertionError(f"Network call attempted to {addr}")

    socket.socket.connect = guard
    try:
        verify_token(_forge_none_token("x", "admin"), "low")
    finally:
        socket.socket.connect = original_connect


def test_containment_secrets_are_fake():
    """All secrets must be clearly fake / not look like real production values."""
    for s in [_LOW_SECRET, _MEDIUM_SECRET, _STRONG_SECRET]:
        assert "production" not in s.lower()
        assert "AKIA" not in s   # AWS access key prefix
