"""Tests for the ssrf scenario."""
import json
import os
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

import scenarios
from scenarios.ssrf.vuln import FAKE_SERVICES, fetch_url, _is_internal_hit

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "ssrf")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS

INTERNAL_URL   = "http://internal-metadata/latest/meta-data/"
INTERNAL_API   = "http://internal-api/secret"
REDIRECT_URL   = "http://redirect-service/"
BENIGN_URL     = "https://example.com/"
MEDIUM_BYPASS  = "http://internal-metadata/latest/meta-data/"  # not in blocklist


def _fetch(client, url):
    return client.post("/api/fetch", data={"url": url})


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_metadata_complete():
    for key in ("id","title","endpoint","target","cwe","owasp","mitre",
                "levels","hints","payloads","detection_regex"):
        assert key in META
    assert set(META["levels"]) == set(LEVELS)
    assert META["status"] == "ready"


# ---------------------------------------------------------------------------
# Low level — no validation
# ---------------------------------------------------------------------------

def test_low_reaches_internal_metadata(client, set_level):
    set_level("low")
    r = _fetch(client, INTERNAL_URL)
    data = r.get_json()
    assert r.status_code == 200
    assert _is_internal_hit(data.get("body")), f"Expected internal hit, got: {data}"


def test_low_reaches_internal_api(client, set_level):
    set_level("low")
    r = _fetch(client, INTERNAL_API)
    assert _is_internal_hit(r.get_json().get("body"))


def test_low_benign_url_works(client, set_level):
    set_level("low")
    r = _fetch(client, BENIGN_URL)
    assert r.status_code == 200
    assert not r.get_json().get("blocked")


# ---------------------------------------------------------------------------
# Medium level — blocklist bypass
# ---------------------------------------------------------------------------

def test_medium_blocks_localhost(client, set_level):
    set_level("medium")
    r = _fetch(client, "http://127.0.0.1/secret")
    assert r.get_json().get("blocked") is True


def test_medium_blocks_169(client, set_level):
    set_level("medium")
    r = _fetch(client, "http://169.254.169.254/latest/meta-data/")
    assert r.get_json().get("blocked") is True


def test_medium_bypassed_via_internal_hostname(client, set_level):
    """http://internal-metadata/ is NOT in blocklist — bypass succeeds."""
    set_level("medium")
    r = _fetch(client, MEDIUM_BYPASS)
    data = r.get_json()
    assert not data.get("blocked")
    assert _is_internal_hit(data.get("body"))


def test_medium_benign_allowed(client, set_level):
    set_level("medium")
    r = _fetch(client, BENIGN_URL)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# High level — open redirect bypass
# ---------------------------------------------------------------------------

def test_high_blocks_internal_directly(client, set_level):
    set_level("high")
    r = _fetch(client, INTERNAL_URL)
    assert r.get_json().get("blocked") is True


def test_high_blocks_non_allowlisted_host(client, set_level):
    set_level("high")
    r = _fetch(client, "https://evil.com/")
    assert r.get_json().get("blocked") is True


def test_high_allowed_host_works(client, set_level):
    set_level("high")
    r = _fetch(client, BENIGN_URL)
    assert r.status_code == 200
    assert not r.get_json().get("blocked")


def test_high_open_redirect_bypass(client, set_level):
    """
    Inject a redirect entry into FAKE_SERVICES under an allowed hostname,
    then fetch that URL — simulates SSRF via open redirect at high level.
    The redirect-service is in fake services but not in allowlist; instead
    we simulate by temporarily patching FAKE_SERVICES.
    """
    set_level("high")
    # Patch: add an allowed-hostname redirect
    FAKE_SERVICES["https://example.com/redirect"] = {
        "_redirect": "http://internal-metadata/latest/meta-data/"
    }
    try:
        r = _fetch(client, "https://example.com/redirect")
        data = r.get_json()
        # The redirect should be followed (high flaw) and hit internal service
        assert not data.get("blocked"), f"Expected bypass, got blocked. Data: {data}"
        assert _is_internal_hit(data.get("body")), f"Expected internal hit, got: {data}"
    finally:
        FAKE_SERVICES.pop("https://example.com/redirect", None)


# ---------------------------------------------------------------------------
# Impossible level — no bypass
# ---------------------------------------------------------------------------

def test_impossible_blocks_internal(client, set_level):
    set_level("impossible")
    assert _fetch(client, INTERNAL_URL).get_json().get("blocked") is True


def test_impossible_blocks_http_scheme(client, set_level):
    set_level("impossible")
    assert _fetch(client, "http://example.com/").get_json().get("blocked") is True


def test_impossible_blocks_redirect(client, set_level):
    set_level("impossible")
    FAKE_SERVICES["https://example.com/redir2"] = {
        "_redirect": "http://internal-metadata/latest/meta-data/"
    }
    try:
        r = _fetch(client, "https://example.com/redir2")
        assert r.get_json().get("blocked") is True
    finally:
        FAKE_SERVICES.pop("https://example.com/redir2", None)


def test_impossible_allows_https_allowlist(client, set_level):
    set_level("impossible")
    r = _fetch(client, BENIGN_URL)
    assert r.status_code == 200
    assert not r.get_json().get("blocked")


# ---------------------------------------------------------------------------
# Level escalation
# ---------------------------------------------------------------------------

def test_low_bypass_fails_on_medium(client, set_level):
    set_level("medium")
    r = _fetch(client, "http://127.0.0.1/secret")
    assert r.get_json().get("blocked") is True


def test_medium_bypass_fails_on_high(client, set_level):
    set_level("high")
    r = _fetch(client, INTERNAL_URL)
    assert r.get_json().get("blocked") is True


def test_high_bypass_fails_on_impossible(client, set_level):
    set_level("impossible")
    FAKE_SERVICES["https://example.com/redir3"] = {
        "_redirect": "http://internal-metadata/latest/meta-data/"
    }
    try:
        r = _fetch(client, "https://example.com/redir3")
        assert r.get_json().get("blocked") is True
    finally:
        FAKE_SERVICES.pop("https://example.com/redir3", None)


# ---------------------------------------------------------------------------
# Detection regex
# ---------------------------------------------------------------------------

def test_detection_catches_internal_metadata():
    assert DETECT.search("http://internal-metadata/latest/meta-data/")


def test_detection_catches_169():
    assert DETECT.search("http://169.254.169.254/")


def test_detection_catches_file_scheme():
    assert DETECT.search("file:///etc/passwd")


def test_detection_ignores_benign():
    for b in META["benign"]:
        for v in b.values():
            assert not DETECT.search(v), f"Benign {v!r} matched detection regex"


# ---------------------------------------------------------------------------
# Wazuh XML and Sigma YAML
# ---------------------------------------------------------------------------

def test_wazuh_parses_and_has_correct_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_ssrf.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100510, 100511}


def test_sigma_parses():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_ssrf.yml")))
    assert "ssrf" in str(rule).lower() or "fetch" in str(rule).lower()


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_on_internal_hit_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)

    if level == "high":
        FAKE_SERVICES["https://example.com/redir4"] = {
            "_redirect": "http://internal-metadata/latest/meta-data/"
        }
        url = "https://example.com/redir4"
    else:
        url = INTERNAL_URL

    try:
        r = _fetch(client, url)
        data = r.get_json()
        assert "flag" in data, f"Expected flag at level={level}, got: {data}"
        assert data["flag"].startswith("HS{")
    finally:
        FAKE_SERVICES.pop("https://example.com/redir4", None)


def test_no_flag_honeypot_mode(client, set_level):
    set_level("low")
    r = _fetch(client, INTERNAL_URL)
    assert "flag" not in (r.get_json() or {})


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _fetch(client, BENIGN_URL)
    assert "flag" not in (r.get_json() or {})


def test_no_flag_for_benign_url(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    r = _fetch(client, BENIGN_URL)
    assert "flag" not in (r.get_json() or {})


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

def test_containment_no_real_network():
    """fetch_url must never make a real network connection."""
    import socket
    orig = socket.socket.connect
    def guard(self, addr):
        raise AssertionError(f"Real network call to {addr}")
    socket.socket.connect = guard
    try:
        fetch_url("http://internal-metadata/latest/meta-data/", "low")
        fetch_url("http://169.254.169.254/", "low")
    finally:
        socket.socket.connect = orig


def test_containment_no_subprocess():
    import inspect
    import scenarios.ssrf.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "urllib.request" not in src
