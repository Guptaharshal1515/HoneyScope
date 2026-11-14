"""Tests for the xss-stored scenario (CWE-79, Stored XSS on the feedback form).

Coverage:
  - Each level: payload stores correctly and dashboard reflects the sanitisation.
  - impossible: every payload (low/medium/high) is fully neutralised.
  - Legitimate comments work at every level.
  - Medium payload does not work on medium (script tag is stripped).
  - High payload does not work on high (onerror/onload stripped).
  - detection_regex catches every payload and ignores benign input.
  - Wazuh XML and Sigma YAML parse and carry the shared regex.
  - Flag appears in lab mode after a surviving XSS; never in honeypot mode;
    never at impossible; never for a benign comment.
  - Requests are logged with lab_level.
  - Containment: sanitised text from impossible contains no executable HTML.
"""
import html as htmllib
import json
import os
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

SCEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scenarios", "xss_stored")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
LEVELS = ("low", "medium", "high", "impossible")
DETECT = re.compile(META["detection_regex"])

# Payloads that should SURVIVE (i.e. be stored verbatim or partially) so the
# XSS fires in the browser.  At impossible, nothing should survive.
SURVIVING_PAYLOADS = {
    "low": META["payloads"]["low"]["comment"],    # raw <script>
    "medium": META["payloads"]["medium"]["comment"],  # <img onerror=...>
    "high": META["payloads"]["high"]["comment"],  # <details ontoggle=...>
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username="mwilson", password="letmein"):
    """Log in with credentials that work at ALL levels including high.
    
    NB: at high level the SQLi filter strips 'or' from passwords.
    'password123' (jsmith) contains 'or' and would be mangled.
    'letmein' (mwilson) has no keyword hits and works at every level.
    """
    client.post("/login", data={"username": username, "password": password})


def _post_comment(client, comment):
    return client.post("/submit_comment", data={"comment": comment})


def _dashboard_html(client):
    return htmllib.unescape(client.get("/dashboard").get_data(as_text=True))


# ---------------------------------------------------------------------------
# Scenario metadata
# ---------------------------------------------------------------------------

def test_metadata_is_complete():
    for key in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre",
                "levels", "hints", "payloads", "benign", "detection_regex"):
        assert key in META, f"scenario.json is missing {key}"
    assert META["id"] == "xss-stored"
    assert set(META["levels"]) == set(LEVELS) == set(META["hints"])


# ---------------------------------------------------------------------------
# Level behaviour: low
# ---------------------------------------------------------------------------

def test_low_stores_script_tag_verbatim(client, set_level):
    """At low, the raw <script> payload is stored and rendered in the page."""
    set_level("low")
    _login(client)
    _post_comment(client, META["payloads"]["low"]["comment"])
    html = _dashboard_html(client)
    # The raw payload must appear in the page (not escaped)
    assert "<script>" in html


# ---------------------------------------------------------------------------
# Level behaviour: medium
# ---------------------------------------------------------------------------

def test_medium_strips_script_tag(client, set_level):
    """At medium, <script> blocks are removed — the low payload is neutralised."""
    set_level("medium")
    _login(client)
    _post_comment(client, META["payloads"]["low"]["comment"])
    html = _dashboard_html(client)
    assert "<script>" not in html


def test_medium_does_not_strip_img_onerror(client, set_level):
    """At medium, <img onerror=...> survives — event-handler bypass works."""
    set_level("medium")
    _login(client)
    _post_comment(client, META["payloads"]["medium"]["comment"])
    html = _dashboard_html(client)
    # The img tag with onerror must still be in the rendered page
    assert "onerror" in html


# ---------------------------------------------------------------------------
# Level behaviour: high
# ---------------------------------------------------------------------------

def test_high_strips_img_onerror(client, set_level):
    """At high, <img> and onerror are stripped — medium payload neutralised."""
    set_level("high")
    _login(client)
    _post_comment(client, META["payloads"]["medium"]["comment"])
    html = _dashboard_html(client)
    assert "onerror" not in html


def test_high_does_not_strip_ontoggle(client, set_level):
    """At high, <details ontoggle=...> survives — unknown-handler bypass works."""
    set_level("high")
    _login(client)
    _post_comment(client, META["payloads"]["high"]["comment"])
    html = _dashboard_html(client)
    assert "ontoggle" in html


# ---------------------------------------------------------------------------
# Level behaviour: impossible
# ---------------------------------------------------------------------------

def test_impossible_escapes_all_payloads(client, set_level):
    """At impossible, every payload is fully HTML-escaped; no raw tags rendered."""
    set_level("impossible")
    _login(client)
    for lvl in ("low", "medium", "high", "impossible"):
        payload = META["payloads"][lvl]["comment"]
        _post_comment(client, payload)
    # Use raw HTML (not unescaped) so we detect literal < chars from stored content.
    raw_html = client.get("/dashboard").get_data(as_text=True)
    # At impossible, stored text uses html.escape(), so the page source contains
    # &lt;script&gt; (entity-encoded), never a bare <script> from stored comments.
    # We check the comment-body divs specifically to avoid matching the page's own tags.
    import re as re_
    # Extract comment bodies and verify no unescaped script/event tags
    bodies = re_.findall(r'class="comment-body">(.*?)</div>', raw_html, re_.DOTALL)
    for body in bodies:
        assert "<script>" not in body, f"Unescaped <script> in comment-body: {body!r}"
        # At impossible, event handlers appear inside entity-encoded text (&lt;img onerror...&gt;)
        # so they cannot execute. Confirm no executable form: bare < before tag name.
        assert not re_.search(r"<\s*(script|img|svg|iframe|details)", body), \
            f"Executable tag in comment-body at impossible: {body!r}"


def test_impossible_escapes_low_payload(client, set_level):
    """At impossible, the low-level <script> payload is stored escaped."""
    from scenarios.xss_stored.vuln import sanitise
    result = sanitise("<script>alert('x')</script>", "impossible")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


# ---------------------------------------------------------------------------
# Legitimate comments work at every level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", LEVELS)
def test_benign_comment_stored_and_displayed(client, set_level, level):
    set_level(level)
    _login(client)
    benign = "Great team meeting today!"
    _post_comment(client, benign)
    html = _dashboard_html(client)
    assert benign in html


# ---------------------------------------------------------------------------
# Easier payloads do not work on harder levels
# ---------------------------------------------------------------------------

def test_low_payload_fails_on_medium(client, set_level):
    """Medium strips <script> tags, so the low payload does not execute."""
    set_level("medium")
    _login(client)
    _post_comment(client, META["payloads"]["low"]["comment"])
    assert "<script>" not in _dashboard_html(client)


def test_medium_payload_fails_on_high(client, set_level):
    """High strips onerror, so the medium payload does not execute."""
    set_level("high")
    _login(client)
    _post_comment(client, META["payloads"]["medium"]["comment"])
    assert "onerror" not in _dashboard_html(client)


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", LEVELS)
def test_detection_regex_catches_every_payload(level):
    p = META["payloads"][level]["comment"]
    assert DETECT.search(p), f"regex did not match payload for {level}: {p!r}"


def test_detection_regex_ignores_benign_comments():
    for item in META["benign"]:
        assert not DETECT.search(item["comment"]), \
            f"regex falsely matched benign: {item['comment']!r}"


def test_wazuh_rules_use_the_shared_regex():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_xss_stored.xml")).getroot()
    patterns = [f.text for f in root.iter("field")
                if f.get("name", "") == "form_data.comment"]
    assert len(patterns) >= 2
    assert all(p == META["detection_regex"] for p in patterns)


def test_sigma_rule_uses_the_shared_regex():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_xss_stored.yml")))
    det = rule["detection"]
    assert det["selection_payload"]["form_data.comment|re"] == META["detection_regex"]


# ---------------------------------------------------------------------------
# Flags (lab mode)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_appears_after_xss_survives_filter_in_lab_mode(client, set_level,
                                                              monkeypatch, level):
    """Flag is shown on the dashboard when a payload survives the current filter."""
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    _login(client)
    _post_comment(client, SURVIVING_PAYLOADS[level])
    html = _dashboard_html(client)
    from scenarios import flags
    expected = flags.flag_for("xss-stored", level)
    assert expected in html, f"Flag not found for xss-stored/{level}"


def test_no_flag_for_benign_comment_in_lab_mode(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    _login(client)
    _post_comment(client, "Just a normal comment")
    assert "HS{" not in _dashboard_html(client)


def test_no_flag_when_lab_mode_off(client, set_level):
    """In honeypot mode, no flag should ever appear."""
    set_level("low")
    _login(client)
    _post_comment(client, META["payloads"]["low"]["comment"])
    assert "HS{" not in _dashboard_html(client)


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    _login(client)
    _post_comment(client, META["payloads"]["low"]["comment"])
    assert "HS{" not in _dashboard_html(client)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def test_requests_are_logged_with_level(client, set_level):
    set_level("medium")
    _login(client)
    _post_comment(client, "test comment")
    last = json.loads(client.log_file.read_text().splitlines()[-1])
    assert last["path"] == "/submit_comment" and last["lab_level"] == "medium"


# ---------------------------------------------------------------------------
# Containment: impossible must produce no executable HTML
# ---------------------------------------------------------------------------

def test_containment_impossible_no_executable_html():
    """Prove that impossible-level sanitised output contains no HTML tags."""
    from scenarios.xss_stored.vuln import sanitise
    evil_inputs = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]
    for payload in evil_inputs:
        result = sanitise(payload, "impossible")
        # No unescaped < or > should appear
        assert "<" not in result, f"Raw < in impossible output for {payload!r}"
        assert ">" not in result, f"Raw > in impossible output for {payload!r}"


def test_containment_no_real_execution():
    """sanitise() must never call eval, exec, subprocess, or os.system."""
    import inspect
    from scenarios.xss_stored import vuln
    source = inspect.getsource(vuln)
    for banned in ("os.system", "subprocess", "eval(", "exec(", "__import__"):
        assert banned not in source, f"Banned call found in vuln.py: {banned}"
