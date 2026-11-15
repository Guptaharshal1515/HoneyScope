"""Tests for the cmd-inject scenario."""
import json
import os
import re
import xml.etree.ElementTree as ET
import pytest
import yaml

import scenarios

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "cmd_inject")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


def _post_cmd(client, target):
    return client.post("/api/cmd", data=json.dumps({"target": target}), content_type="application/json")


def _get_file(client, name):
    return client.get(f"/api/file?name={name}")


def _post_xml(client, xml_str):
    return client.post("/api/xml", data=xml_str, content_type="application/xml")


def test_metadata_complete():
    for k in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Command Injection ---
def test_low_cmd_inject_semicolon(client, set_level):
    set_level("low")
    r = _post_cmd(client, "127.0.0.1; whoami")
    assert r.status_code == 200
    data = r.get_json()
    assert "techcorp" in data["simulated_output"]
    assert data["injected_cmd"] == "whoami"


def test_medium_cmd_blocks_semicolon(client, set_level):
    set_level("medium")
    r = _post_cmd(client, "127.0.0.1; whoami")
    assert r.status_code == 400


def test_medium_cmd_accepts_pipe(client, set_level):
    set_level("medium")
    r = _post_cmd(client, "127.0.0.1 | whoami")
    assert r.status_code == 200
    data = r.get_json()
    assert "techcorp" in data["simulated_output"]


def test_high_cmd_blocks_non_ip(client, set_level):
    set_level("high")
    r = _post_cmd(client, "badhost; whoami")
    assert r.status_code == 400


def test_high_cmd_accepts_ip_with_separator(client, set_level):
    set_level("high")
    r = _post_cmd(client, "127.0.0.1; whoami")
    assert r.status_code == 200
    data = r.get_json()
    assert "techcorp" in data["simulated_output"]


def test_impossible_cmd_blocks_injection(client, set_level):
    set_level("impossible")
    r = _post_cmd(client, "127.0.0.1; whoami")
    assert r.status_code == 400


def test_impossible_cmd_accepts_valid_ip(client, set_level):
    set_level("impossible")
    r = _post_cmd(client, "127.0.0.1")
    assert r.status_code == 200
    assert "icmp_seq" in r.get_json()["simulated_output"]


# --- Path Traversal ---
def test_low_path_traversal(client, set_level):
    set_level("low")
    r = _get_file(client, "../../etc/passwd")
    assert r.status_code == 200
    assert "root:x:0:0" in r.get_json()["content"]


def test_medium_path_traversal_nested(client, set_level):
    set_level("medium")
    # Single-pass replace of ../ removes ../ leaving /etc/passwd
    r = _get_file(client, "....//....//etc/passwd")
    assert r.status_code == 200
    assert "root:x:0:0" in r.get_json()["content"]


def test_high_path_traversal_absolute(client, set_level):
    set_level("high")
    r = _get_file(client, "/etc/passwd")
    assert r.status_code == 200
    assert "root:x:0:0" in r.get_json()["content"]


def test_impossible_path_traversal_blocked(client, set_level):
    set_level("impossible")
    r = _get_file(client, "/etc/passwd")
    assert r.status_code == 400


# --- XXE ---
def test_low_xxe_system_entity(client, set_level):
    set_level("low")
    xml = '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>'
    r = _post_xml(client, xml)
    assert r.status_code == 200
    assert "root:x:0:0" in r.get_json()["result"]


def test_medium_xxe_lowercase_system(client, set_level):
    set_level("medium")
    xml = '<!DOCTYPE foo [<!ENTITY x system "file:///etc/passwd">]><foo>&x;</foo>'
    r = _post_xml(client, xml)
    assert r.status_code == 200
    assert "root:x:0:0" in r.get_json()["result"]


def test_impossible_xxe_blocked(client, set_level):
    set_level("impossible")
    xml = '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>'
    r = _post_xml(client, xml)
    assert r.status_code == 400


# --- Detection regex ---
def test_detect_command_separators():
    assert DETECT.search("127.0.0.1; whoami")
    assert DETECT.search("127.0.0.1 && id")
    assert DETECT.search("cat /etc/passwd")


def test_detect_traversal_and_xxe():
    assert DETECT.search("../../etc/passwd")
    assert DETECT.search("/etc/shadow")
    assert DETECT.search('<!ENTITY x SYSTEM "file:///etc/passwd">')


def test_detect_ignores_benign():
    for b in META["benign"]:
        assert not DETECT.search(b["target"])


# --- Wazuh & Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_cmd_inject.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100520, 100521}


def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_cmd_inject.yml")))
    assert "command" in str(r).lower() or "traversal" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flags_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    if level == "low":
        r = _post_cmd(client, "127.0.0.1; id")
    elif level == "medium":
        r = _post_cmd(client, "127.0.0.1 | whoami")
    else:  # high
        r = _post_cmd(client, "127.0.0.1; whoami")

    assert r.status_code == 200
    data = r.get_json()
    assert "flag" in data
    assert data["flag"].startswith("HS{cmd-inject:")


def test_no_flag_in_honeypot_mode(client, set_level):
    set_level("low")
    r = _post_cmd(client, "127.0.0.1; id")
    data = r.get_json()
    assert "flag" not in data


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _post_cmd(client, "127.0.0.1")
    data = r.get_json()
    assert "flag" not in data


# --- Containment ---
def test_containment_no_real_exec():
    import inspect
    import scenarios.cmd_inject.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "eval(" not in src
    assert "exec(" not in src
