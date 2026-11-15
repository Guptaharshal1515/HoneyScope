"""Tests for the insecure-deserialise scenario."""
import base64
import json
import os
import re
import xml.etree.ElementTree as ET
import pytest
import yaml

import scenarios

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "insecure_deserialise")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


def _post(client, body):
    return client.post("/api/deserialise", data=json.dumps(body), content_type="application/json")


def test_metadata_complete():
    for k in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Level low ---
def test_low_pickle_gadget_succeeds(client, set_level):
    set_level("low")
    payload = "cos\nsystem\n(S'whoami'\ntR."
    r = _post(client, {"payload": payload})
    assert r.status_code == 200
    data = r.get_json()
    assert data["simulated_exec"] is True
    assert "app_user" in data["output"]


def test_low_base64_gadget_succeeds(client, set_level):
    set_level("low")
    b64 = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()
    r = _post(client, {"payload": b64})
    assert r.status_code == 200
    data = r.get_json()
    assert data["simulated_exec"] is True
    assert "uid=" in data["output"]


# --- Level medium ---
def test_medium_blocks_direct_os_system(client, set_level):
    set_level("medium")
    r = _post(client, {"payload": json.dumps({"__class__": "os.system", "cmd": "id"})})
    assert r.status_code == 400
    assert "forbidden" in r.get_json()["error"].lower()


def test_medium_accepts_diagnostic_gadget(client, set_level):
    set_level("medium")
    r = _post(client, {"payload": json.dumps({"__class__": "DiagnosticGadget", "cmd": "whoami"})})
    assert r.status_code == 200
    data = r.get_json()
    assert data["simulated_exec"] is True
    assert "app_user" in data["output"]


# --- Level high ---
def test_high_blocks_untrusted_prefix(client, set_level):
    set_level("high")
    r = _post(client, {"payload": json.dumps({"__class__": "DiagnosticGadget", "cmd": "id"})})
    assert r.status_code == 400
    assert "not allowed" in r.get_json()["error"].lower()


def test_high_accepts_prefix_match_gadget(client, set_level):
    set_level("high")
    r = _post(client, {"payload": json.dumps({"__class__": "SafeConfigGadget_Exec", "cmd": "id"})})
    assert r.status_code == 200
    data = r.get_json()
    assert data["simulated_exec"] is True
    assert "uid=" in data["output"]


# --- Level impossible ---
def test_impossible_ignores_gadgets_and_extracts_primitives(client, set_level):
    set_level("impossible")
    r = _post(client, {"payload": json.dumps({"__class__": "SafeConfigGadget_Exec", "username": "alice", "theme": "dark"})})
    assert r.status_code == 200
    data = r.get_json()
    assert "simulated_exec" not in data
    assert data["data"]["username"] == "alice"
    assert data["data"]["theme"] == "dark"


def test_impossible_rejects_pickle_gadget(client, set_level):
    set_level("impossible")
    r = _post(client, {"payload": "cos\nsystem\n(S'id'\ntR."})
    assert r.status_code == 400


# --- Detection regex ---
def test_detect_pickle():
    assert DETECT.search("cos system")
    assert DETECT.search("c__builtin__ exec")
    assert DETECT.search("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==")


def test_detect_class_gadget():
    assert DETECT.search('{"__class__": "DiagnosticGadget"}')
    assert DETECT.search("SafeConfigGadget")


def test_detect_ignores_benign():
    for b in META["benign"]:
        assert not DETECT.search(b["payload"])


# --- Wazuh & Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_insecure_deserialise.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100518, 100519}


def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_insecure_deserialise.yml")))
    assert "deserializ" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flags_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    if level == "low":
        r = _post(client, {"payload": "cos\nsystem\n(S'id'\ntR."})
    elif level == "medium":
        r = _post(client, {"payload": json.dumps({"__class__": "DiagnosticGadget", "cmd": "whoami"})})
    else:  # high
        r = _post(client, {"payload": json.dumps({"__class__": "SafeConfigGadget_Exec", "cmd": "id"})})

    assert r.status_code == 200
    data = r.get_json()
    assert "flag" in data
    assert data["flag"].startswith("HS{insecure-deserialise:")


def test_no_flag_in_honeypot_mode(client, set_level):
    set_level("low")
    r = _post(client, {"payload": "cos\nsystem\n(S'id'\ntR."})
    data = r.get_json()
    assert "flag" not in data


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _post(client, {"payload": json.dumps({"username": "alice"})})
    data = r.get_json()
    assert "flag" not in data


# --- Containment ---
def test_containment_no_real_exec():
    import inspect
    import scenarios.insecure_deserialise.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "pickle.loads" not in src
    assert "eval(" not in src
    assert "exec(" not in src
