"""Tests for the graphql-abuse scenario."""
import json
import os
import re
import xml.etree.ElementTree as ET
import pytest
import yaml

import scenarios

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "graphql_abuse")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


def _gql(client, body, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    return client.post("/api/graphql", data=json.dumps(body), headers=h)


def test_metadata_complete():
    for k in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Level low ---
def test_low_introspection_succeeds(client, set_level):
    set_level("low")
    r = _gql(client, {"query": "{ __schema { types { name } } }"})
    assert r.status_code == 200
    data = r.get_json()
    assert "__schema" in data["data"]
    assert len(data["data"]["__schema"]["types"]) > 0


def test_low_admin_data_succeeds(client, set_level):
    set_level("low")
    r = _gql(client, {"query": "{ adminData { secretKey } }"})
    assert r.status_code == 200
    data = r.get_json()
    assert "adminData" in data["data"]
    assert "secretKey" in data["data"]["adminData"]


# --- Level medium ---
def test_medium_introspection_disabled(client, set_level):
    set_level("medium")
    r = _gql(client, {"query": "{ __schema { types { name } } }"})
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data
    assert "introspection is disabled" in data["errors"][0]["message"].lower()


def test_medium_batching_succeeds(client, set_level):
    set_level("medium")
    batch = [
        {"query": "{ me { username } }"},
        {"query": "{ status { version } }"},
    ]
    r = _gql(client, batch)
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert "me" in data[0]["data"]
    assert "status" in data[1]["data"]


# --- Level high ---
def test_high_batching_limit_enforced(client, set_level):
    set_level("high")
    batch = [
        {"query": "{ me { username } }"},
        {"query": "{ status { version } }"},
        {"query": "{ user(id: 1) { name } }"},
    ]
    r = _gql(client, batch)
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data
    assert "batch limit exceeded" in data["errors"][0]["message"].lower()


def test_high_alias_amplification_succeeds(client, set_level):
    set_level("high")
    q = "{ a1: user(id: 1) { name }, a2: user(id: 2) { name }, a3: user(id: 3) { name }, a4: user(id: 4) { name } }"
    r = _gql(client, {"query": q})
    assert r.status_code == 200
    data = r.get_json()
    assert "data" in data
    assert "a1" in data["data"]
    assert "a4" in data["data"]


# --- Level impossible ---
def test_impossible_introspection_disabled(client, set_level):
    set_level("impossible")
    r = _gql(client, {"query": "{ __schema { types { name } } }"})
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data


def test_impossible_batching_disabled(client, set_level):
    set_level("impossible")
    batch = [{"query": "{ me { username } }"}]
    r = _gql(client, batch)
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data
    assert "batch querying is disabled" in data["errors"][0]["message"].lower()


def test_impossible_alias_limit_enforced(client, set_level):
    set_level("impossible")
    q = "{ a1: user(id: 1) { name }, a2: user(id: 2) { name }, a3: user(id: 3) { name }, a4: user(id: 4) { name } }"
    r = _gql(client, {"query": q})
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data
    assert "alias limit exceeded" in data["errors"][0]["message"].lower()


def test_impossible_depth_limit_enforced(client, set_level):
    set_level("impossible")
    deep_q = "{ user(id: 1) { id { name { role { details { value } } } } } }"
    r = _gql(client, {"query": deep_q})
    assert r.status_code == 200
    data = r.get_json()
    assert "errors" in data
    assert "depth limit exceeded" in data["errors"][0]["message"].lower()


# --- Legitimate queries ---
def test_legitimate_queries_succeed_at_all_levels(client, set_level):
    for lvl in LEVELS:
        set_level(lvl)
        r = _gql(client, {"query": "{ user(id: 1) { name } }"})
        assert r.status_code == 200
        data = r.get_json()
        assert "data" in data
        assert data["data"]["user"]["name"] == "Alice Admin"


# --- Detection regex ---
def test_detect_introspection():
    assert DETECT.search("{ __schema { types } }")
    assert DETECT.search("{ __type(name: 'User') }")


def test_detect_sensitive_field():
    assert DETECT.search("{ adminData { secretKey } }")


def test_detect_batching():
    assert DETECT.search('[{"query": "{ me }"}]')


def test_detect_alias():
    assert DETECT.search("{ a1: user(id: 1) }")


def test_detect_ignores_benign():
    for b in META["benign"]:
        assert not DETECT.search(b["query"])


# --- Wazuh & Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_graphql_abuse.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100516, 100517}


def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_graphql_abuse.yml")))
    assert "graphql" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flags_in_lab_mode(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    if level == "low":
        r = _gql(client, {"query": "{ __schema { types { name } } }"})
        data = r.get_json()
        assert "flag" in data
        assert data["flag"].startswith("HS{graphql-abuse:")
    elif level == "medium":
        batch = [{"query": "{ me { username } }"}, {"query": "{ status }"}]
        r = _gql(client, batch)
        data = r.get_json()
        assert isinstance(data, list)
        assert "flag" in data[0]
        assert data[0]["flag"].startswith("HS{graphql-abuse:")
    else:  # high
        q = "{ a1: user(id: 1) { name }, a2: user(id: 2) { name }, a3: user(id: 3) { name }, a4: user(id: 4) { name } }"
        r = _gql(client, {"query": q})
        data = r.get_json()
        assert "flag" in data
        assert data["flag"].startswith("HS{graphql-abuse:")


def test_no_flag_in_honeypot_mode(client, set_level):
    set_level("low")
    r = _gql(client, {"query": "{ __schema { types { name } } }"})
    data = r.get_json()
    assert "flag" not in data


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _gql(client, {"query": "{ user(id: 1) { name } }"})
    data = r.get_json()
    assert "flag" not in data


def test_no_flag_on_benign_at_low(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    r = _gql(client, {"query": "{ user(id: 1) { name } }"})
    data = r.get_json()
    assert "flag" not in data


# --- Containment ---
def test_containment_no_real_exec():
    import inspect
    import scenarios.graphql_abuse.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "eval(" not in src
    assert "exec(" not in src
