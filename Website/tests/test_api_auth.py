"""Tests for the api-auth scenario."""
import json, os, re, xml.etree.ElementTree as ET
import pytest, yaml
import scenarios
from scenarios.api_auth.vuln import FAKE_USERS, check_login, get_user, list_users, check_admin

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "api_auth")
META  = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS


def _login(client, username, password):
    return client.post("/api/users/login", data={"username": username, "password": password})

def _get_user(client, uid, **kwargs):
    headers = kwargs.pop("headers", {})
    return client.get(f"/api/users/{uid}", headers=headers, **kwargs)

def _post_user(client, uid, body):
    return client.post(f"/api/users/{uid}", data=body)

def _list_users(client, **kwargs):
    headers = kwargs.pop("headers", {})
    return client.get("/api/users/", headers=headers, **kwargs)

def _admin(client, **kwargs):
    headers = kwargs.pop("headers", {})
    return client.get("/api/admin/users", headers=headers, **kwargs)


def test_metadata_complete():
    for k in ("id","title","endpoint","target","cwe","owasp","mitre","levels","hints","payloads","detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Low level ---
def test_low_bola_any_user_read(client, set_level):
    set_level("low")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)   # alice reads bob's record
    data = r.get_json()
    assert r.status_code == 200
    assert data["data"]["username"] == "bob"
    assert "salary" in data["data"]

def test_low_bfla_admin_accessible(client, set_level):
    set_level("low")
    _login(client, "alice", "alice-pass")
    r = _admin(client)
    assert r.status_code == 200

def test_low_legit_own_record(client, set_level):
    set_level("low")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 1)
    assert r.status_code == 200


# --- Medium level ---
def test_medium_get_own_record(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 1)
    assert r.status_code == 200

def test_medium_bola_get_blocked(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)   # alice GET bob → blocked
    assert r.status_code == 403

def test_medium_bola_post_body_bypass(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = _post_user(client, 2, {"user_id": "2"})  # override user_id in body
    assert r.status_code == 200
    assert r.get_json()["data"]["username"] == "bob"

def test_medium_bfla_role_query_bypass(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = client.get("/api/admin/users?role=admin")
    assert r.status_code == 200

def test_medium_bfla_blocked_without_role(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = _admin(client)
    assert r.status_code == 403


# --- High level ---
def test_high_individual_record_blocked(client, set_level):
    set_level("high")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)
    assert r.status_code == 403

def test_high_list_leaks_salary(client, set_level):
    set_level("high")
    _login(client, "alice", "alice-pass")
    r = _list_users(client)
    data = r.get_json()
    assert r.status_code == 200
    assert any("salary" in u for u in data["data"])

def test_high_bfla_x_role_bypass(client, set_level):
    set_level("high")
    _login(client, "alice", "alice-pass")
    r = _admin(client, headers={"X-Role": "admin"})
    assert r.status_code == 200


# --- Impossible level ---
def test_impossible_own_record(client, set_level):
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 1)
    assert r.status_code == 200
    assert "salary" not in r.get_json()["data"]

def test_impossible_bola_blocked(client, set_level):
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)
    assert r.status_code == 403

def test_impossible_list_no_salary(client, set_level):
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = _list_users(client)
    assert all("salary" not in u for u in r.get_json()["data"])

def test_impossible_bfla_header_blocked(client, set_level):
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = _admin(client, headers={"X-Role": "admin"})
    assert r.status_code == 403

def test_impossible_bfla_query_blocked(client, set_level):
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = client.get("/api/admin/users?role=admin")
    assert r.status_code == 403


# --- Level escalation ---
def test_low_bypass_fails_on_medium(client, set_level):
    set_level("medium")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)
    assert r.status_code == 403

def test_medium_bypass_fails_on_high(client, set_level):
    # medium body-override doesn't work at high (high uses session user_id for GET)
    # Actually high uses session for individual but list leaks — test body POST
    set_level("high")
    _login(client, "alice", "alice-pass")
    r = _post_user(client, 2, {"user_id": "2"})
    # At high level, POST uses body_user_id but then checks ownership same as medium
    # Actually: high doesn't use body_user_id differently — let's verify
    # The high level only fixes individual GET checks; POST at high also checks session
    # So body_user_id override should be blocked at high
    assert r.status_code == 403


# --- Detection regex ---
def test_detect_bola_url():
    assert DETECT.search("/api/users/2")
def test_detect_admin_url():
    assert DETECT.search("/api/admin/users")
def test_detect_x_role():
    assert DETECT.search("X-Role: admin")
def test_detect_ignores_benign():
    for b in META["benign"]:
        for v in b.values():
            assert not DETECT.search(v)


# --- Wazuh / Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_api_auth.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100512, 100513}

def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_api_auth.yml")))
    assert "bola" in str(r).lower() or "api" in str(r).lower() or "users" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low","medium","high"])
def test_flag_on_bola(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB","1")
    set_level(level)
    _login(client, "alice", "alice-pass")
    if level == "low":
        r = _get_user(client, 2)
    elif level == "medium":
        r = _post_user(client, 2, {"user_id": "2"})
    else:  # high — use list endpoint
        r = _list_users(client)
    data = r.get_json()
    assert "flag" in data, f"No flag at level={level}: {data}"

def test_no_flag_honeypot(client, set_level):
    set_level("low")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 2)
    assert "flag" not in (r.get_json() or {})

def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB","1")
    set_level("impossible")
    _login(client, "alice", "alice-pass")
    r = _get_user(client, 1)
    assert "flag" not in (r.get_json() or {})


# --- Containment ---
def test_containment_no_real_exec():
    import inspect, scenarios.api_auth.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
