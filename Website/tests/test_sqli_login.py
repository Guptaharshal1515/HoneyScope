import json
import os
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

SCEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scenarios", "sqli_login")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
LEVELS = list(META["levels"])


def _login(client, creds):
    return client.post("/login", data=creds)


def _bypassed(resp):
    return resp.status_code == 302 and resp.headers["Location"].endswith("/dashboard")


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_payload_bypasses_vulnerable_levels(client, set_level, level):
    set_level(level)
    assert _bypassed(_login(client, META["payloads"][level]))


def test_impossible_is_not_injectable(client, set_level):
    set_level("impossible")
    assert not _bypassed(_login(client, META["payloads"]["impossible"]))
    # every other level's payload must fail too
    for lvl in ("low", "medium", "high"):
        assert not _bypassed(_login(client, META["payloads"][lvl]))


@pytest.mark.parametrize("level", LEVELS)
def test_real_credentials_work_at_every_level(client, set_level, level):
    set_level(level)
    assert _bypassed(_login(client, {"username": "mwilson", "password": "letmein"}))


def test_high_blacklist_breaks_legit_password_containing_keyword(client, set_level):
    # Lesson: blacklists have false positives. "password123" contains "or",
    # which the high-level filter strips, so a legitimate user is locked out.
    set_level("high")
    assert not _bypassed(_login(client, {"username": "jsmith", "password": "password123"}))
    set_level("impossible")
    assert _bypassed(_login(client, {"username": "jsmith", "password": "password123"}))


@pytest.mark.parametrize("level", LEVELS)
def test_wrong_password_fails(client, set_level, level):
    set_level(level)
    assert not _bypassed(_login(client, {"username": "jsmith", "password": "nope"}))


def test_easier_payload_does_not_work_on_harder_level(client, set_level):
    set_level("medium")
    assert not _bypassed(_login(client, META["payloads"]["low"]))
    set_level("high")
    assert not _bypassed(_login(client, META["payloads"]["medium"]))


def test_invalid_level_falls_back_to_low(client, set_level):
    set_level("banana")
    assert _bypassed(_login(client, META["payloads"]["low"]))


def test_requests_are_logged_with_level(client, set_level):
    set_level("medium")
    _login(client, META["payloads"]["medium"])
    last = json.loads(client.log_file.read_text().splitlines()[-1])
    assert last["path"] == "/login" and last["lab_level"] == "medium"
    assert last["form_data"]["password"] == META["payloads"]["medium"]["password"]


# ---- detections ------------------------------------------------------------

DETECT = re.compile(META["detection_regex"])


@pytest.mark.parametrize("level", LEVELS)
def test_detection_regex_catches_every_payload(level):
    p = META["payloads"][level]
    assert DETECT.search(p["username"]) or DETECT.search(p["password"])


def test_detection_regex_ignores_benign_logins():
    for creds in META["benign"]:
        assert not DETECT.search(creds["username"])
        assert not DETECT.search(creds["password"])


def test_wazuh_rules_use_the_shared_regex():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_sqli_login.xml")).getroot()
    patterns = [f.text for f in root.iter("field") if f.get("name", "").startswith("form_data.")]
    assert len(patterns) == 2
    assert all(p == META["detection_regex"] for p in patterns)


def test_sigma_rule_uses_the_shared_regex():
    rule = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_sqli_login.yml")))
    det = rule["detection"]
    assert det["selection_payload"]["form_data.username|re"] == META["detection_regex"]
    assert det["selection_payload_pw"]["form_data.password|re"] == META["detection_regex"]
