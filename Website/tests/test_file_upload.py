"""Tests for the file-upload scenario."""
import io
import json
import os
import re
import xml.etree.ElementTree as ET
import pytest
import yaml

import scenarios
from scenarios.file_upload.vuln import MAX_SIZE, UPLOAD_DIR, _IMAGE_EXTENSIONS

SCEN_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios", "file_upload")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
DETECT = re.compile(META["detection_regex"])
LEVELS = scenarios.LEVELS

VALID_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb"
VALID_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
SCRIPT_CONTENT = b"<?php echo 'simulated'; ?>"


def _upload(client, filename, content, content_type="application/octet-stream"):
    data = {
        "file": (io.BytesIO(content), filename, content_type)
    }
    return client.post("/api/upload", data=data, content_type="multipart/form-data")


def test_metadata_complete():
    for k in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints", "payloads", "detection_regex"):
        assert k in META
    assert META["status"] == "ready"


# --- Level low ---
def test_low_accepts_script_file(client, set_level):
    set_level("low")
    r = _upload(client, "webshell.php", SCRIPT_CONTENT, "text/plain")
    assert r.status_code == 200
    data = r.get_json()
    assert data["filename"] == "webshell.php"
    assert "stored_as" in data
    assert os.path.exists(os.path.join(UPLOAD_DIR, data["stored_as"]))


# --- Level medium ---
def test_medium_rejects_non_image_content_type(client, set_level):
    set_level("medium")
    r = _upload(client, "webshell.php", SCRIPT_CONTENT, "text/plain")
    assert r.status_code == 400
    assert "not an image type" in r.get_json()["reason"].lower()


def test_medium_accepts_spoofed_content_type(client, set_level):
    set_level("medium")
    r = _upload(client, "webshell.php", SCRIPT_CONTENT, "image/jpeg")
    assert r.status_code == 200
    data = r.get_json()
    assert "stored_as" in data


# --- Level high ---
def test_high_rejects_script_extension(client, set_level):
    set_level("high")
    r = _upload(client, "webshell.php", SCRIPT_CONTENT, "image/jpeg")
    assert r.status_code == 400
    assert "not in the allowed list" in r.get_json()["reason"].lower()


def test_high_accepts_double_extension(client, set_level):
    set_level("high")
    r = _upload(client, "webshell.php.jpg", SCRIPT_CONTENT, "image/jpeg")
    assert r.status_code == 200
    data = r.get_json()
    assert "stored_as" in data


# --- Level impossible ---
def test_impossible_rejects_fake_image(client, set_level):
    set_level("impossible")
    r = _upload(client, "webshell.php.jpg", SCRIPT_CONTENT, "image/jpeg")
    assert r.status_code == 400
    assert "magic" in r.get_json()["reason"].lower() or "signature" in r.get_json()["reason"].lower() or "image format" in r.get_json()["reason"].lower()


def test_impossible_accepts_valid_image(client, set_level):
    set_level("impossible")
    r = _upload(client, "photo.jpg", VALID_JPEG, "image/jpeg")
    assert r.status_code == 200
    data = r.get_json()
    assert "stored_as" in data


# --- General validation ---
def test_size_limit_enforced_at_all_levels(client, set_level):
    for lvl in LEVELS:
        set_level(lvl)
        huge = b"A" * (MAX_SIZE + 1024)
        r = _upload(client, "photo.jpg", huge, "image/jpeg")
        assert r.status_code == 400
        assert "too large" in r.get_json()["reason"].lower()


def test_missing_file_field(client):
    r = client.post("/api/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400


# --- Detection regex ---
def test_detect_script_extensions():
    assert DETECT.search("webshell.php")
    assert DETECT.search("attack.py")
    assert DETECT.search("script.sh")
    assert DETECT.search("payload.exe")
    assert DETECT.search("cmd.jsp")


def test_detect_spoofed_type():
    assert DETECT.search("Content-Type: image/jpeg; name=shell.php")


def test_detect_ignores_benign():
    for b in META["benign"]:
        assert not DETECT.search(b["filename"])


# --- Wazuh & Sigma ---
def test_wazuh_ids():
    root = ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_file_upload.xml")).getroot()
    ids = {int(r.get("id")) for r in root.iter("rule")}
    assert ids == {100514, 100515}


def test_sigma_parses():
    r = yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_file_upload.yml")))
    assert "upload" in str(r).lower()


# --- Flags ---
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_flag_on_bypassed_upload(client, set_level, monkeypatch, level):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level(level)
    if level == "low":
        r = _upload(client, "webshell.php", SCRIPT_CONTENT, "text/plain")
    elif level == "medium":
        r = _upload(client, "webshell.php", SCRIPT_CONTENT, "image/jpeg")
    else:  # high
        r = _upload(client, "webshell.php.jpg", SCRIPT_CONTENT, "image/jpeg")

    assert r.status_code == 200
    data = r.get_json()
    assert "flag" in data, f"No flag at level={level}: {data}"
    assert data["flag"].startswith("HS{file-upload:")


def test_no_flag_in_honeypot_mode(client, set_level):
    set_level("low")
    r = _upload(client, "webshell.php", SCRIPT_CONTENT, "text/plain")
    assert r.status_code == 200
    assert "flag" not in r.get_json()


def test_no_flag_at_impossible(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("impossible")
    r = _upload(client, "photo.jpg", VALID_JPEG, "image/jpeg")
    assert r.status_code == 200
    assert "flag" not in r.get_json()


def test_no_flag_on_legit_image_at_low(client, set_level, monkeypatch):
    monkeypatch.setenv("HONEYSCOPE_LAB", "1")
    set_level("low")
    r = _upload(client, "photo.jpg", VALID_JPEG, "image/jpeg")
    assert r.status_code == 200
    assert "flag" not in r.get_json()


# --- Containment ---
def test_containment_no_real_exec():
    import inspect
    import scenarios.file_upload.vuln as m
    src = inspect.getsource(m)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "eval(" not in src
    assert "exec(" not in src


def test_containment_attachment_header(client, set_level):
    set_level("low")
    r = _upload(client, "test.txt", b"safe content", "text/plain")
    assert r.headers.get("Content-Disposition") == "attachment"
