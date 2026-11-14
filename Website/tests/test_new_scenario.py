import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest
import yaml

import scenarios

WEBSITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(WEBSITE, "tools", "new_scenario.py")
ARGS = ["--title", "Demo Thing", "--cwe", "CWE-79", "--owasp", "A03:2021 Injection",
        "--mitre", "T1059", "--endpoint", "POST /demo", "--target", "/demo", "--date", "2026-11-15"]


def run_tool(dest, scenario_id, *extra):
    return subprocess.run([sys.executable, "-I", TOOL, scenario_id, *ARGS, "--dest", str(dest), *extra],
                          capture_output=True, text=True)


def test_generates_a_complete_draft_skeleton(tmp_path):
    r = run_tool(tmp_path, "demo-thing")
    assert r.returncode == 0, r.stderr
    d = tmp_path / "scenarios" / "demo_thing"
    for rel in ("__init__.py", "scenario.json", "vuln.py", "README.md", "attack.py",
                "rules/wazuh_demo_thing.xml", "rules/sigma_demo_thing.yml"):
        assert (d / rel).is_file(), rel
    assert (tmp_path / "tests" / "test_demo_thing.py").is_file()

    meta = json.loads((d / "scenario.json").read_text())
    assert meta["status"] == "draft" and meta["id"] == "demo-thing"
    assert set(meta["levels"]) == set(meta["hints"]) == set(scenarios.LEVELS)
    assert meta["detection_regex"] == "" and all(p == {} for p in meta["payloads"].values())

    ET.parse(d / "rules" / "wazuh_demo_thing.xml")
    sigma = yaml.safe_load((d / "rules" / "sigma_demo_thing.yml").read_text())
    assert sigma["tags"] == ["attack.t1059"] and sigma["title"] == "Demo Thing"
    for py in ("vuln.py", "attack.py"):
        compile((d / py).read_text(), py, "exec")


def test_generator_writes_no_exploit_content(tmp_path):
    run_tool(tmp_path, "demo-thing")
    vuln = (tmp_path / "scenarios" / "demo_thing" / "vuln.py").read_text()
    assert vuln.count("NotImplementedError") == 4  # every level is an empty stub


def test_generated_tests_pass_and_skip_until_filled_in(tmp_path):
    run_tool(tmp_path, "demo-thing")
    r = subprocess.run([sys.executable, "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        str(tmp_path / "tests" / "test_demo_thing.py")],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "passed" in r.stdout and "skipped" in r.stdout and "failed" not in r.stdout


def test_rule_ids_are_allocated_without_collisions(tmp_path):
    run_tool(tmp_path, "first-one")
    run_tool(tmp_path, "second-one")
    ids = []
    for name in ("first_one", "second_one"):
        root = ET.parse(tmp_path / "scenarios" / name / "rules" / f"wazuh_{name}.xml").getroot()
        ids += [int(r.get("id")) for r in root.iter("rule")]
    assert ids == [100500, 100501, 100502, 100503]


def test_rule_ids_skip_ids_already_used_by_real_scenarios():
    import importlib.util
    spec = importlib.util.spec_from_file_location("new_scenario", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from pathlib import Path
    assert mod.next_rule_id(Path(WEBSITE) / "scenarios") >= 100502  # sqli-login uses 100500-100501


def test_refuses_to_overwrite_and_validates_input(tmp_path):
    assert run_tool(tmp_path, "demo-thing").returncode == 0
    again = run_tool(tmp_path, "demo-thing")
    assert again.returncode != 0 and "already exists" in again.stderr
    for bad in ("Demo_Thing", "demo--thing", "1demo", "demo-"):
        assert run_tool(tmp_path, bad).returncode != 0
    assert subprocess.run([sys.executable, "-I", TOOL, "ok-id", *ARGS[:4], "--cwe", "79"] + ARGS[6:],
                          capture_output=True, text=True).returncode != 0


def test_drafts_are_hidden_from_the_lab(tmp_path):
    run_tool(tmp_path, "demo-thing")
    base = str(tmp_path / "scenarios")
    assert scenarios.load_scenarios(base=base) == []
    assert [s["id"] for s in scenarios.load_scenarios(base=base, include_drafts=True)] == ["demo-thing"]
    # flip to ready -> visible
    p = tmp_path / "scenarios" / "demo_thing" / "scenario.json"
    meta = json.loads(p.read_text()); meta["status"] = "ready"; p.write_text(json.dumps(meta))
    assert [s["id"] for s in scenarios.load_scenarios(base=base)] == ["demo-thing"]


def test_real_scenarios_are_not_drafts():
    assert "sqli-login" in [s["id"] for s in scenarios.load_scenarios()]
