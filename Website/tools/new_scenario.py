#!/usr/bin/env python3
"""Create the skeleton for a new HoneyScope scenario.

    python tools/new_scenario.py my-scenario --title "My Scenario" \
        --cwe CWE-79 --owasp "A03:2021 Injection" --mitre T1059 \
        --endpoint "POST /example" --target /example

It writes folders and templates only: metadata, empty level stubs, a README
outline, detection-rule templates with the next free Wazuh rule IDs, a replay
script stub, and a skeleton test file. It does NOT write vulnerable code or
payloads; the scenario author does that. The new scenario starts as
"status": "draft", which hides it from /lab and the scoreboard until you flip
it to "ready" in scenario.json.

Standard library only.
"""
import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

LEVELS = ("low", "medium", "high", "impossible")
ID_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
RULE_ID_RE = re.compile(r'<rule\s+id="(\d+)"')
FIRST_RULE_ID = 100500  # 100010-100058 belong to the original honeypot rules
RULES_PER_SCENARIO = 2

VULN_PY = '''"""Scenario: @@TITLE@@ (@@CWE@@, MITRE @@MITRE@@)

TODO: one paragraph describing the weakness and what each level changes.

  low         TODO
  medium      TODO
  high        TODO
  impossible  TODO. This must be the real fix, not just a harder bypass.

Do not put solutions or payloads in this file; they belong in scenario.json and
the README (collapsed).

Flags (lab mode): when a learner succeeds at low/medium/high, the app may show
`flags.flag_for("@@ID@@", level)`. See how app.py does it for sqli-login: only
when lab_enabled() is true, never at "impossible", never in honeypot mode.
"""
from scenarios import flags  # noqa: F401  (used once the scenario is wired in)

SCENARIO_ID = "@@ID@@"


def low(*args, **kwargs):
    raise NotImplementedError("TODO: low level behaviour")


def medium(*args, **kwargs):
    raise NotImplementedError("TODO: medium level behaviour")


def high(*args, **kwargs):
    raise NotImplementedError("TODO: high level behaviour")


def impossible(*args, **kwargs):
    raise NotImplementedError("TODO: the real fix")


HANDLERS = {"low": low, "medium": medium, "high": high, "impossible": impossible}


def handle(level, *args, **kwargs):
    """Dispatch to the behaviour for `level`."""
    return HANDLERS[level](*args, **kwargs)
'''

README_MD = '''# Scenario: @@TITLE@@

| | |
|---|---|
| Endpoint | `@@ENDPOINT@@` |
| CWE / OWASP | @@CWE@@ / @@OWASP@@ |
| MITRE ATT&CK | @@MITRE@@ |
| Code | [`vuln.py`](vuln.py) |
| Detections | [`rules/`](rules/) |

> Status: **draft**. Set `"status": "ready"` in `scenario.json` when this is finished.

**Goal (red team):** TODO
**Goal (blue team):** make sure every attempt raises an alert, at every level.

Set the difficulty with `HONEYSCOPE_LEVEL=low|medium|high|impossible`.

## Levels

| Level | What the app does | Why it falls |
|---|---|---|
| low | TODO | TODO |
| medium | TODO | TODO |
| high | TODO | TODO |
| impossible | TODO (the real fix) | Not exploitable |

## Hints (no spoilers)

- low: TODO
- medium: TODO
- high: TODO

<details><summary>Solutions (spoilers)</summary>

TODO

</details>

## The fix

TODO: show the secure code and explain why it works.

## Blue-team material

- `scenario.json` -> `detection_regex`: shared by the Wazuh rule, the Sigma rule and the tests.
- `rules/wazuh_@@SLUG@@.xml` and `rules/sigma_@@SLUG@@.yml`
- `attack.py`: replays the scenario against a running instance.
- Known false positives: TODO
'''

WAZUH_XML = '''<!--
  HoneyScope scenario: @@ID@@  (DRAFT TEMPLATE)
  Add to /var/ossec/etc/rules/ once finished. IDs @@RID1@@-@@RID2@@ were the next free
  ones when this was generated; IDs from 100500 up are reserved for scenarios.
  TODO: replace the placeholder fields with the real log fields and the shared regex
  from scenario.json (a test checks they match).
-->
<group name="honeypot,honeyscope,@@SLUG@@,web,">

  <rule id="@@RID1@@" level="10">
    <decoded_as>json</decoded_as>
    <field name="path">^/TODO$</field>
    <description>HoneyScope: TODO detection for @@TITLE_XML@@</description>
    <mitre><id>@@MITRE@@</id></mitre>
  </rule>

  <rule id="@@RID2@@" level="10">
    <decoded_as>json</decoded_as>
    <field name="path">^/TODO$</field>
    <description>HoneyScope: TODO second detection for @@TITLE_XML@@</description>
    <mitre><id>@@MITRE@@</id></mitre>
  </rule>

</group>
'''

SIGMA_YML = '''title: @@TITLE_Q@@
id: @@UUID@@
status: experimental
description: TODO - what this detects (HoneyScope @@ID@@ scenario).
references:
  - scenarios/@@SLUG@@/README.md
author: HoneyScope contributors
date: @@DATE@@
tags:
  - attack.@@MITRE_TAG@@
logsource:
  product: honeyscope
  service: webapp
detection:
  selection:
    path: '/TODO'
  condition: selection
falsepositives:
  - TODO
level: medium
'''

ATTACK_PY = '''#!/usr/bin/env python3
"""Replay the @@ID@@ scenario against a running HoneyScope (draft stub).

Usage: python attack.py http://localhost:5000 [low|medium|high|impossible]
Only run against instances you own. Standard library only.
"""
import json
import os
import sys


def load_payloads(level):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "scenario.json")) as f:
        return json.load(f)["payloads"][level]


def attack(base_url, level):
    """Return True if the scenario was defeated at `level`."""
    raise NotImplementedError("TODO: implement the replay for this scenario")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    ok = attack(url, lvl)
    print(f"[{lvl}] {'SUCCEEDED' if ok else 'failed'}")
    sys.exit(0 if ok else 1)
'''

TEST_PY = '''"""Skeleton tests for the @@ID@@ scenario (generated).

The structural tests run immediately. Behaviour tests skip until you fill in
`payloads` and `detection_regex` in scenario.json, so a draft never breaks CI.
"""
import json
import os
import xml.etree.ElementTree as ET

import pytest
import yaml

SCEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scenarios", "@@SLUG@@")
META = json.load(open(os.path.join(SCEN_DIR, "scenario.json")))
LEVELS = ("low", "medium", "high", "impossible")


def test_metadata_is_complete():
    for key in ("id", "title", "endpoint", "target", "cwe", "owasp", "mitre", "levels", "hints"):
        assert key in META, f"scenario.json is missing {key}"
    assert META["id"] == "@@ID@@"
    assert set(META["levels"]) == set(LEVELS) == set(META["hints"])


def test_rules_are_well_formed():
    ET.parse(os.path.join(SCEN_DIR, "rules", "wazuh_@@SLUG@@.xml"))
    yaml.safe_load(open(os.path.join(SCEN_DIR, "rules", "sigma_@@SLUG@@.yml")))


@pytest.mark.parametrize("level", LEVELS)
def test_each_level_behaves_as_documented(level):
    if not META.get("payloads", {}).get(level):
        pytest.skip("draft: add a payload for this level in scenario.json, then write this test")
    # TODO: with the Flask test client (see tests/test_sqli_login.py), assert that the
    # payload succeeds at low/medium/high and fails at impossible.
    pytest.skip("TODO: write the behaviour test")


def test_detection_regex_matches_payloads_and_ignores_benign_input():
    if not META.get("detection_regex"):
        pytest.skip("draft: set detection_regex in scenario.json")
    # TODO: compile META["detection_regex"]; assert it matches each payload value and
    # none of META["benign"]; assert the Wazuh and Sigma rules carry the same regex.
    pytest.skip("TODO: write the detection test")
'''


def next_rule_id(scenarios_dir: Path) -> int:
    """First free Wazuh rule ID (>= 100500) across every scenario's rules/*.xml."""
    used = []
    for xml in scenarios_dir.glob("*/rules/*.xml"):
        used += [int(m) for m in RULE_ID_RE.findall(xml.read_text(encoding="utf-8"))]
    return max([FIRST_RULE_ID - 1] + used) + 1


def render(template: str, values: dict) -> str:
    for key, val in values.items():
        template = template.replace(f"@@{key}@@", val)
    return template


def build(args, root: Path) -> list:
    scen_dir = root / "scenarios"
    slug = args.id.replace("-", "_")
    target_dir = scen_dir / slug
    if target_dir.exists():
        raise SystemExit(f"error: {target_dir} already exists; refusing to overwrite")

    rid1 = next_rule_id(scen_dir)
    values = {
        "ID": args.id, "SLUG": slug, "TITLE": args.title, "TITLE_XML": escape(args.title),
        "TITLE_Q": json.dumps(args.title), "CWE": args.cwe, "OWASP": args.owasp,
        "MITRE": args.mitre[0], "MITRE_TAG": args.mitre[0].lower(),
        "ENDPOINT": args.endpoint, "RID1": str(rid1), "RID2": str(rid1 + 1),
        "UUID": str(uuid.uuid4()), "DATE": args.date,
    }

    meta = {
        "id": args.id, "status": "draft", "title": args.title, "endpoint": args.endpoint,
        "target": args.target, "cwe": args.cwe, "owasp": args.owasp, "mitre": args.mitre,
        "levels": {l: f"TODO: what the app does at {l}" for l in LEVELS},
        "hints": {l: f"TODO: spoiler-free hint for {l}" for l in LEVELS},
        "payloads": {l: {} for l in LEVELS},
        "benign": [],
        "detection_regex": "",
    }

    files = {
        target_dir / "__init__.py": "",
        target_dir / "scenario.json": json.dumps(meta, indent=2) + "\n",
        target_dir / "vuln.py": render(VULN_PY, values),
        target_dir / "README.md": render(README_MD, values),
        target_dir / "attack.py": render(ATTACK_PY, values),
        target_dir / "rules" / f"wazuh_{slug}.xml": render(WAZUH_XML, values),
        target_dir / "rules" / f"sigma_{slug}.yml": render(SIGMA_YML, values),
        root / "tests" / f"test_{slug}.py": render(TEST_PY, values),
    }
    for path, text in files.items():
        if path.exists():
            raise SystemExit(f"error: {path} already exists; refusing to overwrite")
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return list(files)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Create a new HoneyScope scenario skeleton.")
    p.add_argument("id", help="kebab-case id, e.g. my-scenario")
    p.add_argument("--title", required=True)
    p.add_argument("--cwe", required=True, help="e.g. CWE-79")
    p.add_argument("--owasp", required=True, help='e.g. "A03:2021 Injection"')
    p.add_argument("--mitre", required=True, nargs="+", help="technique id(s), e.g. T1190")
    p.add_argument("--endpoint", required=True, help='e.g. "POST /example"')
    p.add_argument("--target", required=True, help="URL path the /lab page links to")
    p.add_argument("--dest", default=None, help="Website root to write into (default: this repo's Website/)")
    p.add_argument("--date", default="2026-01-01", help="date for the Sigma rule (YYYY-MM-DD)")
    args = p.parse_args(argv)
    if not ID_RE.match(args.id):
        p.error("id must be kebab-case: lowercase letters, digits and single hyphens, starting with a letter")
    if not re.match(r"^CWE-\d+$", args.cwe):
        p.error("--cwe must look like CWE-79")
    for m in args.mitre:
        if not MITRE_RE.match(m):
            p.error(f"--mitre {m!r} must look like T1190 or T1059.001")
    if not args.target.startswith("/"):
        p.error("--target must start with /")
    return args


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    root = Path(args.dest).resolve() if args.dest else Path(__file__).resolve().parent.parent
    created = build(args, root)
    print(f"Created scenario '{args.id}' (draft):")
    for path in created:
        print("  " + str(path.relative_to(root)))
    print(f"""
Next steps:
  1. Write scenarios/{args.id.replace('-', '_')}/vuln.py (low/medium/high, plus `impossible` as the real fix).
  2. Fill in scenario.json: levels, hints, payloads, benign inputs, detection_regex.
  3. Wire the route into app.py (see how sqli-login uses scenarios.get_level()).
  4. Finish the Wazuh and Sigma rules with the shared detection_regex.
  5. Write the tests, implement attack.py, fill in the README.
  6. Set "status": "ready" in scenario.json, then add a row to the README scenarios table and CHANGELOG.md.""")


if __name__ == "__main__":
    main()
