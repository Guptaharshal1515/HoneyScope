"""HoneyScope scenarios.

Each scenario lives in its own sub-package with:
  scenario.json  - metadata (id, CWE, MITRE, levels, hints, payloads, detection regex)
  vuln.py        - the vulnerable code, one behaviour per difficulty level
  README.md      - write-up: goal, hints, solutions, fix
  rules/         - detections (Wazuh, Sigma) for that scenario

Difficulty is read from HONEYSCOPE_LEVEL. When lab mode is on (HONEYSCOPE_LAB=1)
it can also be switched at runtime from the /lab page.
"""
import json
import os

LEVELS = ("low", "medium", "high", "impossible")
DEFAULT_LEVEL = "low"  # "low" == original honeypot behaviour

_override = None  # set by the /lab page; only reachable when lab mode is on


def lab_enabled() -> bool:
    return os.environ.get("HONEYSCOPE_LAB", "0") == "1"


def get_level():
    """Current difficulty: runtime override (lab mode) > HONEYSCOPE_LEVEL > low."""
    if _override in LEVELS:
        return _override
    level = os.environ.get("HONEYSCOPE_LEVEL", DEFAULT_LEVEL).strip().lower()
    return level if level in LEVELS else DEFAULT_LEVEL


def set_level(level):
    """Set (or with None, clear) the runtime override. Returns True if accepted."""
    global _override
    if level is None or level in LEVELS:
        _override = level
        return True
    return False


def load_scenarios():
    """All scenario.json files found next to this package, sorted by id."""
    base = os.path.dirname(os.path.abspath(__file__))
    found = []
    for name in sorted(os.listdir(base)):
        meta = os.path.join(base, name, "scenario.json")
        if os.path.isfile(meta):
            with open(meta, encoding="utf-8") as f:
                found.append(json.load(f))
    return found
