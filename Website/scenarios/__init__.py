"""HoneyScope scenarios.

Each scenario lives in its own sub-package with:
  scenario.json  - metadata (id, CWE, MITRE, levels, payloads, detection regex)
  vuln.py        - the vulnerable code, one behaviour per difficulty level
  README.md      - write-up: goal, hints, solutions, fix
  rules/         - detections (Wazuh, Sigma) for that scenario
"""
import os

LEVELS = ("low", "medium", "high", "impossible")
DEFAULT_LEVEL = "low"  # "low" == original honeypot behaviour


def get_level():
    """Current difficulty, read from HONEYSCOPE_LEVEL at call time."""
    level = os.environ.get("HONEYSCOPE_LEVEL", DEFAULT_LEVEL).strip().lower()
    return level if level in LEVELS else DEFAULT_LEVEL
