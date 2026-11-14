"""Flags and scoreboard for lab mode.

A flag proves a learner really got past a scenario at a given level. Flags are
derived with HMAC, so nothing is stored, and each (scenario, level) pair has its
own flag. The `impossible` level has no flag: nothing should be capturable there.

Set HONEYSCOPE_FLAG_SECRET to something private if you share the lab with others;
the default is public in this repo. Progress is kept in memory only (resets when
the server restarts).
"""
import hashlib
import hmac
import os

from . import LEVELS

FLAG_LEVELS = tuple(l for l in LEVELS if l != "impossible")

_solved = set()  # {(scenario_id, level)}


def _secret() -> bytes:
    return os.environ.get("HONEYSCOPE_FLAG_SECRET", "honeyscope-lab-default").encode()


def flag_for(scenario_id: str, level: str) -> str:
    digest = hmac.new(_secret(), f"{scenario_id}:{level}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"HS{{{scenario_id}:{level}:{digest}}}"


def submit(flag: str, scenario_ids):
    """Check a submitted flag. Returns (scenario_id, level, newly_solved) or None."""
    flag = (flag or "").strip()
    for sid in scenario_ids:
        for level in FLAG_LEVELS:
            if hmac.compare_digest(flag, flag_for(sid, level)):
                new = (sid, level) not in _solved
                _solved.add((sid, level))
                return sid, level, new
    return None


def solved() -> set:
    return {f"{sid}:{level}" for sid, level in _solved}


def reset() -> None:
    _solved.clear()
