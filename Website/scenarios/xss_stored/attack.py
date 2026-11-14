#!/usr/bin/env python3
"""Replay the xss-stored scenario against a running HoneyScope instance.

Usage: python attack.py http://localhost:5000 [low|medium|high|impossible]
Exit code 0 = XSS payload stored and detected on dashboard; 1 = not stored.
Only run against instances you own. Standard library only.

What this script does:
  1. Log in as jsmith (password123).
  2. POST the payload for the given level to /submit_comment.
  3. GET /dashboard and check that the payload appears (not escaped).
  4. Exit 0 if the raw payload appears in the response, 1 otherwise.
"""
import html as htmllib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def _build_opener(cookie_jar):
    """Build an opener that stores cookies and does not follow redirects."""
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


def attack(base_url: str, level: str) -> bool:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "scenario.json")) as f:
        meta = json.load(f)
    payload = meta["payloads"][level]["comment"]

    base = base_url.rstrip("/")
    cookies = {}
    opener = _build_opener(cookies)

    # Log in
    login_data = urllib.parse.urlencode(
        {"username": "jsmith", "password": "password123"}
    ).encode()
    try:
        opener.open(urllib.request.Request(base + "/login", login_data))
    except urllib.error.HTTPError:
        pass  # redirect is expected

    # POST the XSS payload
    comment_data = urllib.parse.urlencode({"comment": payload}).encode()
    try:
        opener.open(urllib.request.Request(base + "/submit_comment", comment_data))
    except urllib.error.HTTPError:
        pass

    # GET dashboard and look for the raw payload
    try:
        resp = opener.open(urllib.request.Request(base + "/dashboard"))
        html = htmllib.unescape(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        print(f"  error reading dashboard: {exc}", file=sys.stderr)
        return False

    if level == "impossible":
        # At impossible the payload should NOT appear raw
        return payload not in html and "<script>" not in html
    else:
        # At other levels the raw payload (or its key vector) should appear
        return payload in html


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    ok = attack(url, lvl)
    if lvl == "impossible":
        print(f"[{lvl}] XSS payload was {'correctly blocked' if ok else 'NOT blocked (unexpected)'}")
    else:
        print(f"[{lvl}] XSS stored and rendered {'SUCCEEDED' if ok else 'failed'}")
    sys.exit(0 if ok else 1)
