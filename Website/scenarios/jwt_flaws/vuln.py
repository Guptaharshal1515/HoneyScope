"""JWT Handling Flaws — vuln.py
CWE-347 | A02:2021 | T1550.001

Level designs
-------------
low      : Algorithm = "none" accepted — no signature verification at all.
           The server signs tokens with HS256 but also accepts tokens with
           alg="none" and an empty signature.
medium   : Algorithm "none" is blocked, but the secret is a short, guessable
           string ("secret"). A learner who cracks it can forge any token.
high     : Strong random secret (env HONEYSCOPE_JWT_SECRET, 32-byte default).
           Flaw: `kid` header is accepted and used to look up the signing key
           from an in-process registry — injection via a known kid value
           allows an attacker to sign with a predictable key.
impossible: Strong secret; `kid` ignored; algorithm explicitly pinned to HS256
           via `algorithms=["HS256"]`; `alg` from header is ignored. The
           reference fix.

All secrets are fake / simulated. No real auth system is involved.
"""

import os
import jwt  # PyJWT

# ---------------------------------------------------------------------------
# Fake in-process user store (not a real auth system)
# ---------------------------------------------------------------------------

FAKE_USERS: dict[str, dict] = {
    "alice":  {"password": "alice-pass",  "role": "user"},
    "bob":    {"password": "bob-pass",    "role": "user"},
    "eve":    {"password": "eve-pass",    "role": "user"},
    "charlie":{"password": "charlie-pass","role": "user"},
}

# ---------------------------------------------------------------------------
# Secrets / keys — all fake, in-process only
# ---------------------------------------------------------------------------

# low: a real but disclosed weak secret (doesn't matter — alg=none bypasses)
_LOW_SECRET = "honeyscope-low-jwt-secret"

# medium: short, dictionary-crackable secret
_MEDIUM_SECRET = "secret"

# high/impossible: from env or a 32-byte random-looking default
_STRONG_SECRET = os.environ.get("HONEYSCOPE_JWT_SECRET", "xK8#mP2$qR9!vL5@nW3^cF7&tY1*bJ4(")

# high: kid → secret registry (the injectable one)
# A learner can forge tokens by using kid="dev" and signing with "dev-secret"
_KID_REGISTRY: dict[str, str] = {
    "prod":    _STRONG_SECRET,
    "dev":     "dev-secret",          # weak: known to learners via source hint
    "legacy":  "legacy-secret-1234",  # another weak one
}


# ---------------------------------------------------------------------------
# Level-aware token issuance
# ---------------------------------------------------------------------------

def issue_token(username: str, role: str, level: str) -> str:
    """Return a JWT for *username* at *level*.  Called on successful login."""
    payload = {"sub": username, "role": role}
    if level == "low":
        return jwt.encode(payload, _LOW_SECRET, algorithm="HS256")
    if level == "medium":
        return jwt.encode(payload, _MEDIUM_SECRET, algorithm="HS256")
    if level in ("high", "impossible"):
        headers = {"kid": "prod"} if level == "high" else {}
        return jwt.encode(payload, _STRONG_SECRET, algorithm="HS256",
                          headers=headers)
    raise ValueError(f"Unknown level: {level!r}")


# ---------------------------------------------------------------------------
# Level-aware token verification
# ---------------------------------------------------------------------------

def verify_token(token: str, level: str) -> dict | None:
    """
    Verify *token* and return the decoded payload, or None on failure.

    low      – accepts alg=none (no signature check) or HS256 with the low secret.
    medium   – rejects alg=none; verifies HS256 with the crackable secret.
    high     – rejects alg=none; looks up key via kid header (kid injection flaw).
    impossible – pins to HS256; ignores kid; rejects everything else.
    """
    if level == "low":
        return _verify_low(token)
    if level == "medium":
        return _verify_medium(token)
    if level == "high":
        return _verify_high(token)
    if level == "impossible":
        return _verify_impossible(token)
    return None


def _verify_low(token: str) -> dict | None:
    """Accept alg=none (no signature) OR a valid HS256 token."""
    # Peek at the header to detect alg=none before PyJWT touches it.
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None

    alg = header.get("alg", "").lower()
    if alg == "none":
        # SIMULATED: treat unsigned token as trusted (the vulnerability).
        # We decode without any verification; PyJWT 2.x raises if alg=none
        # unless we pass algorithms=["none"] and options.
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["HS256", "none"],
            )
            return payload
        except Exception:
            return None

    # Normal HS256 path
    try:
        return jwt.decode(token, _LOW_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def _verify_medium(token: str) -> dict | None:
    """Reject alg=none; use short crackable secret."""
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none":
            return None   # blocked
        return jwt.decode(token, _MEDIUM_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def _verify_high(token: str) -> dict | None:
    """Reject alg=none; kid header used to look up signing key (injectable)."""
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none":
            return None
        kid = header.get("kid", "prod")
        # FLAW: attacker can supply kid="dev" to use a known weak key.
        secret = _KID_REGISTRY.get(kid)
        if secret is None:
            return None   # unknown kid → reject
        return jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        return None


def _verify_impossible(token: str) -> dict | None:
    """Pin to HS256; ignore kid; use strong secret. The reference fix."""
    try:
        # algorithms= is explicit; kid is never consulted; alg from header
        # is ignored because decode() checks the algorithm against the list.
        return jwt.decode(
            token, _STRONG_SECRET,
            algorithms=["HS256"],
            options={"verify_exp": False},  # no expiry in this demo
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Simple login helper (level-agnostic; only checks fake password store)
# ---------------------------------------------------------------------------

def check_login(username: str, password: str) -> str | None:
    """Return the user's role if credentials match, else None."""
    user = FAKE_USERS.get(username)
    if user and user["password"] == password:
        return user["role"]
    return None


# ---------------------------------------------------------------------------
# Expose kid registry read-only (for tests only — not a real API)
# ---------------------------------------------------------------------------

def kid_registry_keys() -> list[str]:
    """Return the list of known kid values (test helper)."""
    return list(_KID_REGISTRY.keys())


def kid_secret(kid: str) -> str | None:
    """Return the secret for *kid* (test helper)."""
    return _KID_REGISTRY.get(kid)
