"""Broken API Authorization — vuln.py
CWE-284 | A01:2021 | T1548

BOLA (Broken Object Level Auth) + BFLA (Broken Function Level Auth).

Level designs
-------------
low      : No ownership check; no role check. Any user can read any user's
           full record (salary included) and call admin endpoints.
medium   : BOLA — GET checks ownership, but POST trusts a user_id in the
           request body, not the session (bypass: override user_id in body).
           BFLA — admin role check reads from request.args ("?role=admin").
high     : Ownership fixed for GET/POST. Admin role from session.
           BOLA flaw: GET /api/users/ lists ALL users with salary.
           BFLA flaw: X-Role header overrides session role.
impossible: Ownership from session only; role from session only; user list
           returns only public fields; no header/query override.
"""

# ---------------------------------------------------------------------------
# Fake in-process user store (not a real auth system)
# ---------------------------------------------------------------------------

FAKE_USERS: dict[int, dict] = {
    1: {"id": 1, "username": "alice",   "email": "alice@lab.fake",   "role": "user",  "salary": 50000, "password": "alice-pass"},
    2: {"id": 2, "username": "bob",     "email": "bob@lab.fake",     "role": "user",  "salary": 55000, "password": "bob-pass"},
    3: {"id": 3, "username": "charlie", "email": "charlie@lab.fake", "role": "admin", "salary": 90000, "password": "charlie-pass"},
    4: {"id": 4, "username": "eve",     "email": "eve@lab.fake",     "role": "user",  "salary": 48000, "password": "eve-pass"},
}

# Public fields returned to any authenticated user (impossible level)
_PUBLIC_FIELDS = {"id", "username"}


def _safe_view(user: dict) -> dict:
    """Return only public fields — used at impossible level."""
    return {k: v for k, v in user.items() if k in _PUBLIC_FIELDS}


def _full_view(user: dict) -> dict:
    """Return full record minus password."""
    return {k: v for k, v in user.items() if k != "password"}


# ---------------------------------------------------------------------------
# Login helper
# ---------------------------------------------------------------------------

def check_login(username: str, password: str) -> dict | None:
    """Return the user dict if credentials match, else None."""
    for user in FAKE_USERS.values():
        if user["username"] == username and user["password"] == password:
            return user
    return None


# ---------------------------------------------------------------------------
# BOLA: read a user record
# ---------------------------------------------------------------------------

def get_user(session_user_id: int, session_role: str, target_id: int,
             body_user_id: int | None, x_role: str | None,
             role_query: str | None, level: str) -> dict:
    """
    Return {"allowed": bool, "data": dict|None, "reason": str}.
    session_user_id: who is logged in
    target_id: the user record being requested (from URL)
    body_user_id: user_id from POST body (may be None)
    x_role: value of X-Role header (may be None)
    role_query: value of ?role= query param (may be None)
    """
    target = FAKE_USERS.get(target_id)
    if not target:
        return {"allowed": False, "data": None, "reason": "user not found"}

    if level == "low":
        # No ownership check — any user reads any record
        return {"allowed": True, "data": _full_view(target), "reason": "low: no access control"}

    if level == "medium":
        # GET: checks session; POST body user_id overrides
        effective_id = body_user_id if body_user_id is not None else session_user_id
        if effective_id == target_id or session_role == "admin":
            return {"allowed": True, "data": _full_view(target), "reason": "medium: access granted"}
        return {"allowed": False, "data": None, "reason": "forbidden"}

    if level == "high":
        # Ownership fixed for individual records; flaw is in list endpoint
        if session_user_id == target_id or session_role == "admin":
            return {"allowed": True, "data": _full_view(target), "reason": "high: access granted"}
        return {"allowed": False, "data": None, "reason": "forbidden"}

    if level == "impossible":
        if session_user_id == target_id:
            return {"allowed": True, "data": _safe_view(target), "reason": "impossible: own record only"}
        return {"allowed": False, "data": None, "reason": "forbidden"}

    return {"allowed": False, "data": None, "reason": "unknown level"}


# ---------------------------------------------------------------------------
# BOLA: list all users
# ---------------------------------------------------------------------------

def list_users(session_role: str, level: str) -> dict:
    """Return user list — the high-level BOLA flaw leaks salary for all users."""
    if level in ("low", "medium"):
        # Any authenticated user can list; full records returned
        return {"allowed": True, "data": [_full_view(u) for u in FAKE_USERS.values()]}

    if level == "high":
        # BOLA flaw: full records including salary exposed to any user
        return {"allowed": True, "data": [_full_view(u) for u in FAKE_USERS.values()]}

    if level == "impossible":
        # Only public fields — no salary, no email
        return {"allowed": True, "data": [_safe_view(u) for u in FAKE_USERS.values()]}

    return {"allowed": False, "data": None}


# ---------------------------------------------------------------------------
# BFLA: check admin access
# ---------------------------------------------------------------------------

def check_admin(session_role: str, role_query: str | None, x_role: str | None, level: str) -> bool:
    """Return True if admin access is granted at this level."""
    if level == "low":
        # No check at all
        return True

    if level == "medium":
        # Role from query string — attacker can pass ?role=admin
        effective_role = role_query or session_role
        return effective_role == "admin"

    if level == "high":
        # X-Role header overrides session role — BFLA flaw
        effective_role = x_role or session_role
        return effective_role == "admin"

    if level == "impossible":
        # Role from session only — no header/query override
        return session_role == "admin"

    return False
