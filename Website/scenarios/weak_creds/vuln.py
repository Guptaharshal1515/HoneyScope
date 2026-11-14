"""Scenario: Weak Default Admin Credentials (CWE-798, MITRE T1078.001)

The /admin endpoint is a hidden admin login page. The weakness is that it uses
hardcoded or easily-guessable credentials, with no brute-force protection.

One function (admin_check), four behaviours:

  low         Original honeypot behaviour: hardcoded username 'admin' and
              password 'admin123' compared with plain ==. No rate limiting.
  medium      Password moved to the env var HONEYSCOPE_ADMIN_PASS (default
              'admin123'). Still no rate limiting. The default value is public
              in this repo, so the effective security is the same as low.
  high        Env-var password, plus a simple in-process rate limiter: 5
              failed attempts per IP per minute triggers a 60-second lockout.
              Flaw: the lockout dict is per-process and per-IP; a different
              process, a restarted server, or a different IP bypasses it.
  impossible  Constant-time comparison (secrets.compare_digest) against an
              env-var password. Rate limiting retained. /admin returns 404 for
              GET requests when lab mode is off, reducing attack surface.
              The real fix: set HONEYSCOPE_ADMIN_PASS to a long random secret.

Containment: no real host credentials or secrets. The admin panel only manages
the honeypot's own data; no host access is possible through it.
"""
import os
import secrets
import time
from collections import defaultdict

SCENARIO_ID = "weak-admin"

# Default password used at all vulnerable levels. Intentionally weak and public.
_DEFAULT_PASS = "admin123"
_ADMIN_USER = "admin"

# In-process rate-limit table: {ip: (failure_count, window_start)}
# Used at high and impossible levels only.
_rate_table: dict = defaultdict(lambda: [0, 0.0])
_RATE_WINDOW = 60   # seconds
_RATE_MAX = 5       # failures before lockout


def _env_password() -> str:
    """Read admin password from environment (may still be the weak default)."""
    return os.environ.get("HONEYSCOPE_ADMIN_PASS", _DEFAULT_PASS)


def _rate_check(ip: str) -> bool:
    """Return True if the IP is currently locked out (too many failures)."""
    count, window_start = _rate_table[ip]
    now = time.monotonic()
    if now - window_start > _RATE_WINDOW:
        # Window expired — reset counter
        _rate_table[ip] = [0, now]
        return False
    return count >= _RATE_MAX


def _rate_record_failure(ip: str) -> None:
    """Record a failed attempt for the given IP."""
    count, window_start = _rate_table[ip]
    now = time.monotonic()
    if now - window_start > _RATE_WINDOW:
        _rate_table[ip] = [1, now]
    else:
        _rate_table[ip] = [count + 1, window_start]


def _rate_reset(ip: str) -> None:
    """Clear rate-limit state for an IP (called on successful login)."""
    _rate_table.pop(ip, None)


def reset_rate_table() -> None:
    """Clear the entire rate-limit table (used in tests for isolation)."""
    _rate_table.clear()


def admin_check(username: str, password: str, ip: str, level: str) -> str:
    """Authenticate an admin login attempt.

    Returns one of:
      'ok'       — credentials accepted; grant access
      'denied'   — wrong credentials
      'locked'   — IP is rate-limited (high/impossible only)
    """
    if level == "low":
        # INTENTIONALLY VULNERABLE: hardcoded credentials, no rate limit
        if username == _ADMIN_USER and password == _DEFAULT_PASS:
            return "ok"
        return "denied"

    if level == "medium":
        # INTENTIONALLY VULNERABLE: env-var password, but default is still weak;
        # no rate limit
        correct = _env_password()
        if username == _ADMIN_USER and password == correct:
            return "ok"
        return "denied"

    if level == "high":
        # Rate-limited, but still uses plain == and an in-process table
        if _rate_check(ip):
            return "locked"
        correct = _env_password()
        # INTENTIONALLY VULNERABLE: plain == (susceptible to timing attacks, though
        # timing-based attacks are impractical over a network; the main educational
        # point is the in-process lockout bypass)
        if username == _ADMIN_USER and password == correct:
            _rate_reset(ip)
            return "ok"
        _rate_record_failure(ip)
        return "denied"

    # impossible — constant-time comparison + rate limit
    if _rate_check(ip):
        return "locked"
    correct = _env_password()
    # secrets.compare_digest prevents timing-based enumeration
    username_ok = secrets.compare_digest(username, _ADMIN_USER)
    password_ok = secrets.compare_digest(password, correct)
    if username_ok and password_ok:
        _rate_reset(ip)
        return "ok"
    _rate_record_failure(ip)
    return "denied"
