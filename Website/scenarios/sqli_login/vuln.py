"""Scenario: SQL injection on the login form (CWE-89, MITRE T1190).

One function, four behaviours:

  low         original honeypot: raw string concatenation, SQL errors shown,
              plus a username-only fallback query.
  medium      concatenation, but a naive filter removes upper/lower-case "OR"
              and SQL comments. Case-mixing bypasses it.
  high        concatenation, but a case-insensitive blacklist removes
              keywords ONCE (non-recursive). Nested keywords bypass it.
  impossible  parameterised query. Not injectable. This is the reference fix.
"""
import re

_MEDIUM_FILTER = re.compile(r"\bOR\b|\bor\b|--|#")
_HIGH_FILTER = re.compile(r"(?i)or|and|union|select|--|/\*|#")


def _medium(s: str) -> str:
    return _MEDIUM_FILTER.sub("", s)


def _high(s: str) -> str:
    # BUG (intentional): single pass. "OORR" -> "OR" after the inner "OR" is removed.
    return _HIGH_FILTER.sub("", s)


def authenticate(db, username: str, password: str, level: str):
    """Return the matching user row (or None). May raise sqlite3.Error."""
    if level == "impossible":
        return db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

    if level == "medium":
        username, password = _medium(username), _medium(password)
    elif level == "high":
        username, password = _high(username), _high(password)

    # INTENTIONALLY VULNERABLE (low/medium/high): string concatenation.
    query = ("SELECT * FROM users WHERE username = '" + username
             + "' AND password = '" + password + "'")
    result = db.execute(query).fetchone()

    if result is None and level == "low" and "'" in username:
        # Original honeypot quirk, kept at "low" so ' OR '1'='1 in the username
        # alone works. Only runs when the username contains a quote, so a plain
        # wrong password for a real user is still rejected.
        result = db.execute(
            "SELECT * FROM users WHERE username = '" + username + "'"
        ).fetchone()
    return result
