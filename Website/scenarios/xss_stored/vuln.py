"""Scenario: Stored XSS - Employee Feedback (CWE-79, MITRE T1059.007)

Comments are stored in the database and rendered on the dashboard for all users.
The weakness is cross-site scripting: user-controlled HTML reaches the browser
without sanitisation, so an attacker can inject script that runs for every viewer.

One function, four behaviours:

  low         Original honeypot: comment stored verbatim; template renders with
              `| safe`, so any HTML/JS executes in the victim's browser.
  medium      A naive filter strips <script>...</script> blocks. Any other tag or
              event-handler attribute (e.g. <img onerror=...>) bypasses it.
  high        A blocklist removes <script>, <img>, <svg>, <iframe> and the
              onerror/onload attribute names — once, case-insensitively.
              Lesser-known event handlers (ontoggle, onmouseover, etc.) and
              nesting tricks bypass it.
  impossible  Standard HTML escaping via Jinja2 autoescaping (no | safe).
              All special characters become entities; no HTML survives.

Containment: XSS impact is real within the page (that's the educational point),
but it stays inside the sandbox browser. No external data channel is involved.
The filter flaws are real conceptually; the "execution" is simulated in the
browser and cannot touch the host OS, filesystem, or network beyond the app.

Do NOT put solutions or payloads here; they belong in scenario.json and README.
"""
import html
import re

# --- medium filter -----------------------------------------------------------
# Strips <script>...</script> blocks (case-insensitive, non-greedy).
# BUG (intentional): only blocks <script>; ignores all other vectors.
_MEDIUM_SCRIPT = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
                             re.IGNORECASE | re.DOTALL)


def _medium_filter(text: str) -> str:
    """Remove <script> blocks only. Many other vectors remain."""
    return _MEDIUM_SCRIPT.sub("", text)


# --- high filter -------------------------------------------------------------
# Removes named tags and two event-handler names, once, case-insensitively.
# BUG (intentional): single pass; misses lesser-known handlers (ontoggle, etc.)
# and self-closing variants with unusual spacing.
_HIGH_TAGS = re.compile(
    r"<\s*/?\s*(?:script|img|svg|iframe|object|embed)[^>]*>",
    re.IGNORECASE,
)
_HIGH_HANDLERS = re.compile(r"\bon(?:error|load)\s*=", re.IGNORECASE)


def _high_filter(text: str) -> str:
    """Remove a named set of tags and two event handler attributes."""
    text = _HIGH_TAGS.sub("", text)
    text = _HIGH_HANDLERS.sub("data-removed=", text)
    return text


# --- public API --------------------------------------------------------------

def sanitise(comment: str, level: str) -> str:
    """Return the comment text to be stored, filtered per level.

    low         No change — stored verbatim.
    medium      <script> blocks removed.
    high        Named tags + onerror/onload attributes removed.
    impossible  HTML-escaped: all special chars become entities.
    """
    if level == "low":
        return comment                          # intentionally vulnerable
    if level == "medium":
        return _medium_filter(comment)          # intentionally incomplete
    if level == "high":
        return _high_filter(comment)            # intentionally incomplete
    # impossible — real fix
    return html.escape(comment, quote=True)
