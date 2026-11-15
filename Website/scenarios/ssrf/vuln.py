"""SSRF — Server-Side Request Forgery — vuln.py
CWE-918 | A10:2021 | T1090

Containment: NO real HTTP requests are ever made.  All "fetching" resolves
against FAKE_SERVICES, an in-process dict.  The standard library's network
modules (urllib, requests, socket) are never called against external addresses.

Level designs
-------------
low      : Accepts any URL.  Resolves against in-process registry.
           Internal services are reachable directly.
medium   : Blocklist of exact strings: "localhost", "127.0.0.1",
           "169.254.169.254".  Bypassable: http://internal-metadata/ is not
           blocked; neither are alternate IP encodings.
high     : Hostname allowlist: only example.com and safe.example.org.
           Flaw: a fake "redirect" service (in-process) returns a redirect
           instruction that the fetcher follows — SSRF via open redirect.
impossible: Allowlist after simulated DNS resolution; redirects not followed;
           scheme must be https; not exploitable.
"""

from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# In-process fake service registry
# SIMULATED: these are all in-memory dicts, never real network endpoints.
# ---------------------------------------------------------------------------

FAKE_SERVICES: dict[str, object] = {
    # Cloud-metadata simulation (AWS IMDSv1 style)
    "http://internal-metadata/latest/meta-data/": {
        "iam": {"role": "FakeLabRole"},
        "hostname": "fake-internal-host",
        "flag_hint": "you reached the metadata service",
    },
    "http://internal-metadata/latest/meta-data/iam/": {
        "role": "FakeLabRole",
        "credentials": {
            "AccessKeyId": "FAKE_AKID_LAB_ONLY",
            "SecretAccessKey": "FAKE_SECRET_LAB_ONLY",
        },
    },
    "http://internal-metadata/": {
        "version": "2021-01-01",
        "paths": ["/latest/meta-data/"],
    },
    # Internal API
    "http://internal-api/secret": {"secret": "FAKE_INTERNAL_API_SECRET_LAB"},
    "http://internal-api/health": {"status": "ok"},
    "http://internal-api/": {"endpoints": ["/health", "/secret"]},
    # Redirect service — the high-level bypass
    # _redirect key is a special instruction to the fetcher
    "http://redirect-service/": {"_redirect": "http://internal-metadata/latest/meta-data/"},
    # Safe external placeholder (benign)
    "https://example.com/": {"content": "Example Domain", "status": "external-safe"},
    "https://safe.example.org/": {"content": "Safe Example", "status": "external-safe"},
}

# Blocklist used at medium level (exact hostname / IP strings)
_MEDIUM_BLOCKLIST = {"localhost", "127.0.0.1", "169.254.169.254", "::1", "[::1]"}

# Allowlist used at high and impossible levels (exact hostnames)
_HOSTNAME_ALLOWLIST = {"example.com", "safe.example.org"}


# ---------------------------------------------------------------------------
# Core fetch logic
# ---------------------------------------------------------------------------

def _lookup(url: str) -> object:
    """
    Look up *url* in the in-process registry.
    Returns the registered value, or a "not found" placeholder dict.
    SIMULATED: no real network call is ever made.
    """
    # Normalise: ensure trailing slash for root paths
    parsed = urlparse(url)
    normalised = url if parsed.path else url.rstrip("/") + "/"
    # Exact match first
    if normalised in FAKE_SERVICES:
        return FAKE_SERVICES[normalised]
    if url in FAKE_SERVICES:
        return FAKE_SERVICES[url]
    # Prefix match (e.g. sub-paths)
    for key, val in FAKE_SERVICES.items():
        if isinstance(key, str) and normalised.startswith(key.rstrip("/")):
            return val
    return {"content": "external resource not found (simulated)", "status": 404}


def fetch_url(url: str, level: str) -> dict:
    """
    Simulate fetching *url* at *level*.
    Returns {"status": int, "body": any, "url": str, "blocked": bool}.
    Never makes a real network request.
    """
    if level == "low":
        return _fetch_low(url)
    if level == "medium":
        return _fetch_medium(url)
    if level == "high":
        return _fetch_high(url)
    if level == "impossible":
        return _fetch_impossible(url)
    return {"status": 400, "body": {"error": "unknown level"}, "url": url, "blocked": True}


def _fetch_low(url: str) -> dict:
    """No validation — any URL is resolved against the registry."""
    result = _lookup(url)
    if isinstance(result, dict) and "_redirect" in result:
        # SIMULATED: follow the redirect in-process
        result = _lookup(result["_redirect"])
    return {"status": 200, "body": result, "url": url, "blocked": False}


def _fetch_medium(url: str) -> dict:
    """Block exact strings; hostname variants bypass the check."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname.lower() in _MEDIUM_BLOCKLIST:
        return {"status": 403, "body": {"error": "blocked: hostname not allowed"}, "url": url, "blocked": True}
    # FLAW: http://internal-metadata/ is NOT in the blocklist
    result = _lookup(url)
    if isinstance(result, dict) and "_redirect" in result:
        result = _lookup(result["_redirect"])
    return {"status": 200, "body": result, "url": url, "blocked": False}


def _fetch_high(url: str) -> dict:
    """Hostname allowlist enforced, BUT redirects are followed (SSRF bypass)."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    # Scheme must be http or https
    if parsed.scheme not in ("http", "https"):
        return {"status": 400, "body": {"error": "scheme not allowed"}, "url": url, "blocked": True}
    if hostname not in _HOSTNAME_ALLOWLIST:
        return {"status": 403, "body": {"error": "hostname not in allowlist"}, "url": url, "blocked": True}
    # Allowlist passed — fetch (may hit redirect service if attacker registered it, but
    # redirect-service.com is not in allowlist; the flaw is the in-process redirect follow)
    result = _lookup(url)
    if isinstance(result, dict) and "_redirect" in result:
        # FLAW: redirect is followed without re-checking the allowlist
        # SIMULATED: attacker controls a redirect at an allowed domain → SSRF
        result = _lookup(result["_redirect"])
    return {"status": 200, "body": result, "url": url, "blocked": False}


def _fetch_impossible(url: str) -> dict:
    """Strict allowlist, scheme must be https, no redirects followed."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"status": 400, "body": {"error": "only https allowed"}, "url": url, "blocked": True}
    hostname = (parsed.hostname or "").lower()
    if hostname not in _HOSTNAME_ALLOWLIST:
        return {"status": 403, "body": {"error": "hostname not in allowlist"}, "url": url, "blocked": True}
    # No redirect following
    result = _lookup(url)
    if isinstance(result, dict) and "_redirect" in result:
        return {"status": 403, "body": {"error": "redirects not followed"}, "url": url, "blocked": True}
    return {"status": 200, "body": result, "url": url, "blocked": False}


# ---------------------------------------------------------------------------
# Flag helper: did the response contain internal service data?
# ---------------------------------------------------------------------------

def _is_internal_hit(body: object) -> bool:
    """Return True if the response body indicates an internal service was reached."""
    if not isinstance(body, dict):
        return False
    body_str = str(body)
    return any(marker in body_str for marker in [
        "FakeLabRole", "FAKE_INTERNAL_API_SECRET", "FAKE_AKID_LAB", "flag_hint",
    ])
