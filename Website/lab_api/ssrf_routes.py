"""SSRF scenario routes — /api/fetch and /api/internal/* (fake services).

The vulnerability lives in scenarios/ssrf/vuln.py.  This module is thin glue.
"""
from flask import request, jsonify

from lab_api import lab_api
from scenarios import get_level, lab_enabled
from scenarios import flags
from scenarios.ssrf.vuln import fetch_url, FAKE_SERVICES, _is_internal_hit


@lab_api.route("/fetch", methods=["POST", "GET"])
def ssrf_fetch():
    """
    Accept a URL and 'fetch' it (simulated in-process, never real network).
    POST body (JSON or form): {"url": "http://..."}
    GET ?url=... for browser convenience.
    """
    if request.is_json:
        data = request.get_json(force=True, silent=True) or {}
        url = data.get("url", "")
    else:
        url = request.form.get("url") or request.args.get("url", "")

    if not url:
        return jsonify({"error": "url parameter required"}), 400

    level = get_level()
    result = fetch_url(url, level)

    # Lab flag: grant when an internal service was successfully reached
    ssrf_flag = None
    if lab_enabled() and level != "impossible" and not result.get("blocked"):
        if _is_internal_hit(result.get("body")):
            ssrf_flag = flags.flag_for("ssrf", level)

    resp = {
        "url": result["url"],
        "status": result["status"],
        "body": result["body"],
        "level": level,
        "blocked": result.get("blocked", False),
    }
    if ssrf_flag:
        resp["flag"] = ssrf_flag
    http_status = 403 if result.get("blocked") else 200
    return jsonify(resp), http_status


@lab_api.route("/internal/<path:subpath>", methods=["GET"])
def ssrf_internal(subpath):
    """
    Fake internal service viewer — shows what the metadata endpoint returns.
    This route is NOT part of the SSRF vulnerability itself; it's a UI helper
    so learners can browse the fake service structure.
    """
    full_url = f"http://internal-{subpath}"
    result = FAKE_SERVICES.get(full_url) or {"error": "not found", "available": list(FAKE_SERVICES.keys())}
    return jsonify(result)
