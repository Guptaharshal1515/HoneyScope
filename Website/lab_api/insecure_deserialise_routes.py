"""Insecure deserialization scenario routes — POST /api/deserialise.

The flaw logic lives in scenarios/insecure_deserialise/vuln.py.
"""
from flask import jsonify, request

from lab_api import lab_api
from scenarios import flags, get_level, lab_enabled
from scenarios.insecure_deserialise.vuln import deserialize_payload


@lab_api.route("/deserialise", methods=["POST"])
def deserialise_endpoint():
    """
    POST /api/deserialise — endpoint accepting serialized payload.
    Accepts JSON `{"payload": "..."}` or raw form/body data.
    """
    level = get_level()

    # Extract payload string
    payload_str = ""
    if request.is_json:
        body = request.get_json(silent=True) or {}
        payload_str = body.get("payload", "")
        if not payload_str and isinstance(body, dict):
            import json
            payload_str = json.dumps(body)
    elif request.form and "payload" in request.form:
        payload_str = request.form["payload"]
    else:
        payload_str = request.get_data(as_text=True)

    result, exploited = deserialize_payload(payload_str, level)

    status_code = 200
    if "error" in result:
        status_code = 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("insecure-deserialise", level)

    return jsonify(result), status_code
