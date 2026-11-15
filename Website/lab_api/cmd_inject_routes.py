"""Command injection, path traversal, and XXE routes.

The flaw logic lives in scenarios/cmd_inject/vuln.py.
"""
from flask import jsonify, request

from lab_api import lab_api
from scenarios import flags, get_level, lab_enabled
from scenarios.cmd_inject.vuln import execute_cmd, parse_xml_payload, read_virtual_file


@lab_api.route("/cmd", methods=["POST"])
def cmd_endpoint():
    """POST /api/cmd — diagnostic ping/trace endpoint."""
    level = get_level()
    target = ""
    if request.is_json:
        target = (request.get_json(silent=True) or {}).get("target", "")
    elif request.form:
        target = request.form.get("target", "")
    else:
        target = request.get_data(as_text=True)

    result, exploited = execute_cmd(target, level)
    status_code = 200 if "error" not in result else 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("cmd-inject", level)

    return jsonify(result), status_code


@lab_api.route("/file", methods=["GET"])
def file_endpoint():
    """GET /api/file?name=... — file retrieval endpoint."""
    level = get_level()
    filename = request.args.get("name", "")

    result, exploited = read_virtual_file(filename, level)
    status_code = 200 if "error" not in result else 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("cmd-inject", level)

    return jsonify(result), status_code


@lab_api.route("/xml", methods=["POST"])
def xml_endpoint():
    """POST /api/xml — XML diagnostics processing endpoint."""
    level = get_level()
    xml_data = request.get_data(as_text=True)

    result, exploited = parse_xml_payload(xml_data, level)
    status_code = 200 if "error" not in result else 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("cmd-inject", level)

    return jsonify(result), status_code
