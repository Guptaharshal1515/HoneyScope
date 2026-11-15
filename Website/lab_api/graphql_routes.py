"""GraphQL scenario routes — POST /api/graphql.

The flaw logic lives in scenarios/graphql_abuse/vuln.py.
"""
from flask import jsonify, request

from lab_api import lab_api
from scenarios import flags, get_level, lab_enabled
from scenarios.graphql_abuse.vuln import execute_graphql


@lab_api.route("/graphql", methods=["POST"])
def graphql_endpoint():
    """
    POST /api/graphql — GraphQL query endpoint supporting single and batched operations.
    """
    level = get_level()
    payload = request.get_json(silent=True)

    if payload is None:
        return jsonify({"errors": [{"message": "Invalid JSON or missing body"}]}), 400

    role = request.headers.get("X-Role", "guest")
    result, exploited = execute_graphql(payload, level, role)

    if lab_enabled() and level != "impossible" and exploited:
        flag = flags.flag_for("graphql-abuse", level)
        if isinstance(result, dict):
            result["flag"] = flag
        elif isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict):
            result[0]["flag"] = flag

    return jsonify(result), 200
