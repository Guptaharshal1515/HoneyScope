"""LLM chatbot scenario routes — POST /api/chat.

The flaw logic lives in scenarios/llm_chatbot/vuln.py.
"""
from flask import jsonify, request

from lab_api import lab_api
from scenarios import flags, get_level, lab_enabled
from scenarios.llm_chatbot.vuln import mock_llm_generate


@lab_api.route("/chat", methods=["POST"])
def chat_endpoint():
    """POST /api/chat — submit a message to the internal IT support AI assistant."""
    level = get_level()
    data = request.get_json(silent=True) or request.form or {}
    message = data.get("message", "")

    result, exploited = mock_llm_generate(message, level)
    status_code = 200 if "error" not in result else 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("llm-chatbot", level)

    return jsonify(result), status_code
