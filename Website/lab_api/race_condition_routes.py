"""Race condition & business logic scenario routes.

The flaw logic lives in scenarios/race_condition/vuln.py.
"""
from flask import jsonify, request

from lab_api import lab_api
from scenarios import flags, get_level, lab_enabled
from scenarios.race_condition.vuln import apply_coupon, get_balance, reset_user


@lab_api.route("/coupon/apply", methods=["POST"])
def coupon_apply_endpoint():
    """POST /api/coupon/apply — apply promo coupon."""
    level = get_level()
    data = request.get_json(silent=True) or request.form or {}
    coupon = data.get("coupon", "")
    user_id = int(data.get("user_id", 1))

    result, exploited = apply_coupon(coupon, user_id, level)
    status_code = 200 if "error" not in result else 400

    if lab_enabled() and level != "impossible" and exploited:
        result["flag"] = flags.flag_for("race-condition", level)

    return jsonify(result), status_code


@lab_api.route("/coupon/balance", methods=["GET"])
def coupon_balance_endpoint():
    """GET /api/coupon/balance — view current user balance."""
    user_id = int(request.args.get("user_id", 1))
    return jsonify({"user_id": user_id, "balance": get_balance(user_id)}), 200


@lab_api.route("/coupon/reset", methods=["POST"])
def coupon_reset_endpoint():
    """POST /api/coupon/reset — reset user balance and coupons."""
    user_id = int(request.args.get("user_id", 1))
    reset_user(user_id)
    return jsonify({"status": "success", "message": "User state reset"}), 200
