"""api-auth scenario routes."""
from flask import request, jsonify, session

from lab_api import lab_api
from scenarios import get_level, lab_enabled
from scenarios import flags
from scenarios.api_auth.vuln import (
    FAKE_USERS, check_login, get_user, list_users, check_admin
)


@lab_api.route("/users/login", methods=["POST"])
def api_auth_login():
    data = request.form if not request.is_json else (request.get_json(silent=True) or {})
    user = check_login(data.get("username",""), data.get("password",""))
    if not user:
        return jsonify({"error": "invalid credentials"}), 401
    session["api_user_id"]   = user["id"]
    session["api_username"]  = user["username"]
    session["api_user_role"] = user["role"]
    return jsonify({"user_id": user["id"], "username": user["username"], "role": user["role"]})


@lab_api.route("/users/logout", methods=["POST"])
def api_auth_logout():
    session.pop("api_user_id", None)
    return jsonify({"ok": True})


@lab_api.route("/users/", methods=["GET"])
def api_auth_list_users():
    if "api_user_id" not in session:
        return jsonify({"error": "not authenticated"}), 401
    level = get_level()
    result = list_users(session.get("api_user_role","user"), level)
    api_flag = None
    if lab_enabled() and level != "impossible" and session.get("api_user_role") != "admin":
        data = result.get("data", [])
        if any("salary" in u for u in (data or [])):
            api_flag = flags.flag_for("api-auth", level)
    resp = {"data": result.get("data"), "level": level}
    if api_flag: resp["flag"] = api_flag
    return jsonify(resp)


@lab_api.route("/users/<int:user_id>", methods=["GET","POST"])
def api_auth_get_user(user_id):
    if "api_user_id" not in session:
        return jsonify({"error": "not authenticated"}), 401
    level = get_level()
    sid  = session.get("api_user_id")
    srol = session.get("api_user_role","user")
    body_uid  = None
    x_role    = request.headers.get("X-Role")
    role_qry  = request.args.get("role")
    if request.method == "POST":
        body = request.form if not request.is_json else (request.get_json(silent=True) or {})
        try: body_uid = int(body.get("user_id", sid))
        except (TypeError, ValueError): body_uid = sid

    result = get_user(sid, srol, user_id, body_uid, x_role, role_qry, level)
    if not result["allowed"]:
        return jsonify({"error": result["reason"]}), 403

    api_flag = None
    data = result.get("data") or {}
    if (lab_enabled() and level != "impossible" and srol != "admin"
            and user_id != sid and "salary" in data):
        api_flag = flags.flag_for("api-auth", level)
    resp = {"data": data, "level": level}
    if api_flag: resp["flag"] = api_flag
    return jsonify(resp)


@lab_api.route("/admin/users", methods=["GET"])
def api_auth_admin_users():
    if "api_user_id" not in session:
        return jsonify({"error": "not authenticated"}), 401
    level = get_level()
    srol  = session.get("api_user_role","user")
    x_role   = request.headers.get("X-Role")
    role_qry = request.args.get("role")
    if not check_admin(srol, role_qry, x_role, level):
        return jsonify({"error": "forbidden"}), 403

    api_flag = None
    if lab_enabled() and level != "impossible" and srol != "admin":
        api_flag = flags.flag_for("api-auth", level)

    all_users = [dict(u, password="[hidden]") for u in FAKE_USERS.values()]
    resp = {"data": all_users, "level": level}
    if api_flag: resp["flag"] = api_flag
    return jsonify(resp)
