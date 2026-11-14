"""JWT scenario routes — /api/auth/login and /api/auth/profile.

The flaw lives in scenarios/jwt_flaws/vuln.py.  This module is thin glue.
"""
import json

from flask import request, jsonify, session

from lab_api import lab_api
from scenarios import get_level, lab_enabled
from scenarios import flags
from scenarios.jwt_flaws.vuln import check_login, issue_token, verify_token


@lab_api.route("/auth/login", methods=["GET", "POST"])
def jwt_login():
    """
    GET  – return a small HTML login form (so learners can open it in browser).
    POST – accept JSON or form data; return a JWT on success.
    """
    if request.method == "GET":
        return (
            "<!doctype html><html><body>"
            "<h2>JWT Auth Demo</h2>"
            "<form method=POST>"
            "username: <input name=username><br>"
            "password: <input name=password type=password><br>"
            "<button type=submit>Login</button></form>"
            "<p><a href='/api/auth/profile'>Profile (paste token as Bearer header)</a></p>"
            "</body></html>"
        )

    # Accept both JSON and form-encoded bodies.
    if request.is_json:
        data = request.get_json(force=True, silent=True) or {}
    else:
        data = request.form

    username = data.get("username", "")
    password = data.get("password", "")

    role = check_login(username, password)
    if role is None:
        return jsonify({"error": "Invalid credentials"}), 401

    level = get_level()
    token = issue_token(username, role, level)
    return jsonify({"token": token, "level": level})


@lab_api.route("/auth/profile", methods=["GET"])
def jwt_profile():
    """
    Returns the decoded JWT claims.  Accepts token via:
      - Authorization: Bearer <token>
      - ?token=<token> query string (convenient for browser testing)
    """
    level = get_level()

    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        token = request.args.get("token", "")

    if not token:
        return jsonify({"error": "No token provided"}), 401

    payload = verify_token(token, level)
    if payload is None:
        return jsonify({"error": "Token verification failed"}), 403

    # Lab flag: grant a flag when the token claims role=admin but no such
    # user exists (i.e. the learner forged the token).
    jwt_flag = None
    if lab_enabled() and level != "impossible":
        claimed_role = payload.get("role", "")
        claimed_sub  = payload.get("sub", "")
        from scenarios.jwt_flaws.vuln import FAKE_USERS
        real_role = FAKE_USERS.get(claimed_sub, {}).get("role")
        # Flag if role was elevated to something not in the user store
        if claimed_role == "admin" and real_role != "admin":
            jwt_flag = flags.flag_for("jwt-flaws", level)

    resp = {"claims": payload, "level": level}
    if jwt_flag:
        resp["flag"] = jwt_flag
    return jsonify(resp)
