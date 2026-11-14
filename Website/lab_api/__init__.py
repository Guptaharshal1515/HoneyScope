"""lab_api — Flask Blueprint for Phase-2 HoneyScope lab scenarios.

Registered in app.py with url_prefix="/api".
Only active when HONEYSCOPE_LAB=1.  Normal honeypot mode never imports this.
"""
from flask import Blueprint

lab_api = Blueprint("lab_api", __name__, url_prefix="/api")

# Route modules are imported below so they register on the blueprint.
from lab_api import jwt_routes   # noqa: E402, F401
