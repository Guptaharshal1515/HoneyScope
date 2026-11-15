"""lab_api — Flask Blueprint for Phase-2 HoneyScope lab scenarios.

Registered in app.py with url_prefix="/api".
Only active when HONEYSCOPE_LAB=1.  Normal honeypot mode never imports this.
"""
from flask import Blueprint

lab_api = Blueprint("lab_api", __name__, url_prefix="/api")

# Route modules are imported below so they register on the blueprint.
from lab_api import jwt_routes        # noqa: E402, F401  scenario: jwt-flaws
from lab_api import ssrf_routes       # noqa: E402, F401  scenario: ssrf
from lab_api import api_auth_routes   # noqa: E402, F401  scenario: api-auth
from lab_api import file_upload_routes # noqa: E402, F401  scenario: file-upload
from lab_api import graphql_routes     # noqa: E402, F401  scenario: graphql-abuse
from lab_api import insecure_deserialise_routes # noqa: E402, F401  scenario: insecure-deserialise
from lab_api import cmd_inject_routes           # noqa: E402, F401  scenario: cmd-inject
from lab_api import race_condition_routes       # noqa: E402, F401  scenario: race-condition
from lab_api import llm_routes                  # noqa: E402, F401  scenario: llm-chatbot
