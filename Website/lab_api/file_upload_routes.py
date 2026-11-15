"""File-upload scenario routes — POST /api/upload.

The flaw lives in scenarios/file_upload/vuln.py.  This module is thin glue.
"""
import os

from flask import request, jsonify

from lab_api import lab_api
from scenarios import get_level, lab_enabled
from scenarios import flags
from scenarios.file_upload.vuln import validate_upload, store_file, _safe_ext, _IMAGE_EXTENSIONS, is_webshell_content


@lab_api.route("/upload", methods=["POST"])
def file_upload():
    """
    POST /api/upload — accept a file upload and return metadata.

    Expects multipart/form-data with a 'file' field.
    Returns JSON: {"filename": str, "size": int, "stored_as": str, ...}
    Files are served with Content-Disposition: attachment to prevent browser
    execution.  Files are NEVER executed — SIMULATED impact only.
    """
    level = get_level()

    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    upload = request.files["file"]
    filename = upload.filename or "upload"
    content_type = upload.content_type or upload.mimetype or ""
    content = upload.read()

    allowed, reason = validate_upload(filename, content_type, content, level)

    if not allowed:
        return jsonify({
            "error": "Upload rejected",
            "reason": reason,
            "filename": filename,
            "level": level,
        }), 400

    # Store the file (always sandboxed, never executed)
    stored_as = store_file(filename, content)

    # Determine if this upload bypassed image controls (flag condition):
    # file extension is NOT in the image allowlist → defence bypassed
    ext = _safe_ext(filename)
    has_script_ext = any(p in filename.lower() for p in [".php", ".py", ".sh", ".exe", ".jsp", ".pl", ".cgi", ".asp"])
    bypassed = (ext not in _IMAGE_EXTENSIONS) or (has_script_ext or is_webshell_content(content))

    upload_flag = None
    if lab_enabled() and level != "impossible" and bypassed:
        upload_flag = flags.flag_for("file-upload", level)

    resp = {
        "filename": filename,
        "size": len(content),
        "stored_as": stored_as,
        "level": level,
        "content_type": content_type,
    }
    if upload_flag:
        resp["flag"] = upload_flag

    response = jsonify(resp)
    # Content-Disposition: attachment prevents browser from executing the file
    response.headers["Content-Disposition"] = "attachment"
    return response, 200
