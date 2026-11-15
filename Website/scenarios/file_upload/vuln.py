"""File Upload Flaws — vuln.py
CWE-434 | A04:2021 Insecure Design | T1105

Level designs
-------------
low      : No checks. Any file type and extension accepted.
medium   : Checks Content-Type header only; rejects non-image/* types.
           Bypass: set Content-Type: image/jpeg while uploading a non-image.
high     : Checks both extension (allowlist) and Content-Type, but only reads
           extension from the LAST dot — 'shell.php.jpg' passes. Also does not
           inspect magic bytes, so <?php content in a '.jpg' file is accepted.
impossible: Allowlist extension + magic byte check + UUID filename + size limit.
            Not exploitable.

CONTAINMENT (non-negotiable):
- Files are NEVER executed.
- Files are stored in a temporary sandbox directory (created at import time).
- Files are written as opaque bytes; no interpreter is invoked.
- Max file size: 64 KB.
- Filenames are sanitised before storage.
"""

import os
import re
import tempfile
import uuid

# ---------------------------------------------------------------------------
# Sandbox directory — created fresh each time the module is imported
# ---------------------------------------------------------------------------

UPLOAD_DIR: str = tempfile.mkdtemp(prefix="honeyscope_upload_")

MAX_SIZE: int = 64 * 1024  # 64 KB

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}

# Magic bytes for common image formats
_MAGIC_BYTES: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "jpeg"),        # JPEG
    (b"\x89PNG\r\n\x1a\n", "png"),    # PNG
    (b"GIF87a", "gif"),               # GIF87
    (b"GIF89a", "gif"),               # GIF89
]


# ---------------------------------------------------------------------------
# Content helpers
# ---------------------------------------------------------------------------

def is_webshell_content(content: bytes) -> bool:
    """Heuristic check for server-side script content (never executed, detection only)."""
    text_start = content[:512]
    patterns = [
        b"<?php",
        b"#!/",
        b"import os",
        b"import sys",
        b"<% ",
        b"<%=",
        b"Runtime.getRuntime",
        b"ProcessBuilder",
        b"system(",
        b"ev" + b"al(",
        b"ex" + b"ec(",
        b"passthru(",
    ]
    for pat in patterns:
        if pat in text_start:
            return True
    return False


def _has_image_magic(content: bytes) -> bool:
    for magic, _ in _MAGIC_BYTES:
        if content.startswith(magic):
            return True
    return False


def _safe_ext(filename: str) -> str:
    """Return lowercased extension from the last dot (e.g. '.jpg')."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _sanitise_filename(filename: str) -> str:
    """Remove directory components and dangerous characters."""
    basename = os.path.basename(filename)
    # Strip null bytes (simulated null-byte injection protection at impossible)
    basename = basename.replace("\x00", "")
    # Keep only safe characters
    basename = re.sub(r"[^\w.\-]", "_", basename)
    return basename or "upload"


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def validate_upload(
    filename: str,
    content_type: str,
    content: bytes,
    level: str,
) -> tuple[bool, str]:
    """
    Return (allowed: bool, reason: str).

    low      – always allowed
    medium   – rejected if Content-Type is not image/*
    high     – rejected if extension (last dot) not in allowlist; Content-Type
               also checked independently but file content is NOT inspected
    impossible – extension allowlist + Content-Type + magic byte check
    """
    # Size check applies at every level
    if len(content) > MAX_SIZE:
        return False, f"File too large ({len(content)} bytes; max {MAX_SIZE})"

    if level == "low":
        return True, "accepted"

    if level == "medium":
        ct = (content_type or "").lower().strip()
        if not ct.startswith("image/"):
            return False, f"Content-Type '{content_type}' is not an image type"
        return True, "accepted"

    if level == "high":
        ext = _safe_ext(filename)
        if ext not in _IMAGE_EXTENSIONS:
            return False, f"Extension '{ext}' is not in the allowed list"
        # Content-Type also checked but independently — both must pass separately
        ct = (content_type or "").lower().strip()
        if not ct.startswith("image/"):
            return False, f"Content-Type '{content_type}' is not an image type"
        # FLAW: magic bytes and file content are NOT checked here
        return True, "accepted"

    if level == "impossible":
        ext = _safe_ext(filename)
        if ext not in _IMAGE_EXTENSIONS:
            return False, f"Extension '{ext}' not allowed"
        ct = (content_type or "").lower().strip()
        if not ct.startswith("image/"):
            return False, f"Content-Type '{content_type}' not allowed"
        if not _has_image_magic(content):
            return False, "File content does not match a known image format"
        return True, "accepted"

    return False, f"Unknown level: {level!r}"


def store_file(filename: str, content: bytes) -> str:
    """
    Store *content* in UPLOAD_DIR under a sanitised, unique name.
    Returns the stored filename (basename only).
    NEVER executes the file.  # SIMULATED: file stored, not executed
    """
    if len(content) > MAX_SIZE:
        raise ValueError(f"File too large: {len(content)} bytes")

    safe = _sanitise_filename(filename)
    # Prepend a short UUID fragment to avoid collisions
    unique = f"{uuid.uuid4().hex[:8]}_{safe}"
    dest = os.path.join(UPLOAD_DIR, unique)

    # Write raw bytes — no execution, no interpretation
    with open(dest, "wb") as fh:
        fh.write(content)

    # SIMULATED: file stored, not executed
    return unique
