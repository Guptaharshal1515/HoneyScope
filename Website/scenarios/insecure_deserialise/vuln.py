"""Scenario: Insecure Deserialization (CWE-502, MITRE T1059)

Simulates deserialization vulnerabilities without any real code execution.
All execution impact is entirely simulated in-process.

Difficulty levels:
  low        : Simulates insecure pickle/binary deserialization.
               Detects simulated pickle payloads (e.g. cos\\nsystem or base64 gadget)
               and simulates execution.
  medium     : Custom JSON class instantiator. Blocks direct system commands, but accepts
               diagnostic gadgets like 'DiagnosticGadget'.
  high       : Class allowlist using naive startswith('SafeConfig').
               Bypassable via 'SafeConfigGadget_Exec'.
  impossible : Strict JSON schema validation; only expected primitive fields extracted.
               Dynamic type instantiation is completely removed.

CONTAINMENT:
  - No external process execution, dynamic code interpretation, or native unpickling.
  - All command results and object restorations are synthetic.
"""
import base64
import json
import re

# SIMULATED: safe dummy responses for fake command execution
SIMULATED_OUTPUTS = {
    "whoami": "app_user",
    "id": "uid=1001(app_user) gid=1001(app_user) groups=1001(app_user)",
    "uname -a": "Linux honeyscope-sandbox 6.1.0-simulated #1 SMP x86_64",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\napp_user:x:1001:1001::/home/app_user:/bin/sh",
}


def _simulated_run(cmd: str) -> str:
    """Return simulated command execution output. NEVER runs actual commands."""
    cmd_clean = cmd.strip()
    return SIMULATED_OUTPUTS.get(cmd_clean, f"[SIMULATED EXECUTION: {cmd_clean}]")


def deserialize_payload(payload_raw: str, level: str) -> tuple[dict, bool]:
    """
    Deserialize the untrusted payload.
    Returns (result_dict, exploited: bool).
    """
    if not payload_raw or not isinstance(payload_raw, str):
        return {"error": "Missing or invalid payload string"}, False

    # Bound size to prevent resource exhaustion
    if len(payload_raw) > 8192:
        return {"error": "Payload exceeds maximum length"}, False

    # --- Low Level: Simulated Pickle / Binary stream ---
    if level == "low":
        decoded = payload_raw
        # Check if base64 encoded
        try:
            raw_bytes = base64.b64decode(payload_raw)
            decoded = raw_bytes.decode("latin1", errors="ignore")
        except Exception:
            decoded = payload_raw

        # Detect simulated pickle gadget (cos\nsystem or cposix\nsystem or similar)
        # SIMULATED: purely string pattern match, never real deserialization
        pickle_match = re.search(r"c(?:os|posix)\s*\n\s*system\s*\n\s*(?:\(S'([^']+)'|q\s*\x00\s*\x00\s*S'([^']+)')", decoded)
        if not pickle_match:
            pickle_match = re.search(r"(?:cos\s+system|c__builtin__\s+exec)\s*\(?['\"]?([^'\"\n)]*)", decoded)

        if pickle_match or "cos\nsystem" in decoded or "cos system" in decoded:
            cmd = "id"
            if pickle_match:
                cmd = pickle_match.group(1) or pickle_match.group(2) or "id"
            # SIMULATED: gadget execution simulated
            return {
                "status": "success",
                "object_type": "RestoredPickleSession",
                "simulated_exec": True,
                "command": cmd,
                "output": _simulated_run(cmd),
            }, True

        return {
            "status": "success",
            "object_type": "RestoredPickleSession",
            "data": "Valid session data restored",
        }, False

    # --- JSON-based deserializers for medium, high, impossible ---
    try:
        data = json.loads(payload_raw)
    except Exception:
        return {"error": "Invalid JSON payload"}, False

    if not isinstance(data, dict):
        return {"error": "JSON payload must be an object"}, False

    # --- Medium Level: Gadget blocklist ---
    if level == "medium":
        cls_name = data.get("__class__", "")
        if not cls_name:
            return {"status": "success", "data": data}, False

        # Naive blocklist
        blocked = ["os" + ".system", "sub" + "process", "ev" + "al", "ex" + "ec", "posix"]
        if any(b in cls_name.lower() for b in blocked):
            return {"error": f"SecurityException: Forbidden class '{cls_name}'"}, False

        # Flaw: diagnostic gadget allowed
        if cls_name in ("DiagnosticGadget", "SystemProbe", "CommandRunner"):
            cmd = data.get("cmd", "whoami")
            return {
                "status": "success",
                "object_type": cls_name,
                "simulated_exec": True,
                "command": cmd,
                "output": _simulated_run(cmd),
            }, True

        return {"status": "success", "object_type": cls_name, "data": data}, False

    # --- High Level: Insecure startswith check ---
    if level == "high":
        cls_name = data.get("__class__", "")
        if not cls_name:
            return {"status": "success", "data": data}, False

        # Flaw: checks prefix with startswith
        if not (cls_name.startswith("SafeConfig") or cls_name.startswith("UserProfile")):
            return {"error": f"SecurityException: Class '{cls_name}' is not allowed"}, False

        # Gadget with prefix bypass
        if "Gadget" in cls_name or "Exec" in cls_name or "Probe" in cls_name:
            cmd = data.get("cmd", "id")
            return {
                "status": "success",
                "object_type": cls_name,
                "simulated_exec": True,
                "command": cmd,
                "output": _simulated_run(cmd),
            }, True

        return {"status": "success", "object_type": cls_name, "data": data}, False

    # --- Impossible Level: Safe strict parsing ---
    if level == "impossible":
        # Strictly whitelist allowed fields and types; ignore all magic attributes
        safe_obj = {}
        if "username" in data and isinstance(data["username"], str):
            safe_obj["username"] = data["username"][:64]
        if "theme" in data and isinstance(data["theme"], str):
            safe_obj["theme"] = data["theme"][:16]
        if "role" in data and isinstance(data["role"], str):
            safe_obj["role"] = "user"  # Enforce default role

        return {
            "status": "success",
            "object_type": "SafeUserProfile",
            "data": safe_obj,
        }, False

    return {"error": f"Unknown level: {level}"}, False
