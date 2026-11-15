"""Scenario: Injection & Traversal Flaws (CWE-78, CWE-22, CWE-611, MITRE T1059.004)

Simulated command interpreter, virtual file system, and simulated XML parser.
NO real host commands, filesystem calls, or external network requests are ever made.

Difficulty levels:
  low        : Command injection via shell metacharacters (; && |).
               Path traversal via ../ or absolute paths.
               XXE via <!ENTITY ... SYSTEM ...>.
  medium     : Command injection: naive blocklist for ';' and '&&'. Pipe '|' and newline work.
               Path traversal: naive single-pass replace('../', ''). '....//' works.
               XXE: case-sensitive check for 'SYSTEM'. 'system' works.
  high       : Command injection: unanchored regex allows command after valid IP.
               Path traversal: blocks '..' but allows absolute paths like '/etc/passwd'.
               XXE: blocks 'SYSTEM', but internal parameter entity works.
  impossible : Strict allowlists, parameterised calls, basename-only file access,
               and entity resolution disabled.

CONTAINMENT:
  - In-memory virtual filesystem only.
  - In-process command simulator only (no external process spawning).
  - Virtual entities only (no outbound HTTP or real file reading).
"""
import re

VIRTUAL_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\ntechcorp:x:1000:1000:TechCorp User:/home/techcorp:/bin/sh",
    "/etc/shadow": "root:$6$fakehash$abcdef123456:19000:0:99999:7:::",
    "/var/log/app.log": "2026-11-15 10:00:00 INFO System started successfully",
    "welcome.txt": "Welcome to the TechCorp Diagnostics API.",
    "status.txt": "All diagnostics services operating within normal parameters.",
}

SIMULATED_COMMANDS = {
    "id": "uid=1000(techcorp) gid=1000(techcorp) groups=1000(techcorp)",
    "whoami": "techcorp",
    "uname": "Linux honeyscope-diagnostic 6.1.0-simulated",
    "uname -a": "Linux honeyscope-diagnostic 6.1.0-simulated #1 SMP x86_64",
    "cat /etc/passwd": VIRTUAL_FS["/etc/passwd"],
    "cat /etc/shadow": VIRTUAL_FS["/etc/shadow"],
}


def _run_simulated_command(cmd: str) -> str:
    """Execute within simulated command interpreter. Never invokes real host shell."""
    c = cmd.strip()
    if c in SIMULATED_COMMANDS:
        return SIMULATED_COMMANDS[c]
    for key, val in SIMULATED_COMMANDS.items():
        if c.startswith(key):
            return val
    return f"[SIMULATED: executed '{c}']"


# ---------------------------------------------------------------------------
# 1. Command Injection (POST /api/cmd)
# ---------------------------------------------------------------------------

def execute_cmd(target: str, level: str) -> tuple[dict, bool]:
    """Execute simulated diagnostic tool (ping/traceroute)."""
    if not target or not isinstance(target, str):
        return {"error": "Missing target parameter"}, False

    if len(target) > 512:
        return {"error": "Target parameter too long"}, False

    exploited = False
    injected_cmd = None

    if level == "low":
        # Any shell separator executes secondary command
        # # SIMULATED: parsed in memory, never sent to real shell
        match = re.search(r"[;&|]\s*([a-zA-Z0-9_\- /]+)", target)
        if match:
            injected_cmd = match.group(1).strip()
            exploited = True

    elif level == "medium":
        # Naive blocklist against ';' and '&&'
        if ";" in target or "&&" in target:
            return {"error": "Invalid character detected in target"}, False
        # Flaw: pipe '|' and newline are not blocked
        match = re.search(r"[|\n]\s*([a-zA-Z0-9_\- /]+)", target)
        if match:
            injected_cmd = match.group(1).strip()
            exploited = True

    elif level == "high":
        # Unanchored regex checking for IP prefix
        # Flaw: re.match without end anchor ($) allows trailing separators
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            return {"error": "Target must start with a valid IPv4 address"}, False
        match = re.search(r"[;&|]\s*([a-zA-Z0-9_\- /]+)", target)
        if match:
            injected_cmd = match.group(1).strip()
            exploited = True

    elif level == "impossible":
        # Strict validation: alphanumeric hostname or strict IPv4 only
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9.-]+$", target):
            return {"error": "Invalid target: must be a strict IP address or hostname"}, False

    if injected_cmd:
        output = _run_simulated_command(injected_cmd)
        return {
            "status": "success",
            "simulated_output": f"PING {target} 56(84) bytes of data.\n" + output,
            "injected_cmd": injected_cmd,
        }, exploited

    return {
        "status": "success",
        "simulated_output": f"PING {target} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms",
    }, False


# ---------------------------------------------------------------------------
# 2. Path Traversal (GET /api/file?name=...)
# ---------------------------------------------------------------------------

def read_virtual_file(filename: str, level: str) -> tuple[dict, bool]:
    """Read a file from the in-memory virtual filesystem."""
    if not filename or not isinstance(filename, str):
        return {"error": "Missing filename parameter"}, False

    exploited = False
    resolved = filename

    if level == "low":
        # Direct lookup in virtual filesystem
        resolved = filename

    elif level == "medium":
        # Naive single-pass replacement of '../'
        resolved = filename.replace("../", "")

    elif level == "high":
        # Blocks '..' but allows absolute paths
        if ".." in filename:
            return {"error": "Path traversal sequences are forbidden"}, False
        resolved = filename

    elif level == "impossible":
        # Basename only and allowlist
        import os
        base = os.path.basename(filename)
        if base not in ("welcome.txt", "status.txt"):
            return {"error": "Access to requested file is forbidden"}, False
        resolved = base

    # Check virtual filesystem
    import posixpath
    if resolved in VIRTUAL_FS:
        lookup = resolved
    else:
        lookup = posixpath.normpath(posixpath.join("/var/www", resolved))

    content = VIRTUAL_FS.get(resolved) or VIRTUAL_FS.get(lookup)
    if content is not None:
        if "/etc/passwd" in resolved or "/etc/shadow" in resolved or "/etc/passwd" in lookup:
            exploited = True
        return {"status": "success", "filename": resolved, "content": content}, exploited

    return {"error": f"File '{filename}' not found in virtual filesystem"}, False


# ---------------------------------------------------------------------------
# 3. XXE (POST /api/xml)
# ---------------------------------------------------------------------------

def parse_xml_payload(xml_data: str, level: str) -> tuple[dict, bool]:
    """Parse XML payload with simulated entity resolution."""
    if not xml_data or not isinstance(xml_data, str):
        return {"error": "Missing XML payload"}, False

    exploited = False

    if level == "impossible":
        # Strictly forbid DTD and entities
        if "<!DOCTYPE" in xml_data or "<!ENTITY" in xml_data:
            return {"error": "Custom DTD and external entities are forbidden"}, False
        return {"status": "success", "parsed": "XML processed safely without DTDs"}, False

    if level == "high":
        # Case-insensitive check for SYSTEM keyword
        if re.search(r"SYSTEM", xml_data, re.IGNORECASE):
            return {"error": "External SYSTEM entities are prohibited"}, False
        # Parameter entities or internal entity expansion allowed
        entity_match = re.search(r'<!ENTITY\s+([a-zA-Z0-9_-]+)\s+["\']([^"\']+)["\']', xml_data)
        if entity_match:
            ent_name = entity_match.group(1)
            ent_val = entity_match.group(2)
            if "flag" in ent_val.lower() or "secret" in ent_val.lower() or "passwd" in ent_val.lower():
                exploited = True
            return {"status": "success", "result": f"Resolved &{ent_name}; to '{ent_val}'"}, exploited

    if level == "medium":
        # Case-sensitive check for "SYSTEM"
        if "SYSTEM" in xml_data:
            return {"error": "SYSTEM entity blocked by security filter"}, False
        # Flaw: "system" (lowercase) passes
        match = re.search(r'<!ENTITY\s+([a-zA-Z0-9_-]+)\s+system\s+["\']file://([^"\']+)["\']', xml_data)
        if match:
            ent_name = match.group(1)
            target_path = match.group(2)
            file_res, exp = read_virtual_file(target_path, "low")
            return {"status": "success", "result": file_res.get("content", "")}, True

    if level == "low":
        # Any SYSTEM entity processed against virtual filesystem
        match = re.search(r'<!ENTITY\s+([a-zA-Z0-9_-]+)\s+SYSTEM\s+["\'](?:file://)?([^"\']+)["\']', xml_data, re.IGNORECASE)
        if match:
            ent_name = match.group(1)
            target_path = match.group(2)
            file_res, exp = read_virtual_file(target_path, "low")
            return {"status": "success", "result": file_res.get("content", "")}, True

    return {"status": "success", "parsed": "XML processed"}, False
