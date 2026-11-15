"""Scenario: GraphQL Vulnerabilities (CWE-284, MITRE T1190)

Simulated in-memory GraphQL endpoint demonstrating common API abuse vectors:
  - Introspection enabled in production (schema leakage)
  - Unbounded query depth (resource consumption / DoS risk)
  - Query batching abuse (bypassing rate limits)
  - Field alias abuse (multiplying operations in one query)
  - Broken field-level authorization on sensitive types

Difficulty levels:
  low        : Introspection enabled, unbounded depth, unlimited batching,
               adminData query accessible without authorization.
  medium     : Introspection disabled (__schema / __type rejected),
               adminData field blocked, but batching and deep queries allowed.
  high       : Depth limit (max depth 5) and batch limit (max 2) enforced,
               but alias-based amplification (> 3 aliases) is permitted.
  impossible : Strict limits: depth <= 3, batch size <= 1, aliases <= 3,
               introspection disabled, adminData strictly forbidden.

CONTAINMENT:
  - In-process lightweight parser, no external libraries or network calls.
  - Safe bounds on execution loops and output size.
  - Data is entirely synthetic.
"""
import re

FAKE_USERS = {
    1: {"id": 1, "name": "Alice Admin", "role": "admin"},
    2: {"id": 2, "name": "Bob Analyst", "role": "analyst"},
    3: {"id": 3, "name": "Charlie User", "role": "user"},
}

SCHEMA_TYPES = [
    {"name": "Query", "fields": ["user", "me", "status", "adminData"]},
    {"name": "User", "fields": ["id", "name", "role"]},
    {"name": "Status", "fields": ["status", "version"]},
    {"name": "AdminData", "fields": ["secretKey", "backupCode"]},
]


def calculate_depth(query: str) -> int:
    """Calculate the maximum nesting depth of curly braces in the query."""
    max_d = 0
    curr_d = 0
    for char in query:
        if char == "{":
            curr_d += 1
            if curr_d > max_d:
                max_d = curr_d
        elif char == "}":
            if curr_d > 0:
                curr_d -= 1
    return max_d


def count_aliases(query: str) -> int:
    """Count field aliases (e.g. `a1: user(id: 1)`)."""
    # Matches patterns like `alias_name: field_name`
    matches = re.findall(r"\b([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_]+)\b", query)
    # Exclude common argument keys like id: 1
    aliases = [m for m in matches if m[1] not in ("id", "limit", "offset", "true", "false", "null")]
    return len(aliases)


def execute_single_query(query: str, level: str, role: str = "guest") -> dict:
    """Execute a single GraphQL query string according to current difficulty level."""
    if not query or not isinstance(query, str):
        return {"errors": [{"message": "Must provide query string"}]}

    # Bounded query length to prevent DoS
    if len(query) > 4096:
        return {"errors": [{"message": "Query exceeds maximum allowed length"}]}

    q_lower = query.lower()

    # 1. Depth validation
    depth = calculate_depth(query)
    if level in ("high", "impossible") and depth > (3 if level == "impossible" else 5):
        return {"errors": [{"message": f"Query depth limit exceeded (max {3 if level == 'impossible' else 5}, got {depth})"}]}

    # 2. Alias validation
    aliases = count_aliases(query)
    if level == "impossible" and aliases > 3:
        return {"errors": [{"message": f"Query alias limit exceeded (max 3, got {aliases})"}]}

    # 3. Introspection check
    has_introspection = "__schema" in q_lower or "__type" in q_lower
    if has_introspection:
        if level != "low":
            return {"errors": [{"message": "GraphQL introspection is disabled."}]}
        return {
            "data": {
                "__schema": {
                    "types": SCHEMA_TYPES
                }
            }
        }

    # 4. Field-level auth on adminData
    if "admindata" in q_lower:
        if level in ("medium", "high", "impossible") and role != "admin":
            return {"errors": [{"message": "Unauthorized access to adminData field."}]}
        return {
            "data": {
                "adminData": {
                    "secretKey": "CONFIDENTIAL_LAB_KEY_9981",
                    "backupCode": "4819"
                }
            }
        }

    # 5. Handle user queries and aliases
    res_data = {}
    if "user" in q_lower:
        # Check for multiple aliased user lookups
        alias_matches = re.findall(r"\b([a-zA-Z0-9_]+)\s*:\s*user\s*\(\s*id\s*:\s*(\d+)\s*\)", query, re.IGNORECASE)
        if alias_matches:
            for alias, uid_str in alias_matches:
                uid = int(uid_str)
                user = FAKE_USERS.get(uid, {"id": uid, "name": "Unknown", "role": "guest"})
                res_data[alias] = user
        else:
            # Single user query
            uid_match = re.search(r"user\s*\(\s*id\s*:\s*(\d+)\s*\)", query, re.IGNORECASE)
            uid = int(uid_match.group(1)) if uid_match else 1
            res_data["user"] = FAKE_USERS.get(uid, {"id": uid, "name": "Unknown", "role": "guest"})

    if "me" in q_lower:
        res_data["me"] = {"username": "student", "role": role}

    if "status" in q_lower:
        res_data["status"] = {"status": "ok", "version": "1.0.0"}

    if not res_data:
        res_data["result"] = "Operation completed"

    return {"data": res_data}


def execute_graphql(payload, level: str, role: str = "guest") -> tuple[dict | list, bool]:
    """
    Main entry point for GraphQL execution.
    Returns (response_json, exploited: bool).
    """
    exploited = False

    # Handle batch queries (JSON array)
    if isinstance(payload, list):
        # Bound batch size
        if len(payload) > 50:
            return {"errors": [{"message": "Batch size exceeds maximum limit"}]}, False

        if level == "impossible":
            return {"errors": [{"message": "Batch querying is disabled"}]}, False
        if level == "high" and len(payload) > 2:
            return {"errors": [{"message": "Batch limit exceeded (max 2 queries)"}]}, False

        results = []
        for item in payload:
            q = item.get("query", "") if isinstance(item, dict) else ""
            res = execute_single_query(q, level, role)
            results.append(res)

        # Batch exploitation triggered at medium
        if len(payload) > 1 and level in ("low", "medium"):
            exploited = True

        return results, exploited

    # Handle single query (JSON object)
    if isinstance(payload, dict):
        query = payload.get("query", "")
        res = execute_single_query(query, level, role)

        # Determine exploitation
        q_lower = query.lower()
        if level == "low" and ("__schema" in q_lower or "admindata" in q_lower):
            if "data" in res:
                exploited = True
        elif level == "high":
            if count_aliases(query) > 3 and "data" in res:
                exploited = True
        elif level == "medium":
            if calculate_depth(query) > 5 and "data" in res:
                exploited = True

        return res, exploited

    return {"errors": [{"message": "Invalid request body format"}]}, False
