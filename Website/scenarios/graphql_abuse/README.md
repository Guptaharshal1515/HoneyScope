# GraphQL Vulnerabilities (CWE-284)

## Scenario Overview
| Attribute | Value |
|---|---|
| ID | `graphql-abuse` |
| CWE | CWE-284: Improper Access Control |
| OWASP | A01:2021 Broken Access Control |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |
| Endpoint | `POST /api/graphql` |

## Difficulty Levels

| Level | Server Defence | Attacker Technique |
|---|---|---|
| `low` | Introspection enabled, no depth or batch limits, adminData field accessible. | Query `__schema` to inspect the full data model or read `adminData`. |
| `medium` | Introspection disabled and sensitive field blocked, but batching is unrestricted. | Submit an array of queries `[{"query": "..."}, ...]` in one request. |
| `high` | Batch size capped at 2 and query depth limited to 5. | Use field aliases (`a1: user(id: 1), a2: user(id: 2), ...`) to amplify requests. |
| `impossible` | Introspection disabled, batching disallowed, query depth <= 3, aliases <= 3. | None (safe reference implementation). |

## Containment
- In-memory simulated GraphQL schema and data.
- Pure standard library implementation with bounded recursion and loop controls.
- No real database or secrets.

## Blue Team Notes
- Monitor `/api/graphql` for `__schema` or `__type` reconnaissance.
- Detect batch query arrays (`[{"query": ...}]`) used to bypass rate limiters.
- Detect query alias amplification patterns (`alias: field`).
- Wazuh rules: `100516` (introspection/adminData), `100517` (batching/alias amplification).
- Sigma rule: `rules/sigma_graphql_abuse.yml`.
