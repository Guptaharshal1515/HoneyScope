# Injection & Traversal Flaws (CWE-78, CWE-22, CWE-611)

## Scenario Overview
| Attribute | Value |
|---|---|
| ID | `cmd-inject` |
| CWE | CWE-78: OS Command Injection, CWE-22: Path Traversal, CWE-611: XXE |
| OWASP | A03:2021 Injection |
| MITRE ATT&CK | T1059.004 (Unix Shell) |
| Endpoint | `POST /api/cmd`, `GET /api/file`, `POST /api/xml` |

## Difficulty Levels

| Level | Server Defence | Attacker Technique |
|---|---|---|
| `low` | No input validation. Unbounded separators (`;`, `&&`, `\|`). | Semicolon or pipe command chaining (`127.0.0.1; id`). |
| `medium` | Naive blocklist against `;` and `&&`. | Pipe character chaining (`127.0.0.1 \| whoami`). |
| `high` | Unanchored IP prefix regex without end-of-string anchor. | Append command after valid IP prefix (`127.0.0.1; whoami`). |
| `impossible` | Strict anchored alphanumeric/IP regex with parameterised invocation. Basename-only files. DTD/entities disabled. | None (safe reference implementation). |

## Containment
- **SIMULATED ONLY:** Never calls `subprocess`, `os.system`, or shell interpreters.
- In-memory virtual filesystem for path traversal tests.
- In-memory virtual entity resolver for XXE tests (no real network or disk access).

## Blue Team Notes
- Monitor diagnostic tools for command chaining metacharacters (`;`, `\|`, `&&`).
- Detect traversal sequences (`../`, `/etc/passwd`).
- Detect XML entity declarations (`<!ENTITY`, `SYSTEM`).
- Wazuh rules: `100520` (command injection), `100521` (traversal / XXE).
- Sigma rule: `rules/sigma_cmd_inject.yml`.
