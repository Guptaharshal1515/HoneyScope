# Insecure Deserialization (CWE-502)

## Scenario Overview
| Attribute | Value |
|---|---|
| ID | `insecure-deserialise` |
| CWE | CWE-502: Deserialization of Untrusted Data |
| OWASP | A08:2021 Software and Data Integrity Failures |
| MITRE ATT&CK | T1059 (Command and Scripting Interpreter) |
| Endpoint | `POST /api/deserialise` |

## Difficulty Levels

| Level | Server Defence | Attacker Technique |
|---|---|---|
| `low` | Insecure binary stream deserialization (pickle simulation). | Craft a callable gadget (`cos\nsystem`). |
| `medium` | JSON custom class instantiator with blocklist against direct OS calls. | Use an unblocked diagnostic gadget (`DiagnosticGadget`). |
| `high` | Class allowlist using naive `startswith('SafeConfig')`. | Prefix-match bypass using `SafeConfigGadget_Exec`. |
| `impossible` | Strict schema validation with primitive data types only. Dynamic type instantiation removed. | None (safe reference implementation). |

## Containment
- **SIMULATED ONLY:** Never calls `pickle.loads`, `eval`, `exec`, `os.system`, or `subprocess`.
- Synthetic command output returned in-memory.
- Strict size bound on incoming payloads.

## Blue Team Notes
- Look for binary stream patterns (e.g. Python pickle opcodes, Java serialization magic bytes `rO0AB`).
- Monitor JSON endpoints for `__class__`, `__proto__`, or gadget class declarations.
- Wazuh rules: `100518` (binary stream/pickle), `100519` (class gadget).
- Sigma rule: `rules/sigma_insecure_deserialise.yml`.
