# Insecure File Upload (CWE-434)

## Scenario Overview
| Attribute | Value |
|---|---|
| ID | `file-upload` |
| CWE | CWE-434: Unrestricted Upload of File with Dangerous Type |
| OWASP | A04:2021 Insecure Design |
| MITRE ATT&CK | T1105 (Ingress Tool Transfer) |
| Endpoint | `POST /api/upload` |

## Difficulty Levels

| Level | Server Defence | Attacker Technique |
|---|---|---|
| `low` | None. All files and extensions accepted. | Upload a script (`.php`, `.py`, `.sh`). |
| `medium` | Content-Type header checked (`image/*` required). | Spoof `Content-Type: image/jpeg` while uploading a script. |
| `high` | Extension allowlist (.jpg, .jpeg, .png, .gif) checked on last extension dot. Content-Type checked. Content not inspected. | Double extension (e.g. `webshell.php.jpg`) or embedding script in image. |
| `impossible` | Extension allowlist + Content-Type validation + magic byte signature verification + UUID filename + size limit. | None (safe reference implementation). |

## Containment
- Uploaded files are written to a throwaway temporary directory and **NEVER executed**.
- Served with `Content-Disposition: attachment`.
- Strict file size limit (64 KB).

## Blue Team Notes
- Monitor file uploads for executable script extensions (`.php`, `.py`, `.sh`, `.exe`, `.jsp`).
- Detect discrepancies between declared `Content-Type` and file extension / magic bytes.
- Wazuh rules: `100514` (script upload), `100515` (Content-Type spoofing / double extension).
- Sigma rule: `rules/sigma_file_upload.yml`.
