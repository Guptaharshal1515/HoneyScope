# Server-Side Request Forgery (SSRF)

**Scenario ID:** `ssrf` | **CWE:** CWE-918 | **OWASP:** A10:2021 | **MITRE:** T1090  
**Endpoint:** `POST /api/fetch`

## Goal
Make the server fetch an internal service (`http://internal-metadata/`) that should not be accessible from the outside.

## Levels

| Level | Defence | Gap |
|---|---|---|
| `low` | None — any URL is fetched | Direct request to internal services |
| `medium` | Blocklist: 127.0.0.1, localhost, 169.254.169.254 | Hostname `internal-metadata` not in blocklist |
| `high` | Hostname allowlist (example.com, safe.example.org) | Open redirect on an allowed host chains to internal service |
| `impossible` | Allowlist + https-only + no redirects followed | Not exploitable |

## Hints
- **Low:** What internal services might a cloud server expose locally?
- **Medium:** IP blocklists miss alternative hostnames for the same service.
- **High:** The allowlist looks solid, but what happens when an allowed server redirects your request?
- **Impossible:** Compare redirect handling and allowlist logic across levels.

<details><summary>Solutions</summary>

### Low
`POST /api/fetch url=http://internal-metadata/latest/meta-data/`

### Medium  
`http://internal-metadata/` hostname is not `127.0.0.1` or `localhost` → not blocked.

### High
Register a redirect at an allowed domain → server follows it into internal services.

### Fix (Impossible)
- Allowlist hostnames
- Only allow `https://`
- Never follow HTTP redirects
- Validate after any simulated DNS resolution
</details>

## Blue-team notes
Wazuh rules: **100510–100511**. Detection: requests to `internal-metadata`, `169.254.169.254`, unusual schemes.

**Hardening:** Allowlist outbound destinations; use a dedicated egress proxy; block IMDS at the network layer; never follow redirects in server-side fetch operations.
