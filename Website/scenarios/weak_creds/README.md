# Weak / Default Admin Credentials

**Scenario ID:** `weak-admin`  
**CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)  
**OWASP:** A07:2021 Identification and Authentication Failures  
**MITRE ATT&CK:** [T1078.001 – Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/)  
**Endpoint:** `POST /admin`

---

## Goal

Access the admin dashboard at `/admin/dashboard` by exploiting weak or default credentials on the `/admin` login page.

---

## Levels

| Level | Defence | Gap |
|---|---|---|
| `low` | Credentials hard-coded as `admin` / `admin123` with plain `==`. No rate limiting. | No defence. Default credentials never changed. |
| `medium` | Password moved to env var `HONEYSCOPE_ADMIN_PASS` (default: `admin123`). No rate limiting. | The env var is never set, so the default password still works. |
| `high` | Env-var password + 5-failures-per-minute in-process rate limiter per IP. | Rate limit is per-process and per-IP. A different source IP or server restart bypasses it. |
| `impossible` | `secrets.compare_digest` for constant-time comparison + rate limiting. `HONEYSCOPE_ADMIN_PASS` **must** be set to a strong value. | Not exploitable with the documented payloads when the password is strong. |

---

## Hints (spoiler-free)

- **Low:** What are the most common default admin credential pairs? Check the project README or `Website/payloads.txt`.
- **Medium:** The password is no longer in the source code — but what is the *default* value of the environment variable if it is never set?
- **High:** A rate limiter is active, but it only knows your IP and lives in-process. What two things could reset or circumvent it?
- **Impossible:** Nothing to bypass here. Study the difference between `==` and `secrets.compare_digest` and why the env var must be changed.

---

## Payloads

| Level | Username | Password |
|---|---|---|
| low | `admin` | `admin123` |
| medium | `admin` | `admin123` |
| high | `admin` | `admin123` (before 5 failures from same IP) |
| impossible | `admin` | `admin123` → **fails** (password must differ) |

---

<details>
<summary>Solutions (expand only after attempting)</summary>

### Low — Hard-coded credentials
The source (`vuln.py`) compares with `username == "admin" and password == "admin123"`.
Submit those credentials directly:

```
POST /admin
username=admin&password=admin123
```

The server redirects to `/admin/dashboard`.

### Medium — Default env var
The code reads `os.environ.get("HONEYSCOPE_ADMIN_PASS", "admin123")`.
If `HONEYSCOPE_ADMIN_PASS` is not set in the environment (which it isn't in the default deployment), the default value `admin123` is still used.
Same payload as `low` works.

### High — Bypassing per-IP rate limit
The rate limiter counts failures per source IP. Options:
1. **Different IP** — send the same payload from a different IP address (e.g., via a proxy, VPN, or second host).
2. **Server restart** — the rate table is in-process memory (`defaultdict`); restarting the Flask process clears it.
3. **Fresh minute** — the limiter resets after 60 seconds.

### Fix (Impossible level)
```python
import secrets, os
expected = os.environ.get("HONEYSCOPE_ADMIN_PASS", "admin123")
# secrets.compare_digest prevents timing-oracle attacks.
ok = (username == "admin") and secrets.compare_digest(password, expected)
```

Deploy with a strong `HONEYSCOPE_ADMIN_PASS` (e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`) and **never use the default**.

</details>

---

## Blue-team notes

### Detection

The Wazuh and Sigma rules fire on:
- Any POST to `/admin` with `username=admin` in the body (attempted admin login — always suspicious in a real app).

**Wazuh rule IDs:** 100506, 100507  
**Shared detection regex:** `(?i)username=admin|^admin$`

### Logging fields checked
Every POST to `/admin` is logged (JSON Lines) with:
- `method`, `path`, `form` (body), `status`, `lab_level`, `ip`

### Likely false positives
- Legitimate admin logins on a system where the admin username is `admin` (i.e., the detection fires even on a correct login). In a production system you would tune on *repeated failures* (rate pattern) rather than on the username alone.

### Hardening checklist
- [ ] Set `HONEYSCOPE_ADMIN_PASS` to a randomly generated secret before deployment.
- [ ] Never commit the admin password to version control.
- [ ] Add a persistent rate limiter (e.g., Redis-backed) so it survives process restarts.
- [ ] Log admin login attempts to an append-only log.
- [ ] Consider MFA for the admin panel.
