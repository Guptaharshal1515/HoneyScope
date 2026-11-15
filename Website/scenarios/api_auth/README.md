# Broken API Authorization (BOLA + BFLA)

**ID:** `api-auth` | **CWE:** CWE-284 | **OWASP:** A01:2021 | **MITRE:** T1548  
**Endpoints:** `POST /api/users/login`, `GET /api/users/<id>`, `GET /api/users/`, `GET /api/admin/users`

## Goal
Access another user's sensitive record (BOLA) or admin-only data (BFLA) while authenticated as a regular user.

## Levels

| Level | BOLA gap | BFLA gap |
|---|---|---|
| `low` | No check | No check |
| `medium` | POST body `user_id` overrides | `?role=admin` query string |
| `high` | List endpoint leaks all salaries | `X-Role` header |
| `impossible` | Session-only ownership; public fields only | Session-only role |

## Hints
- **Low:** Try accessing a resource that belongs to a different user.
- **Medium:** The GET is protected — what about POST? Are there parameters that influence which record is returned?
- **High:** Individual records are protected. Are there other endpoints? Check all HTTP headers.
- **Impossible:** Compare all four levels. Notice the trust model for each.

<details><summary>Solutions</summary>

### Low — Direct BOLA
`GET /api/users/2` as alice (user 1) → returns bob's salary.

### Medium — Body override + query role
`POST /api/users/2` with body `user_id=2` while authenticated as alice.  
`GET /api/admin/users?role=admin` as a regular user.

### High — List exposure + X-Role
`GET /api/users/` → returns all users with salary.  
`GET /api/admin/users` with header `X-Role: admin`.

### Fix (Impossible)
Never trust user-supplied user_id or role headers. Read identity only from the server-side session.
</details>

## Blue-team notes
Wazuh: **100512–100513**. Watch for cross-user resource access patterns and unusual role headers.
