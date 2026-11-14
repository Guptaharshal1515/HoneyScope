# Scenario: IDOR and Privilege Escalation - Profile Page

| | |
|---|---|
| Endpoint | `GET /profile` · `POST /profile` |
| CWE / OWASP | CWE-639 / A01:2021 Broken Access Control |
| MITRE ATT&CK | T1078 — Valid Accounts (privilege escalation via weak access control) |
| Code | [`vuln.py`](vuln.py) |
| Detections | [`rules/`](rules/) |

**Goal (red team):** Read another user's profile data (IDOR), and/or promote your
own account to `admin` (privilege escalation).

**Goal (blue team):** Detect enumeration of `user_id` parameters and privilege
escalation attempts, at every level.

Set the difficulty with `HONEYSCOPE_LEVEL=low|medium|high|impossible` (default `low`).

## Levels

| Level | What the app does | Why it falls |
|---|---|---|
| low | No ownership check on GET or POST. Role field accepted from form. | Direct object reference — just change `user_id`. Role can be freely changed. |
| medium | GET checks that `user_id` matches the session. POST trusts `user_id` from the form body. | Bypass: submit a POST with a different `user_id` in the body — the GET check doesn't cover it. |
| high | GET and POST both verify ownership. Role field is still accepted from the form. | Bypass: self-promote to `admin` by editing your own profile with `role=admin`. |
| impossible | Ownership enforced on GET and POST. Role field ignored from form; server keeps existing role. | Not exploitable. This is the reference fix. |

## Hints (no spoilers)

- low: What URL parameter controls whose profile you see? Try changing it.
- medium: The GET request checks the URL parameter — but what about the form submission? Look at what the POST body contains.
- high: You can only edit your own profile now. But is there anything in the edit form you shouldn't be able to change?

<details><summary>Solutions (spoilers)</summary>

### IDOR (low, medium)

**Low:** Navigate to `/profile?user_id=1` while logged in as any other user. No check is performed; you see (and can edit) the admin's profile.

**Medium:** The GET check blocks `/profile?user_id=1`. But on a POST, the form body also contains a `user_id` field. Send:
```
POST /profile?user_id=<your_id>
user_id=1&username=...&email=...&role=admin
```
The route reads `request.form.get("user_id", ...)` and uses that to run the UPDATE — your session `user_id` is never checked on POST.

### Privilege escalation (high)

**High:** Ownership is now fixed. But the role dropdown is still in the form:
```
POST /profile?user_id=<your_id>
user_id=<your_id>&username=...&email=...&role=admin
```
The server updates your record including the `role` column. You are now admin.

</details>

## The fix

```python
# impossible level in vuln.py:
# 1. Always verify that the requested user_id matches the session:
if str(post_target_id) != str(session_user_id):
    return None, "Access denied", False

# 2. Never take the role from user input — keep the current DB value:
current = db.execute("SELECT role FROM users WHERE id = ?", (session_user_id,)).fetchone()
current_role = current["role"]
db.execute("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
           (new_username, new_email, current_role, session_user_id))
```

Blacklisting specific fields (e.g. removing `role` from the form at `high`) is not
enough — the POST body can be crafted directly. The only reliable fixes are:
1. **Never trust user-supplied object IDs** — look up the resource from the session.
2. **Never accept privilege-sensitive fields from the user** — look them up from the DB.

## Blue-team material

- `scenario.json → detection_regex`: shared by both Wazuh rules, the Sigma rule, and tests.
- `rules/wazuh_idor_profile.xml`: rules 100504–100505 (role escalation and IDOR enumeration).
- `rules/sigma_idor_profile.yml`: Sigma rule (T1078).
- `attack.py`: replays the scenario against a running instance.

```
# terminal 1
HONEYSCOPE_LEVEL=medium HONEYSCOPE_LAB=1 python app.py
# terminal 2
python scenarios/idor_profile/attack.py http://localhost:5000 medium
```

**Known false positives:**
- Legitimate admin users navigating to `/profile?user_id=1` for support tasks — the detection fires on any numeric `user_id` parameter, not just non-matching ones. Tune by correlating the `user_id` param against the session's `user_id` in the access log.
- Admin-role users submitting their own profile update — their existing `role=admin` in the form matches the detection regex. Suppress alerts where the user's current role already matches the submitted role.
