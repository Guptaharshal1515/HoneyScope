# Scenario: SQL Injection - Login Bypass

| | |
|---|---|
| Endpoint | `POST /login` |
| CWE / OWASP | CWE-89 / A03:2021 Injection |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application |
| Code | [`vuln.py`](vuln.py) |
| Detections | [`rules/`](rules/) |

**Goal (red team):** log in as a user without knowing the password.
**Goal (blue team):** make sure every attempt raises an alert, at every level.

Set the difficulty with `HONEYSCOPE_LEVEL=low|medium|high|impossible` (default `low`).

## Levels

| Level | What the app does | Bypass idea |
|---|---|---|
| low | Raw string concatenation, SQL errors shown, username-only fallback | Classic tautology |
| medium | Removes `OR`/`or` and `--`/`#`, errors shown | Filter is case-sensitive |
| high | Removes `or|and|union|select|--|/*|#` case-insensitively, **once** | Filter is not recursive |
| impossible | Parameterised query | None. This is the fix. |

## Hints (no spoilers)

- low: what does `'` do to the query? Read the error.
- medium: how many ways can you write the word "or"?
- high: what happens if the filter's output is itself a keyword?

<details><summary>Solutions (spoilers)</summary>

| Level | Username | Password |
|---|---|---|
| low | `' OR '1'='1` | anything |
| medium | `x` | `' Or '1'='1` |
| high | `x` | `' OORR '1'='1` |

Why they work, e.g. medium: the query becomes
`... WHERE username='x' AND password='' Or '1'='1'`, and `AND` binds tighter than `OR`, so the whole condition is true and the first row (admin) is returned.
</details>

## The fix

```python
db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

Blacklists (medium/high) fail because they try to enumerate bad input. They also hurt real users: at `high`, `jsmith`'s legitimate password `password123` is mangled because it contains `or`. Parameterisation separates code from data. In a real app you would also hash passwords and rate-limit logins.

## Blue-team material

- `scenario.json -> detection_regex`: one regex used by the Wazuh rule, the Sigma rule, and the automated test, so they cannot drift apart.
- `rules/wazuh_sqli_login.xml`: Wazuh rule (IDs 100500-100501).
- `rules/sigma_sqli_login.yml`: Sigma rule for portability (Splunk, Elastic, ...).
- `attack.py`: replays the payload for each level against a running instance so you can watch alerts appear.

```bash
# terminal 1
HONEYSCOPE_LEVEL=medium python app.py
# terminal 2
python scenarios/sqli_login/attack.py http://localhost:5000 medium
```

Known false positive: legit usernames like `d'orsay` match the regex. Tune for your environment.
