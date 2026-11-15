# Race Condition & Business Logic (CWE-362)

## Scenario Overview
| Attribute | Value |
|---|---|
| ID | `race-condition` |
| CWE | CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization |
| OWASP | A04:2021 Insecure Design |
| MITRE ATT&CK | T1499 (Endpoint Denial of Service / Abuse) |
| Endpoint | `POST /api/coupon/apply`, `GET /api/coupon/balance` |

## Difficulty Levels

| Level | Server Defence | Attacker Technique |
|---|---|---|
| `low` | No concurrency control. Check and balance update are non-atomic. | Concurrent requests exploit the TOCTOU gap to redeem a coupon multiple times. |
| `medium` | Mutex lock surrounds the update step only, leaving the check unprotected. | Concurrent requests pass the check before the first thread acquires the lock. |
| `high` | Per-request lock allocated inside request handler. | Since each request thread holds its own separate lock object, mutual exclusion fails. |
| `impossible` | Shared process-wide critical section protecting both check and state update. | None (safe reference implementation). |

## Containment
- In-memory balances and locks.
- Bounded thread execution and limits.
- No database or external services.

## Blue Team Notes
- Monitor for bursts of identical coupon redemption requests within millisecond intervals.
- Detect discrepancies between allowed coupon limits and final account balance.
- Wazuh rules: `100522` (coupon application), `100523` (double spend / race pattern).
- Sigma rule: `rules/sigma_race_condition.yml`.
