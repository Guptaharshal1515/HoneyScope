# Changelog

## [Unreleased]
### Added
- **Scenario `weak-creds`** (CWE-798, T1078.001): Weak/default credentials on the management login panel (`/mgmt` → `/admin`). Four levels: `low` (hardcoded `admin/admin123`, plain `==`, no rate limit — original honeypot behaviour), `medium` (password in env var `HONEYSCOPE_ADMIN_PASS`, default still `admin123`, no rate limit), `high` (env-var password + 5-failures/60 s per-IP in-process rate limiter; bypassable via different IP or server restart), `impossible` (`secrets.compare_digest` + rate limiter; env var must be set to a strong secret). Wazuh rules 100506–100507, Sigma rule, `attack.py` replay script, 30 tests. Flags work in lab mode; containment verified.
- **Scenario `idor-profile`** (CWE-639/CWE-862, T1078): IDOR + privilege escalation on the profile page. Four levels: `low` (no ownership check, role editable), `medium` (GET checks ownership; POST trusts form `user_id`), `high` (ownership fixed; role still editable by any user on own profile), `impossible` (ownership enforced; role ignored from form). Wazuh rules 100504–100505, Sigma rule, `attack.py` replay script, 37 tests. Flags work in lab mode; containment verified.
- **Scenario `xss-stored`** (CWE-79, T1059.007): Stored XSS on the employee feedback form (`/submit_comment`). Four levels: `low` (verbatim storage with `| safe`), `medium` (strips `<script>` only), `high` (named-tag blocklist, single-pass), `impossible` (`html.escape()` at write time — the reference fix). Wazuh rules 100502–100503, Sigma rule, `attack.py` replay script, 30 tests. Flags work in lab mode; containment verified. Existing honeypot behaviour at `low` is preserved.
- **Scenario generator** `Website/tools/new_scenario.py`: creates a draft scenario skeleton (metadata, level stubs, README outline, Wazuh + Sigma templates with auto-allocated rule IDs, replay-script stub, skeleton tests). Writes no exploit code or payloads.
- `"status": "draft"` in `scenario.json` hides a scenario from `/lab` and the scoreboard; `load_scenarios()` takes `base` and `include_drafts`.
- 8 more tests (53 total).
- **Flags and scoreboard** (lab mode only): HMAC-derived flag per scenario and level, shown on the dashboard after a real login bypass; submit on `/lab` to tick the scoreboard. `HONEYSCOPE_FLAG_SECRET` sets the secret. No flag at `impossible`.
- 12 more tests (45 total).
- **Lab index page** at `/lab` (opt-in with `HONEYSCOPE_LAB=1`, 404 otherwise): lists scenarios, shows per-level hints (no solutions), and switches difficulty at runtime.
- `scenarios.load_scenarios()`, `set_level()` and `lab_enabled()` helpers; runtime level override beats `HONEYSCOPE_LEVEL`.
- `hints` and `target` fields in `scenario.json`.
- 10 more tests (33 total) covering the lab page, hidden-by-default behaviour, level switching and `scenario.json` schema.

## [0.2.0-lab] - 2026-11-14
### Added
- Open-source project files: LICENSE (MIT), CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, ROADMAP, issue/PR templates.
- **Lab mode:** difficulty levels via `HONEYSCOPE_LEVEL` (`low` | `medium` | `high` | `impossible`).
- First scenario, `sqli-login`: four levels, write-up, Wazuh rules (IDs 100500-100501), Sigma rule, and `attack.py` replay script.
- pytest suite (23 tests at the time) and GitHub Actions CI (tests on Python 3.11/3.12 + Docker build).
- `lab_level` field in every access-log entry.
- `.env.example`, `requirements-dev.txt`.

### Changed
- Flask debug mode is now opt-in (`HONEYSCOPE_DEBUG=1`); it previously ran with the Werkzeug debugger on `0.0.0.0`.
- `low` level no longer accepts a wrong password for a valid username; the username-only fallback now only runs when the username contains a quote (the original injection quirk is preserved).
- README restructured around honeypot and lab modes; fixed clone path.

### Fixed
- Removed obsolete `version:` key from `docker-compose.yml`.

## [0.1.0] - 2026-07
- Internship prototype: Flask web honeypot, Cowrie SSH honeypot, Wazuh integration, Gemini-based attack analysis, Raspberry Pi cold-storage log node.
