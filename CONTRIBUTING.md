# Contributing to HoneyScope

Thanks for helping out! HoneyScope is a research honeypot, so contributions that make it more realistic, better instrumented, or safer to run are all welcome.

## Ground rules

1. **Intentional vulnerabilities stay.** Don't "fix" the SQLi, XSS, IDOR, etc. If you add a new one, document it in `Website/description.txt` with CWE/OWASP mapping and add a test payload to `Website/payloads.txt`.
2. **Never commit secrets** or real captured attacker data (IPs, credentials, session recordings). Sanitize sample logs first.
3. **Safety first.** Changes must not let an attacker reach the host or the SIEM. Treat all captured data as hostile input.
4. Every new detection should map to a **MITRE ATT&CK** technique.

## Development setup

```bash
cd Website
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
HONEYSCOPE_DEBUG=1 python app.py   # http://localhost:5000
```

Or: `docker compose up --build`.

## Workflow

- Fork, create a branch (`feat/...`, `fix/...`, `docs/...`), open a PR against `main`.
- Keep PRs focused; describe what changed and how you tested it.
- Use clear commit messages (e.g. `feat(rules): detect SSH key injection`).

## Good first areas

See [ROADMAP.md](ROADMAP.md). Items tagged `good first issue` are a nice starting point.

## Adding a scenario

Copy `Website/scenarios/sqli_login/` as a template. A scenario needs:

1. `vuln.py`: the behaviour for each level (`low`, `medium`, `high`, `impossible`). `impossible` must be the real fix.
2. `scenario.json`: id, title, endpoint, `target` (URL path the /lab page links to), CWE, OWASP, MITRE, `levels`, a spoiler-free `hint` per level in `hints`, a working payload per level, benign inputs, and a `detection_regex`. The /lab page and the tests read these fields, so a missing one fails CI.
3. `README.md`: goal, hints (no spoilers), collapsed solutions, the fix.
4. `rules/`: a Wazuh rule (IDs `1005xx` and up, keep them unique) and a Sigma rule that use the same regex.
5. `attack.py`: replays the payloads against a running instance.
6. Tests in `Website/tests/` covering each level, benign input, and that the rules match `detection_regex`.

Then add a row to the scenarios table in the README and a line in `CHANGELOG.md`.
