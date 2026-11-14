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

Start with the generator. It creates the folder, metadata, empty level stubs, rule templates (with the next free Wazuh rule IDs), a replay-script stub and a skeleton test file. It writes no vulnerable code and no payloads; you write those.

```bash
cd Website
python tools/new_scenario.py my-scenario --title "My Scenario" --cwe CWE-79 --owasp "A03:2021 Injection" --mitre T1059 --endpoint "POST /example" --target /example
```

(One line, so it also works in a Windows terminal: use `python tools\new_scenario.py ...`.)

The new scenario starts with `"status": "draft"`, which keeps it off the `/lab` page and the scoreboard, and its skeleton tests skip until you fill in payloads, so CI stays green while you work. Then:

1. `vuln.py`: the behaviour for each level (`low`, `medium`, `high`, `impossible`). `impossible` must be the real fix.
2. `scenario.json`: id, title, endpoint, `target`, CWE, OWASP, MITRE, `levels`, a spoiler-free `hint` per level in `hints`, a working payload per level, benign inputs, and a `detection_regex`. The /lab page and the tests read these fields.
3. Wire the route into `app.py` using `scenarios.get_level()`; to award a flag, follow the `sqli-login` pattern (lab mode only, never at `impossible`).
4. `rules/`: finish the Wazuh and Sigma rules so both use the same regex as `scenario.json`.
5. `attack.py`, the tests in `Website/tests/`, and the scenario `README.md`.
6. Set `"status": "ready"`, add a row to the scenarios table in the README and a line in `CHANGELOG.md`.
