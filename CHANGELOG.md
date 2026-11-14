# Changelog

## [Unreleased] - 2026-11-14
### Added
- Open-source project files: LICENSE (MIT), CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, ROADMAP, issue/PR templates.
- **Lab mode:** difficulty levels via `HONEYSCOPE_LEVEL` (`low` | `medium` | `high` | `impossible`).
- First scenario, `sqli-login`: four levels, write-up, Wazuh rules (IDs 100500-100501), Sigma rule, and `attack.py` replay script.
- pytest suite (23 tests) and GitHub Actions CI (tests on Python 3.11/3.12 + Docker build).
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
