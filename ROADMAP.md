# HoneyScope Roadmap

Status: v0.1 (internship prototype) -> open source. Direction: a DVWA-style lab *and* a deployable honeypot.

## Done
- [x] Difficulty levels (`HONEYSCOPE_LEVEL`)
- [x] First scenario: `sqli-login` (4 levels, Wazuh + Sigma, replay script)
- [x] pytest suite + CI

## v0.2-lab: Scenarios
- [ ] Convert `xss-stored`, `idor-profile`, `weak-admin` into levelled scenarios
- [ ] Scenario index page in the app (list scenarios, switch level, hints/solutions toggle)
- [ ] Modern scenarios: JWT flaws, SSRF, broken API auth, GraphQL, file upload, insecure deserialisation
- [ ] Flag/scoreboard so learners can check progress
- [ ] Detection-coverage report ("you caught 7 of 10 techniques")
- [ ] Rule coverage in Sigma for every scenario, converted to Splunk/Elastic in CI

## v0.2: Make it reproducible
- [ ] Add `wazuh_rules/local_rules.xml` (IDs 100010-100058) to the repo (referenced in README, missing from the first export)
- [ ] Add `ai_analysis/analyze.py` and `.env.example` (referenced in README, missing from the first export)
- [ ] Single `docker-compose.yml` that brings up web honeypot + Cowrie
- [ ] Configurable branding (company name, seeded users) via env/config instead of hardcoded "TechCorp"
- [ ] Log client IP correctly behind a reverse proxy (`X-Forwarded-For`, trusted proxies)
- [ ] Extend pytest coverage to the remaining intentional vulns (sqli-login done)
- [ ] CI: add linting (tests + Docker build already run on every PR)

## v0.3: Better data
- [ ] Log request headers and raw body, not just form data
- [ ] Log HTTP response of honeypot (to see what the attacker saw)
- [ ] Per-session IDs to correlate web + SSH activity
- [ ] Fail2ban-style tagging of scanners vs. humans
- [ ] Rate-limited, size-capped logging to resist log-flooding

## v0.4: Pluggable analysis
- [ ] LLM provider abstraction (Gemini, OpenAI, Anthropic, local models via Ollama)
- [ ] Prompt-injection hardening of the analyser (attacker-controlled log text)
- [ ] Optional export to Elastic / Splunk / Grafana Loki, not only Wazuh
- [ ] Structured JSON output of reports alongside Markdown

## v0.5: More honeypots
- [ ] Additional web "personalities" (WordPress, phpMyAdmin, Jenkins, REST API)
- [ ] Fake services: FTP, Telnet, MySQL, Redis
- [ ] Honeytokens (fake API keys / documents that alert when used)
- [ ] Threat-intel enrichment (GeoIP, AbuseIPDB, GreyNoise)

## Ideas / community
- [ ] Dashboard (Grafana) with ready-made panels
- [ ] Ansible / Terraform deployment
- [ ] Public sanitized dataset of captured attacks
- [ ] Documentation site
