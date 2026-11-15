# HoneyScope Roadmap

Direction: a DVWA-style lab **and** a deployable honeypot, with detections and AI analysis built in.

## Done
- [x] Open-source project files, CI, pytest suite
- [x] Difficulty levels (`HONEYSCOPE_LEVEL`: low / medium / high / impossible)
- [x] First scenario: `sqli-login` (4 levels, Wazuh + Sigma, replay script)
- [x] `/lab` index page with hints and runtime level switching
- [x] Flags and a scoreboard (lab mode)
- [x] Scenario generator (`tools/new_scenario.py`) with draft status

## Next: make it reproducible (do first)
- [ ] Add `wazuh_rules/local_rules.xml` (IDs 100010-100058), referenced in the README but missing from the repo
- [ ] Add `ai_analysis/analyze.py` and its `.env.example`, same reason
- [ ] Single `docker-compose.yml` that brings up the web honeypot + Cowrie
- [ ] Configurable branding (company name, seeded users) instead of hardcoded "TechCorp"
- [ ] Log client IP correctly behind a reverse proxy (`X-Forwarded-For`, trusted proxies)
- [ ] Linting and security scanning in CI

## Lab scenarios (red team)
- [x] Level the existing stored XSS feature (`xss-stored`: 4 levels, Wazuh + Sigma, tests, attack.py)
- [x] Level the existing IDOR / privilege escalation feature (`idor-profile`: 4 levels, Wazuh + Sigma, tests, attack.py)
- [x] Level the existing weak-creds feature (`weak-creds`: 4 levels, Wazuh + Sigma, tests, attack.py)
- [x] Modern web/API scenarios — JWT (`jwt-flaws`: alg=none, weak secret, kid injection — done)
- [x] Modern web/API scenarios (remaining): SSRF, broken API auth, GraphQL, file upload, deserialisation, command injection, path traversal, XXE, race conditions, business logic
- [x] AI-era scenario: prompt injection and data leakage in an LLM-backed chatbot (OWASP LLM Top 10)
- [x] Hook each new scenario into the flag system (flags wired for all 13 scenarios across low/medium/high)
- [ ] Solutions toggle on the `/lab` page (hints only today)

## Detection engineering (SIEM)
- [ ] Wazuh + Sigma rules for every scenario, mapped to MITRE ATT&CK
- [ ] Convert Sigma to Splunk / Elastic / Sentinel in CI
- [ ] Logs in a standard schema (ECS or OCSF)
- [ ] Replayable attack datasets and a test that each attack raises its alert
- [ ] Detection-coverage report ("you caught 7 of 10 techniques")
- [ ] Suricata or Zeek network sensor alongside the web logs

## Hardening and SOC (blue team)
- [ ] Side-by-side "vulnerable vs patched" diffs for each scenario
- [ ] Incident-response exercises with timelines and questions
- [ ] Playbooks / SOAR-style automation (e.g. auto-block an attacking IP)
- [ ] Container and host hardening checklists
- [ ] Alert-triage practice with a mix of real alerts and false positives

## Threat intel and AI analysis
- [ ] LLM provider abstraction (Gemini, OpenAI, Anthropic, local models via Ollama)
- [ ] Prompt-injection hardening of the analyser (attacker-controlled log text)
- [ ] Structured JSON reports alongside Markdown
- [ ] Enrichment: GeoIP, AbuseIPDB, GreyNoise
- [ ] Attacker session timelines linking web and SSH activity
- [ ] AI assistant for questions about the logs ("what did this IP do?")
- [ ] Honeytokens that alert when used
- [ ] Public, sanitised dataset of captured attacks

## More honeypots
- [ ] Web "personalities": WordPress, phpMyAdmin, Jenkins
- [ ] Fake FTP, Telnet, MySQL and Redis services
- [ ] Fake REST API and IoT / router interfaces

## Project quality
- [ ] Documentation site and a Grafana dashboard
- [ ] Ansible / Terraform deployment
