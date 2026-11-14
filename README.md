<p align="center">
  <img src="https://github.com/user-attachments/assets/d28b4a51-088c-415c-965d-3c004bdfc638"
       alt="HoneyScope Logo"
       width="250" />
</p>


# HoneyScope - Adaptive Web Application Honeypot with SIEM Integration and AI-Assisted Attack Analysis


> This system is deployed in an isolated lab environment for authorized security research only.
> Do NOT deploy in production. All vulnerabilities are intentional.

**Status:** open-source, early stage (v0.1). Originally built during the IIT Jammu Cybersecurity Internship (June-July 2026); now developed in the open.
See [ROADMAP.md](ROADMAP.md) for what's planned, [CONTRIBUTING.md](CONTRIBUTING.md) to get involved, and [SECURITY.md](SECURITY.md) for safe-deployment rules. Licensed under [MIT](LICENSE).

---

## Two ways to use HoneyScope

| Mode | What it is | Who it's for |
|---|---|---|
| **Honeypot** | Deploy it, let real attackers hit it, collect and analyse what they do | Researchers, SOC teams, threat-intel analysts |
| **Lab** *(new, in progress)* | A DVWA-style practice target with difficulty levels, patched versions and ready-made detections | Red teamers, SIEM engineers, blue teamers, students |

### Who can use the lab

| You are... | You get... |
|---|---|
| **Red team / pentester** | Vulnerabilities with 4 difficulty levels (`low`, `medium`, `high`, `impossible`). Practise bypassing filters and see why they fail. |
| **SIEM engineer** | Detection rules per scenario (Wazuh + vendor-neutral Sigma), MITRE ATT&CK mapped, plus a replay script to trigger them on demand. |
| **Hardening / SOC** | The `impossible` level is the reference fix; compare it with the vulnerable code. Detections are tested automatically. |
| **Threat intel / log analysis** | JSON logs tagged with the lab level, and an AI-assisted analyser (Gemini now, more providers planned) that turns alerts into reports. |

### Quick start (lab)

```bash
cd Website
pip install -r requirements.txt
HONEYSCOPE_LEVEL=medium python app.py        # http://localhost:5000
# or: HONEYSCOPE_LEVEL=medium docker compose up --build
```

`HONEYSCOPE_LEVEL` defaults to `low`, which is the original honeypot behaviour.

**Lab index page:** set `HONEYSCOPE_LAB=1` and open `http://localhost:5000/lab` to see every scenario, read the per-level hints, and switch difficulty from the browser (no restart). With `HONEYSCOPE_LAB` unset, `/lab` returns 404, so a deployed honeypot never exposes it.

```bash
HONEYSCOPE_LAB=1 python app.py               # then open http://localhost:5000/lab
```

**Flags and scoreboard:** in lab mode, getting into the app without the right password at `low`, `medium` or `high` reveals a flag (`HS{scenario:level:...}`) on the dashboard. Paste it into the scoreboard on `/lab` to tick that scenario and level off. There is no flag at `impossible`, and flags never appear in honeypot mode or for a normal login. Set `HONEYSCOPE_FLAG_SECRET` to a private value if others will use your lab, since the default is public in this repo. Progress lives in memory and resets when the server restarts.

### Scenarios

| Scenario | Vulnerability | Levels | Detections | Status |
|---|---|---|---|---|
| [`sqli-login`](Website/scenarios/sqli_login/README.md) | SQL injection login bypass (CWE-89) | low / medium / high / impossible | Wazuh + Sigma | Ready |
| `xss-stored` | Stored XSS on the dashboard (CWE-79) | not yet levelled | Wazuh (in honeypot ruleset) | Planned |
| `idor-profile` | IDOR + privilege escalation (CWE-639, CWE-862) | not yet levelled | Wazuh (in honeypot ruleset) | Planned |
| `weak-admin` | Default credentials on `/admin` (CWE-798) | not yet levelled | Wazuh (in honeypot ruleset) | Planned |

New to the project? Converting one of the "Planned" rows into a real scenario is the best first contribution. See [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-scenario).

**Add your own scenario in one command** (the generator writes the folder, metadata, rule templates and skeleton tests; you write the vulnerable code):

```bash
cd Website
python tools/new_scenario.py my-scenario --title "My Scenario" --cwe CWE-79 --owasp "A03:2021 Injection" --mitre T1059 --endpoint "POST /example" --target /example
```

### Run the tests

```bash
cd Website
pip install -r requirements-dev.txt
pytest -q
```

The tests check that every level behaves as documented and that the Wazuh and Sigma rules use the same detection regex as the tests, so rules and exploits can't drift apart.

> Lab mode is meant to be attacked on purpose, inside a sandbox. Honeypot mode faces strangers on a network. They have different safety needs, see [SECURITY.md](SECURITY.md).

---

## 1. What Is This Project?

This project is a multi-layered honeypot system designed to:
- **Lure attackers** using a fake vulnerable web application and a fake SSH server
- **Capture and correlate** all attacker interactions via a SIEM (Wazuh)
- **Reconstruct attack paths** using custom detection rules mapped to MITRE ATT&CK
- **Analyze attacker behavior and psychology** using an AI layer (Gemini 2.5 Flash)
- **Preserve forensic evidence** using a Raspberry Pi as a distributed cold-storage log node

The system answers a core research question: **what do attackers actually do, and what does their behavior tell us about their skill level, intent, and attack vector?**

---

## 2. Architecture

```
                        Attacker
                           │
              ┌────────────┴────────────┐
              │                         │
         Port 22 (SSH)            Port 80 (HTTP)
              │                         │
         iptables redirect        Docker container
              │                         │
         Cowrie SSH Honeypot     Flask Web Honeypot
         (fake Linux shell)      (fake company portal)
              │                         │
              └────────────┬────────────┘
                           │
                    Wazuh Agent (VM1)
                    watches both log files
                           │
              ┌────────────┴────────────┐
              │                         │
       VM2 (Wazuh Manager)      Raspberry Pi Zero 2W
       SIEM Dashboard            Cold Storage (rsyslog)
       Custom Detection Rules    Forensic log backup
       AI Analysis Script        (tamper-resistant copy)
              │
       Gemini 2.5 Flash API
              │
       Attack Analysis Report (.md)
       - Purified logs
       - Attacker behavior profile
       - MITRE ATT&CK mapping
       - Recommendations
```

> <img width="2820" height="1800" alt="IIT Jammu Project" src="https://github.com/user-attachments/assets/393da442-8f81-4a60-9a86-374e41ea5b65" />


---

## 3. Intentional Vulnerability List

### Web Application Honeypot (`/home/website/HoneyScope/Website/`)

| # | Vulnerability | Location | MITRE ATT&CK |
|---|---|---|---|
| 1 | SQL Injection (auth bypass) | `/login` - unsanitized string concat query | T1190 |
| 2 | Stored XSS | `/submit_comment` - no input sanitization | T1059 |
| 3 | Weak/Default Credentials | `/admin` - hardcoded `admin/admin123` | T1078 |
| 4 | IDOR + Privilege Escalation | `/profile?user_id=X` - no ownership check, role field editable | T1078 |

### SSH Honeypot (Cowrie)
- Accepts any password for `root`, `admin`, `phil`, `techcorp`
- Presents a fake Debian Linux shell (`svr04` hostname)
- Logs all commands, keystrokes, file downloads, and session TTY recordings

---

## 4. Setup Guide

### Prerequisites
- VMware Workstation (or similar hypervisor)
- Ubuntu Server 22.04 ISO (VM1)
- Ubuntu Desktop 22.04 ISO (VM2)
- Raspberry Pi running Raspberry Pi OS/OS Lite
- Python 3.x
- Docker + Docker Compose
- A LLM API key 
---

### i) VM1 - Honeypot Machine

**Specs:** 2 vCPU, 2-4GB RAM, 20GB disk, NAT network adapter

**Base setup:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install docker.io docker-compose-plugin git python3-venv -y
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**Deploy the web honeypot:**
```bash
git clone https://github.com/Guptaharshal1515/HoneyScope
cd HoneyScope/Website
docker compose up --build -d
docker compose ps
```

Web app runs on port 80. Logs written to `./logs/access.log`.

**Install Wazuh agent:**
```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
sudo WAZUH_MANAGER='<VM2_IP>' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Edit `/var/ossec/etc/ossec.conf` and add both log sources before `</ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/website/HoneyScope/Website/logs/access.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

**Install Cowrie SSH honeypot:**
```bash
sudo adduser --disabled-password cowrie
sudo apt install python3-venv python3-dev python3-pip libssl-dev libffi-dev build-essential authbind -y
sudo su - cowrie
git clone http://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
cp src/cowrie/data/etc/cowrie.cfg.dist etc/cowrie.cfg
```

Edit `etc/userdb.txt`:
```
root:0:*
admin:0:*
phil:1000:*
techcorp:1000:Welcome123
```

Start Cowrie:
```bash
cowrie start
cowrie status
```

**Redirect port 22 to Cowrie (as website user):**
```bash
# Add port 22222 as backup real SSH access first
sudo nano /etc/ssh/sshd_config
# Add line: Port 22222
sudo systemctl restart ssh

# Then redirect port 22 to Cowrie
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Make persistent
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

**Forward Cowrie logs to Raspberry Pi via rsyslog:**
```bash
sudo nano /etc/rsyslog.d/cowrie-forward.conf
```
```
module(load="imfile" PollingInterval="10")

input(type="imfile"
  File="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
  Tag="cowrie"
  Severity="info"
  Facility="local3")

local3.* action(type="omfwd"
  target="<RASPBERRY_PI_IP>"
  port="514"
  protocol="tcp")
```
```bash
sudo systemctl restart rsyslog
```

---

### ii) VM2 - SIEM Machine

**Specs:** 2 vCPU, 6-8GB RAM, 50GB disk, NAT network adapter

**Install Wazuh (all-in-one):**
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Save the credentials printed at the end - you'll need them for the dashboard and API.

**Access dashboard:**
```
https://<VM2_IP>
```
Login with the `admin` credentials from the install output.

**Add custom detection rules:**
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Paste the full ruleset from `wazuh_rules/local_rules.xml` in this repo (covers SQLi, XSS, weak creds, IDOR, privilege escalation, recon, and all Cowrie SSH attack patterns).

```bash
sudo systemctl restart wazuh-manager
```

---

### iii) Raspberry Pi - Forensic Cold Storage

**Install rsyslog:**
```bash
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

**Configure to receive logs:**
```bash
sudo nano /etc/rsyslog.conf
```

Uncomment/add:
```
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")
```

Add at the bottom:
```
if $hostname == 'companyinternals' then /var/log/cowrie-remote.log
& stop
```

```bash
sudo systemctl restart rsyslog
```

Verify logs are arriving:
```bash
sudo tail -f /var/log/cowrie-remote.log
```

---

## 5. AI Analyser Setup

**On VM2:**
```bash
mkdir ~/ai_analysis
cd ~/ai_analysis
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
```

Create `.env` file (never commit this):
```
INDEXER_USER=admin
INDEXER_PASSWORD=<your_indexer_password>
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=<your_wazuh_api_password>
GEMINI_API_KEY=<your_gemini_api_key>
```

Copy `analyze.py` from this repo into `~/ai_analysis/`.

**Run the analyser:**
```bash
source venv/bin/activate
python3 analyze.py
```

Output saved to `~/ai_analysis/reports/attack_report_<timestamp>.md`.


---

## 6. How the System Works

**Step 1 - Attacker interacts with honeypot**
- HTTP traffic hits the web app on port 80 → Flask app logs every request (IP, method, path, payload, headers, timestamp) to `access.log` in JSON Lines format
- SSH traffic hits port 22 → iptables redirects to Cowrie on port 2222 → Cowrie captures credentials tried, commands typed, files downloaded, session recordings

**Step 2 - Logs forwarded to SIEM**
- Wazuh agent on VM1 watches both log files (`access.log` and `cowrie.json`)
- Agent forwards new log lines to Wazuh manager on VM2 in real time
- Simultaneously, rsyslog on VM1 forwards Cowrie logs to the Raspberry Pi for cold storage

**Step 3 - Detection and correlation**
- Wazuh manager applies custom rules (rule IDs 100010–100058) to classify each event
- Rules detect: SQLi payloads, XSS injections, brute-force patterns, IDOR enumeration, privilege escalation, SSH credential stuffing, dangerous shell commands, persistence attempts, and more
- All rules are mapped to MITRE ATT&CK techniques
- Correlated alerts visible in Wazuh Dashboard at `https://<VM2_IP>`

**Step 4 - AI analysis**
- `analyze.py` authenticates to Wazuh's indexer API (port 9200)
- Pulls recent alerts filtered to the `honeypot` rule group
- Groups events by source IP and sorts chronologically
- Sends structured alert data to Gemini 2.5 Flash API with a detailed prompt
- Gemini produces a human-readable report covering: purified log narrative, attacker behavior profile (skill level, pattern, persistence), cross-honeypot correlation, MITRE ATT&CK mapping, severity assessment, attacker psychology/intent hypothesis, and concrete hardening recommendations
- Report saved as a Markdown file for human analyst review

**Step 5 - Human in the loop**
- The AI report explicitly flags behavioral assessments with confidence levels
- A "Human Review Notes" section prompts the analyst to verify AI conclusions before treating them as ground truth
- The analyst can annotate or correct the generated report

**Step 6 - Forensic preservation**
- All Cowrie logs are independently stored on the Raspberry Pi
- If VM1 is fully compromised and logs deleted, the Pi retains a tamper-resistant copy
- This enables post-incident digital forensics even in a worst-case compromise scenario

---

## Network Reference

| Component | IP | Key Ports |
|---|---|---|
| VM1 (Honeypot) | 192.168.xx.xx | 80 (web), 22 (→Cowrie), 2222 (Cowrie), 22222 (real SSH) |
| VM2 (SIEM) | 192.168.xx.xx | 443 (dashboard), 9200 (indexer), 55000 (API), 1514 (agent) |
| Raspberry Pi | 192.168.xx.xx | 514 (rsyslog receiver), 22 (SSH) |

---

## Important Notes

- **Never expose VM1 to the real internet without proper network isolation**
- **Never commit `.env` files or credential files to version control**
- **This system is for authorized security research only**
- All vulnerabilities in the web app are intentional. In honeypot mode keep `HONEYSCOPE_LEVEL=low`; the `impossible` level exists as a reference fix for lab use
- Always SSH into VM1 on port 22222 (not port 22, which goes to Cowrie)

---

## Project Structure

```
HoneyScope/
├── Website/                    # Web honeypot (Flask app)
│   ├── app.py                  # Main application with intentional vulns
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   ├── scenarios/              # Lab scenarios (one folder each)
│   │   └── sqli_login/         #   vuln.py, scenario.json, README, rules/, attack.py
│   │                           #   (/lab page lists every scenario.json found here)
│   ├── tools/new_scenario.py   # scenario generator
│   ├── tests/                  # pytest suite
│   ├── templates/              # HTML templates
│   └── logs/                   # Runtime logs (gitignored)
├── wazuh_rules/
│   └── local_rules.xml         # All custom Wazuh detection rules
├── ai_analysis/
│   ├── analyze.py              # AI analysis script
│   ├── .env.example            # Template for credentials
│   └── reports/                # Generated reports (gitignored)
└── README.md
```

_Built as part of the IIT Jammu Cybersecurity Internship Program June-July 2026._
