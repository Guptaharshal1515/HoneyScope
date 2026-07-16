<p align="center">
  <img src="https://github.com/user-attachments/assets/d28b4a51-088c-415c-965d-3c004bdfc638"
       alt="HoneyScope Logo"
       width="250" />
</p>

<h1 align="center">HoneyScope</h1>

<p align="center">
  <strong>Observe • Analyze • Learn</strong>
</p>


# HoneyScope - Adaptive Web Application Honeypot with SIEM Integration and AI-Assisted Attack Analysis


> This system is deployed in an isolated lab environment for authorized security research only.
> Do NOT deploy in production. All vulnerabilities are intentional.

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

### Web Application Honeypot (`/home/website/IITJammu/Website/`)

| # | Vulnerability | Location | MITRE ATT&CK |
|---|---|---|---|
| 1 | SQL Injection (auth bypass) | `/login` — unsanitized string concat query | T1190 |
| 2 | Stored XSS | `/submit_comment` — no input sanitization | T1059 |
| 3 | Weak/Default Credentials | `/admin` — hardcoded `admin/admin123` | T1078 |
| 4 | IDOR + Privilege Escalation | `/profile?user_id=X` — no ownership check, role field editable | T1078 |

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

### i) VM1 — Honeypot Machine

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
git clone <your-repo-url>
cd Website
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
  <location>/home/website/IITJammu/Website/logs/access.log</location>
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

### ii) VM2 — SIEM Machine

**Specs:** 2 vCPU, 6-8GB RAM, 50GB disk, NAT network adapter

**Install Wazuh (all-in-one):**
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Save the credentials printed at the end — you'll need them for the dashboard and API.

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

### iii) Raspberry Pi — Forensic Cold Storage

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

**Step 1 — Attacker interacts with honeypot**
- HTTP traffic hits the web app on port 80 → Flask app logs every request (IP, method, path, payload, headers, timestamp) to `access.log` in JSON Lines format
- SSH traffic hits port 22 → iptables redirects to Cowrie on port 2222 → Cowrie captures credentials tried, commands typed, files downloaded, session recordings

**Step 2 — Logs forwarded to SIEM**
- Wazuh agent on VM1 watches both log files (`access.log` and `cowrie.json`)
- Agent forwards new log lines to Wazuh manager on VM2 in real time
- Simultaneously, rsyslog on VM1 forwards Cowrie logs to the Raspberry Pi for cold storage

**Step 3 — Detection and correlation**
- Wazuh manager applies custom rules (rule IDs 100010–100058) to classify each event
- Rules detect: SQLi payloads, XSS injections, brute-force patterns, IDOR enumeration, privilege escalation, SSH credential stuffing, dangerous shell commands, persistence attempts, and more
- All rules are mapped to MITRE ATT&CK techniques
- Correlated alerts visible in Wazuh Dashboard at `https://<VM2_IP>`

**Step 4 — AI analysis**
- `analyze.py` authenticates to Wazuh's indexer API (port 9200)
- Pulls recent alerts filtered to the `honeypot` rule group
- Groups events by source IP and sorts chronologically
- Sends structured alert data to Gemini 2.5 Flash API with a detailed prompt
- Gemini produces a human-readable report covering: purified log narrative, attacker behavior profile (skill level, pattern, persistence), cross-honeypot correlation, MITRE ATT&CK mapping, severity assessment, attacker psychology/intent hypothesis, and concrete hardening recommendations
- Report saved as a Markdown file for human analyst review

**Step 5 — Human in the loop**
- The AI report explicitly flags behavioral assessments with confidence levels
- A "Human Review Notes" section prompts the analyst to verify AI conclusions before treating them as ground truth
- The analyst can annotate or correct the generated report

**Step 6 — Forensic preservation**
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
- All vulnerabilities in the web app are intentional — do not attempt to fix them
- Always SSH into VM1 on port 22222 (not port 22, which goes to Cowrie)

---

## Project Structure

```
honeypot-project/
├── Website/                    # Web honeypot (Flask app)
│   ├── app.py                  # Main application with intentional vulns
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
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


