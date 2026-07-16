# 🍯 TechCorp Internal Portal — Honeypot
A Project portal deployed by Harshal Gupta, Poluru Jiji Dhanvie & M N V Harshith.

> **⚠️ WARNING: This is an intentionally vulnerable web application built for authorized academic security research. DO NOT deploy this to any production environment or expose it to the public internet.**

## Purpose

This project is a **fake internal company portal** designed to function as a **honeypot** for security research. It contains deliberate, well-documented vulnerabilities that allow researchers to study attacker behavior, test detection systems (e.g., Wazuh SIEM), and validate intrusion detection pipelines in a **controlled, isolated lab environment**.

## Intentional Vulnerabilities

| # | Vulnerability | Location | Description |
|---|---|---|---|
| 1 | **SQL Injection** | `/login` | Login query uses string concatenation — allows auth bypass |
| 2 | **Stored XSS** | `/dashboard` | Feedback comments rendered without HTML sanitization |
| 3 | **IDOR** | `/profile?user_id=X` | Any logged-in user can view/edit any other user's profile |
| 4 | **Privilege Escalation** | `/profile` edit form | Role field editable — users can escalate to admin |
| 5 | **Weak/Default Credentials** | `/admin` | Hidden admin panel with hardcoded `admin / admin123` |
| 6 | **No Rate Limiting** | `/login` | No lockout on failed login attempts |

## Seeded Accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | admin |
| `jsmith` | `password123` | employee |
| `agarcia` | `welcome1` | employee |
| `mwilson` | `letmein` | manager |

## Logging

All HTTP requests are logged in **JSON Lines** format to `/var/log/honeypot/access.log`. Each log entry includes timestamp, source IP, method, path, query parameters, form data, user agent, and response status. This is designed for integration with SIEM tools like **Wazuh**.

## Quick Start

### Local (Python)
```bash
pip install -r requirements.txt
python app.py
# App runs at http://localhost:5000
```

### Docker
```bash
docker build -t honeypot-portal .
docker run -p 5000:5000 -v honeypot-logs:/var/log/honeypot honeypot-portal
# App runs at http://localhost:5000
```

## Project Structure

```
.
├── app.py                  # Main Flask application
├── templates/
│   ├── login.html          # Login page
│   ├── dashboard.html      # Employee dashboard
│   ├── profile.html        # User profile (IDOR vulnerable)
│   ├── admin.html          # Hidden admin login
│   └── admin_dashboard.html# Admin settings panel
├── requirements.txt
├── Dockerfile
├── .gitignore
├── description.txt         # Detailed vulnerability descriptions
├── payloads.txt            # Test payloads for each vulnerability
└── README.md
```

## Disclaimer

This application is part of an **IIT Jammu authorized security research project**. It is designed to run in an **isolated environment** only. The authors are not responsible for any misuse of this software. Use responsibly and ethically.
