# Security Policy

HoneyScope is **intentionally vulnerable** (SQLi, stored XSS, IDOR, weak credentials, a weak session key). Those are features, not bugs, and reports about them will be closed as "working as intended".

## What we do want to hear about

- A way to **escape the honeypot** and reach the host, the container, or the SIEM (e.g. RCE on the host, container breakout, log injection that compromises Wazuh or the analyser).
- Flaws in the **non-honeypot** parts: the AI analyser, Wazuh rules, deployment scripts, and Docker setup.
- Leaked secrets in the repository history.

## How to report

Please use GitHub's **private vulnerability reporting** (Security tab -> "Report a vulnerability") rather than a public issue. We aim to acknowledge within 7 days.

## Safe deployment rules

- Run only in an isolated lab network or VLAN with no route to production systems.
- Never run the web app with `HONEYSCOPE_DEBUG=1` on an exposed machine.
- Keep the real SSH daemon on a non-standard port, reachable only from your management network.
- Treat everything attackers send (log lines, payloads, filenames) as hostile, including when it is fed to the AI analyser.
