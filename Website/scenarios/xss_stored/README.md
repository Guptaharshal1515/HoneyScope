# Scenario: Stored XSS - Employee Feedback

| | |
|---|---|
| Endpoint | `POST /submit_comment` |
| CWE / OWASP | CWE-79 / A03:2021 Injection |
| MITRE ATT&CK | T1059.007 — Command and Scripting Interpreter: JavaScript |
| Code | [`vuln.py`](vuln.py) |
| Detections | [`rules/`](rules/) |

**Goal (red team):** Store an XSS payload in a feedback comment so that it
executes in the browser of every user who views the dashboard.

**Goal (blue team):** Make sure every stored XSS attempt raises an alert at
every level, and verify that the `impossible` fix prevents injection entirely.

Set the difficulty with `HONEYSCOPE_LEVEL=low|medium|high|impossible` (default `low`).

## Levels

| Level | What the app does | Why it falls |
|---|---|---|
| low | Comment stored verbatim; template renders with `\| safe` | Any HTML/JS executes in every viewer's browser |
| medium | Strips `<script>...</script>` blocks | Only `<script>` is blocked; `<img onerror=...>`, event attributes, `javascript:` URIs all work |
| high | Removes `<script>`, `<img>`, `<svg>`, `<iframe>`, and `onerror`/`onload` attributes | Single-pass, named-only blocklist; lesser-known handlers (`ontoggle`, `onmouseover`, ...) bypass it |
| impossible | `html.escape()` applied before storing; all special characters become entities | No executable markup can survive; this is the reference fix |

## Hints (no spoilers)

- low: What happens when the browser sees raw HTML in the comment body?
- medium: The filter removes `<script>` tags — but is a `<script>` tag the only way to run JavaScript?
- high: The blocklist names specific tags and two event handlers. What else can carry JavaScript?

<details><summary>Solutions (spoilers)</summary>

| Level | Payload |
|---|---|
| low | `<script>alert('XSS-low')</script>` |
| medium | `<img src=x onerror=alert('XSS-medium')>` |
| high | `<details open ontoggle=alert('XSS-high')>` |

**Why they work:**

- **low:** No filtering at all. The `| safe` Jinja2 filter disables autoescaping. The raw HTML is inserted directly into the page and executed by every browser that views the dashboard.
- **medium:** `<script>` tags are stripped by regex, but `<img>` elements with `onerror` event handlers are not checked. The browser fires `onerror` when the fake image source (`x`) fails to load.
- **high:** `<img>` and `onerror`/`onload` are blocked, but the `<details>` element's `ontoggle` event fires when the element is opened. The filter only names specific tags and two event handlers; HTML5 has ~170 event attributes.

</details>

## The fix

```python
# impossible level in vuln.py
import html
return html.escape(comment, quote=True)
```

The only reliable fix is **output encoding** (not input filtering). Jinja2's
autoescaping converts `<`, `>`, `&`, `"`, `'` to HTML entities before they
reach the browser. Blacklisting specific tags or handlers is fundamentally
incomplete: the HTML spec defines too many event attributes, and new ones are
added regularly.

In a real application you would also set a strict `Content-Security-Policy`
header that bans inline scripts.

## Blue-team material

- `scenario.json → detection_regex`: shared by the Wazuh rule, the Sigma rule
  and the automated tests, so they cannot drift apart.
- `rules/wazuh_xss_stored.xml`: Wazuh rules (IDs 100502–100503).
- `rules/sigma_xss_stored.yml`: Sigma rule for portability (Splunk, Elastic, …).
- `attack.py`: replays the payload for each level against a running instance.

```
# terminal 1
HONEYSCOPE_LEVEL=medium HONEYSCOPE_LAB=1 python app.py
# terminal 2
python scenarios/xss_stored/attack.py http://localhost:5000 medium
```

**Known false positives:** Any comment containing an HTML tag followed by a
space or `>`, such as a user explaining HTML to a colleague (e.g. `"Use <img>
to embed images"`), will match the detection regex. Tune for your environment
by restricting to your app's IP space and correlating with low reputation scores.
