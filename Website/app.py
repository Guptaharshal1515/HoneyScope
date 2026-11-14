from flask import Flask, request, render_template_string, render_template, redirect, url_for, session, g
import sqlite3
import os
import json
import datetime

from scenarios import LEVELS, get_level, lab_enabled, load_scenarios, set_level
from scenarios import flags
from scenarios.sqli_login.vuln import authenticate
# SCENARIO: xss-stored (see scenarios/xss_stored/)
from scenarios.xss_stored.vuln import sanitise as xss_sanitise
# SCENARIO: idor-profile (see scenarios/idor_profile/)
from scenarios.idor_profile.vuln import profile_access
# SCENARIO: weak-creds (see scenarios/weak_creds/)
from scenarios.weak_creds.vuln import admin_check

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Intentionally weak secret key

# Phase-2 lab API blueprint (JWT, SSRF, etc.) — only imported, never breaks honeypot.
# SCENARIO: jwt-flaws and future Phase-2 scenarios (see lab_api/)
from lab_api import lab_api as _lab_api_blueprint
app.register_blueprint(_lab_api_blueprint)

DATABASE = 'honeypot.db'
LOG_DIR = '/var/log/honeypot'
LOG_FILE = os.path.join(LOG_DIR, 'access.log')

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Get a database connection for the current request context."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with tables and seed data."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee'
        )
    ''')

    # Comments/feedback table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed fake employee accounts if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        seed_users = [
            ('admin', 'admin123', 'admin@techcorp-internal.com', 'admin'),
            ('jsmith', 'password123', 'john.smith@techcorp-internal.com', 'employee'),
            ('agarcia', 'welcome1', 'ana.garcia@techcorp-internal.com', 'employee'),
            ('mwilson', 'letmein', 'mike.wilson@techcorp-internal.com', 'manager'),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            seed_users
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Logging Middleware — applies to ALL routes
# ---------------------------------------------------------------------------

@app.before_request
def log_request_start():
    """Capture request start time."""
    g.request_start = datetime.datetime.now(datetime.timezone.utc)


@app.after_request
def log_request(response):
    """Log every HTTP request to access.log in JSON Lines format."""
    try:
        # Ensure log directory exists
        log_dir = LOG_DIR
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                # Fallback to local directory on Windows or permission errors
                log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
                os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'access.log')

        # Build log entry
        log_entry = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_ip': request.remote_addr,
            'method': request.method,
            'path': request.path,
            'query_params': dict(request.args),
            'form_data': dict(request.form) if request.method == 'POST' else {},
            'user_agent': request.headers.get('User-Agent', ''),
            'response_status': response.status_code,
            'lab_level': get_level(),
        }

        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    except Exception:
        # Never crash the app due to logging failures
        pass

    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return redirect(url_for('login'))


# ---- 1. Login Page (SQL Injection vulnerable) ----

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # SCENARIO: sqli-login (see scenarios/sqli_login/). Behaviour depends on
        # HONEYSCOPE_LEVEL: low (default, original honeypot) / medium / high / impossible.
        level = get_level()
        db = get_db()

        try:
            result = authenticate(db, username, password, level)
            if result:
                session['logged_in'] = True
                session['user_id'] = result['id']
                session['username'] = result['username']
                session['role'] = result['role']
                # Logged in as someone other than who was typed = authentication bypass.
                session['bypassed'] = result['username'] != username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials. Please try again.'
        except Exception as e:
            # Verbose SQL errors only at low/medium (they help attackers; that's the point).
            error = f'An error occurred: {str(e)}' if level in ('low', 'medium') \
                else 'An error occurred.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---- 2. Employee Dashboard (Stored XSS vulnerable) ----

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_db()

    # Fetch all comments (rendered without sanitization — stored XSS)
    comments = db.execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()

    # Lab mode only: reward a real authentication bypass with a flag. Never shown
    # in honeypot mode, at the `impossible` level, or for a normal login.
    level = get_level()
    lab_flag = None
    if lab_enabled() and session.get('bypassed') and level != 'impossible':
        lab_flag = flags.flag_for('sqli-login', level)

    # SCENARIO: xss-stored. Award flag when a stored XSS payload survived the filter.
    # The session key is set in submit_comment when a surviving XSS vector is detected.
    xss_flag_level = session.pop('xss_flag_level', None)
    xss_flag = None
    if lab_enabled() and xss_flag_level and xss_flag_level != 'impossible':
        xss_flag = flags.flag_for('xss-stored', xss_flag_level)

    return render_template('dashboard.html',
                           lab_flag=lab_flag,
                           xss_flag=xss_flag,
                           username=session.get('username'),
                           role=session.get('role'),
                           user_id=session.get('user_id'),
                           comments=comments)


@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    comment_text = request.form.get('comment', '')
    user_id = session.get('user_id')
    username = session.get('username')

    if comment_text:
        # SCENARIO: xss-stored. Sanitise according to current level before storing.
        # low/medium/high: partial or no filtering — intentionally vulnerable.
        # impossible: html.escape() — no HTML survives.
        level = get_level()
        sanitised = xss_sanitise(comment_text, level)

        db = get_db()
        db.execute(
            "INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)",
            (user_id, username, sanitised)
        )
        db.commit()

        # Lab mode only: award a flag when the stored comment contains an XSS
        # vector that survived the filter (i.e. was not fully neutralised).
        # Use the same detection_regex as scenario.json (shared with Wazuh/Sigma/tests).
        if lab_enabled() and level != 'impossible':
            import re
            _xss_re = re.compile(
                r"(?i)<\s*(script|img|svg|iframe|object|embed|details|body|form"
                r"|input|link|meta|base)(\s|>|/)"
                r"|\bon\w+\s*=|javascript\s*:",
                re.IGNORECASE,
            )
            # Only award the flag if the sanitised text still contains an XSS vector
            # (i.e. the payload was not completely stripped by the current filter).
            if _xss_re.search(sanitised):
                session['xss_flag_level'] = level
    return redirect(url_for('dashboard'))


# ---- 3. Profile Page (IDOR + Privilege Escalation vulnerable) ----

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_db()
    # SCENARIO: idor-profile. Behaviour depends on HONEYSCOPE_LEVEL.
    level = get_level()

    request_user_id = request.args.get('user_id', session.get('user_id'))

    user, error, flag_trigger = profile_access(
        db=db,
        session_user_id=session.get('user_id'),
        session_role=session.get('role', 'employee'),
        request_user_id=request_user_id,
        method=request.method,
        form=request.form,
        level=level,
    )

    if error:
        status = 403 if error == "Access denied" else 404
        return error, status

    message = None
    if request.method == 'POST' and user:
        message = 'Profile updated successfully.'
        # Refresh session role if the user updated their own record
        if str(user['id']) == str(session.get('user_id')):
            session['role'] = user['role']

    # Lab mode: award flag on a successful exploit (IDOR or privilege escalation)
    idor_flag = None
    if lab_enabled() and flag_trigger and level != 'impossible':
        idor_flag = flags.flag_for('idor-profile', level)

    return render_template('profile.html', user=user, message=message,
                           idor_flag=idor_flag)


# ---- 4. Hidden Admin Panel (Weak credentials) ----
# SCENARIO: weak-creds (see scenarios/weak_creds/). Behaviour depends on
# HONEYSCOPE_LEVEL: low (original hardcoded creds) / medium (env-var, no lockout) /
# high (env-var + rate limit) / impossible (constant-time + rate limit).

@app.route('/admin', methods=['GET', 'POST'])
@app.route('/mgmt', methods=['GET', 'POST'])   # lab alias — same view, no "admin" in URL
def admin_login():
    level = get_level()
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        client_ip = request.remote_addr or '127.0.0.1'

        result = admin_check(username, password, client_ip, level)

        if result == 'ok':
            session['admin_logged_in'] = True
            # Lab mode: award flag after successful admin login (not at impossible)
            if lab_enabled() and level != 'impossible':
                session['admin_flag_level'] = level
            return redirect(url_for('admin_dashboard'))
        elif result == 'locked':
            error = 'Too many failed attempts. Try again later.'
        else:
            error = 'Access denied.'

    return render_template('admin.html', error=error)


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    # Lab mode: show flag after successful weak-credential login
    admin_flag = None
    flag_level = session.pop('admin_flag_level', None)
    if lab_enabled() and flag_level and flag_level != 'impossible':
        admin_flag = flags.flag_for('weak-creds', flag_level)
    return render_template('admin_dashboard.html', admin_flag=admin_flag)


# ---------------------------------------------------------------------------
# Lab index (opt-in): HONEYSCOPE_LAB=1. Returns 404 otherwise, so a deployed
# honeypot never exposes it. Runtime level changes are process-wide.
# ---------------------------------------------------------------------------

@app.route('/lab')
def lab_index():
    if not lab_enabled():
        return "Not Found", 404
    scs = load_scenarios()
    return render_template('lab.html', scenarios=scs, levels=LEVELS, current=get_level(),
                           flag_levels=flags.FLAG_LEVELS, solved=flags.solved(),
                           total=len(scs) * len(flags.FLAG_LEVELS),
                           msg=request.args.get('msg', ''))


@app.route('/lab/level', methods=['POST'])
def lab_set_level():
    if not lab_enabled():
        return "Not Found", 404
    if not set_level(request.form.get('level', '')):
        return "Unknown level", 400
    return redirect(url_for('lab_index'))


@app.route('/lab/flag', methods=['POST'])
def lab_submit_flag():
    if not lab_enabled():
        return "Not Found", 404
    hit = flags.submit(request.form.get('flag', ''), [s['id'] for s in load_scenarios()])
    msg = 'bad' if hit is None else ('new' if hit[2] else 'dup')
    return redirect(url_for('lab_index', msg=msg))


@app.route('/lab/reset', methods=['POST'])
def lab_reset_scores():
    if not lab_enabled():
        return "Not Found", 404
    flags.reset()
    return redirect(url_for('lab_index'))


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    # The Werkzeug debugger gives remote code execution on the host, which is
    # NOT an intentional honeypot vulnerability. Opt-in for local dev only.
    debug = os.environ.get('HONEYSCOPE_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=5000, debug=debug)
