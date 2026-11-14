from flask import Flask, request, render_template_string, render_template, redirect, url_for, session, g
import sqlite3
import os
import json
import datetime

from scenarios import LEVELS, get_level, lab_enabled, load_scenarios, set_level
from scenarios.sqli_login.vuln import authenticate

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Intentionally weak secret key

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

    return render_template('dashboard.html',
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
        db = get_db()
        db.execute(
            "INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)",
            (user_id, username, comment_text)
        )
        db.commit()

    return redirect(url_for('dashboard'))


# ---- 3. Profile Page (IDOR + Privilege Escalation vulnerable) ----

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_db()
    message = None

    # INTENTIONALLY VULNERABLE: No check that session user matches requested user_id
    user_id = request.args.get('user_id', session.get('user_id'))

    if request.method == 'POST':
        # INTENTIONALLY VULNERABLE: Updates ANY user_id without permission check
        # Allows role escalation by editing the role field
        new_username = request.form.get('username', '')
        new_email = request.form.get('email', '')
        new_role = request.form.get('role', '')
        target_id = request.form.get('user_id', user_id)

        db.execute(
            "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
            (new_username, new_email, new_role, target_id)
        )
        db.commit()
        message = 'Profile updated successfully.'

        # Refresh data
        user_id = target_id

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user is None:
        return "User not found", 404

    return render_template('profile.html', user=user, message=message)


# ---- 4. Hidden Admin Panel (Weak credentials) ----

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # INTENTIONALLY VULNERABLE: Hardcoded weak credentials
        if username == 'admin' and password == 'admin123':
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Access denied.'

    return render_template('admin.html', error=error)


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


# ---------------------------------------------------------------------------
# Lab index (opt-in): HONEYSCOPE_LAB=1. Returns 404 otherwise, so a deployed
# honeypot never exposes it. Runtime level changes are process-wide.
# ---------------------------------------------------------------------------

@app.route('/lab')
def lab_index():
    if not lab_enabled():
        return "Not Found", 404
    return render_template('lab.html', scenarios=load_scenarios(),
                           levels=LEVELS, current=get_level())


@app.route('/lab/level', methods=['POST'])
def lab_set_level():
    if not lab_enabled():
        return "Not Found", 404
    if not set_level(request.form.get('level', '')):
        return "Unknown level", 400
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
