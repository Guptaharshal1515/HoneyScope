"""Scenario: IDOR and Privilege Escalation - Profile Page
(CWE-639, CWE-862, MITRE T1078)

The /profile endpoint lets users view and edit their own profile.
The weakness is two-fold:
  1. IDOR: viewing or modifying another user's profile by changing user_id.
  2. Privilege escalation: editing the role field to promote oneself to admin.

One function (profile_access), four behaviours:

  low         No ownership check on GET or POST. Role field accepted from form.
              Any logged-in user can read/write any profile and change any role.
  medium      GET checks session user matches user_id. POST still trusts the
              user_id from the POST body — the check is bypassed by overriding
              user_id in the form submission.
  high        GET and POST both verify ownership correctly. The role field is
              still accepted from the form, so a logged-in user can self-promote
              to 'admin' on their own profile (no privilege check for role changes).
  impossible  Ownership check on GET and POST; role is never accepted from the
              form (server always keeps the existing role). This is the real fix.

Containment: all user data is fake seed data in an in-memory/temp SQLite DB.
No real host privileges, files or networks are involved.
"""

SCENARIO_ID = "idor-profile"


def profile_access(db, session_user_id, session_role,
                   request_user_id, method, form, level):
    """Return (user_row, error_str, flag_trigger).

    user_row     — sqlite3.Row or None
    error_str    — string or None (HTTP 403 / 404 message)
    flag_trigger — True if the request constitutes a successful exploit
    """
    target_id = request_user_id or session_user_id

    # ------------------------------------------------------------------ GET
    if method == "GET":
        if level == "low":
            # INTENTIONALLY VULNERABLE: no ownership check
            user = db.execute("SELECT * FROM users WHERE id = ?",
                              (target_id,)).fetchone()
            return user, (None if user else "User not found"), False

        if level == "medium":
            # Ownership check on GET only
            if str(target_id) != str(session_user_id):
                # INTENTIONALLY VULNERABLE: check on GET, but not POST body
                return None, "Access denied", False
            user = db.execute("SELECT * FROM users WHERE id = ?",
                              (target_id,)).fetchone()
            return user, (None if user else "User not found"), False

        if level == "high":
            # Ownership check on GET (correctly)
            if str(target_id) != str(session_user_id):
                return None, "Access denied", False
            user = db.execute("SELECT * FROM users WHERE id = ?",
                              (target_id,)).fetchone()
            return user, (None if user else "User not found"), False

        # impossible: same ownership check on GET
        if str(target_id) != str(session_user_id):
            return None, "Access denied", False
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (target_id,)).fetchone()
        return user, (None if user else "User not found"), False

    # ------------------------------------------------------------------ POST
    new_username = form.get("username", "")
    new_email = form.get("email", "")
    new_role = form.get("role", "")
    # The POST body may supply a different user_id (IDOR vector at medium)
    post_target_id = form.get("user_id", target_id)

    if level == "low":
        # INTENTIONALLY VULNERABLE: no ownership check, role accepted from form
        db.execute(
            "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
            (new_username, new_email, new_role, post_target_id)
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (post_target_id,)).fetchone()
        flag = True  # any POST is a potential exploit at low
        return user, None, flag

    if level == "medium":
        # GET checks ownership, but POST trusts the form's user_id field.
        # INTENTIONALLY VULNERABLE: an attacker can override post_target_id.
        db.execute(
            "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
            (new_username, new_email, new_role, post_target_id)
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (post_target_id,)).fetchone()
        # Exploit triggered if the user edited a different user's record OR
        # escalated their own role to admin
        flag = (str(post_target_id) != str(session_user_id) or
                (new_role == "admin" and session_role != "admin"))
        return user, None, flag

    if level == "high":
        # Ownership check on POST — IDOR is fixed.
        # INTENTIONALLY VULNERABLE: role field still accepted from form.
        if str(post_target_id) != str(session_user_id):
            return None, "Access denied", False
        db.execute(
            "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
            (new_username, new_email, new_role, session_user_id)
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (session_user_id,)).fetchone()
        # Exploit: role escalation on own account
        flag = (new_role == "admin" and session_role != "admin")
        return user, None, flag

    # impossible: ownership check; role never taken from form
    if str(post_target_id) != str(session_user_id):
        return None, "Access denied", False
    # Fetch current role from DB — ignore whatever the form says
    current = db.execute("SELECT role FROM users WHERE id = ?",
                         (session_user_id,)).fetchone()
    current_role = current["role"] if current else "employee"
    db.execute(
        "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
        (new_username, new_email, current_role, session_user_id)
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?",
                      (session_user_id,)).fetchone()
    return user, None, False   # impossible: never a flag
