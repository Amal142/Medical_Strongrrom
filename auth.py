"""Authentication core: registration, login, logout, session validation.

Security decisions made here (explain these in your Week 6 report):
- Passwords are hashed with bcrypt (salted automatically, tunable work factor).
  We NEVER store or log a plaintext password.
- Sessions are opaque random tokens. The raw token goes in the browser's
  cookie; only its SHA-256 hash is stored server-side. If the database
  leaks, stored session hashes can't be replayed as valid cookies.
- Failed logins are rate-limited via a per-account counter + lockout window,
  independent of the session/password logic, to blunt online brute force.
- Every session is bound to an expiry; there is no "forever" login.
"""
import bcrypt
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from db import get_db

SESSION_LIFETIME = timedelta(hours=8)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


class AuthError(Exception):
    """Raised for any auth failure. Message is safe to show to the user."""


def validate_password(password: str) -> None:
    """Enforce the account password policy before hashing or storing."""
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters.")
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must include at least one number.")
    if not any(not char.isalnum() and not char.isspace() for char in password):
        raise ValueError("Password must include at least one special character, such as ! or #.")


# ---------- password hashing ----------

def hash_password(password: str) -> str:
    # bcrypt handles salt generation internally; the salt is embedded in
    # the returned hash string, so nothing extra needs to be stored.
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


# ---------- registration ----------

def register_staff(username: str, email: str, password: str, full_name: str, role: str, approved: bool = True) -> int:
    try:
        validate_password(password)
    except ValueError as e:
        raise AuthError(str(e)) from e
    if role not in ("clinician", "frontdesk"):
        raise AuthError("Staff accounts can only be clinicians or front-desk staff.")
    if username.casefold() == "admin" or email.casefold() == "admin@medical-strongroom.local":
        raise AuthError("That username or email is reserved for the administrator account.")
    if len(password) < 10:
        raise AuthError("Password must be at least 10 characters.")

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM staff WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        if existing:
            # Deliberately vague: don't reveal *which* field collided.
            raise AuthError("Username or email already in use.")

        password_hash = hash_password(password)
        cur = conn.execute(
            """INSERT INTO staff (username, email, password_hash, role, full_name, approval_status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, email, password_hash, role, full_name, "approved" if approved else "pending"),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def request_staff_account(username: str, email: str, password: str, full_name: str, role: str) -> int:
    """Create a clinician/front-desk registration that cannot sign in before approval."""
    return register_staff(username, email, password, full_name, role, approved=False)


def create_initial_admin(password: str, admin_name: str) -> int:
    """Create the one predetermined admin identity during first-run setup."""
    try:
        validate_password(password)
    except ValueError as e:
        raise AuthError(str(e)) from e
    admin_name = admin_name.strip()
    if not admin_name or len(admin_name) > 80:
        raise AuthError("Administrator name must contain 1 to 80 characters.")
    conn = get_db()
    try:
        if conn.execute("SELECT 1 FROM staff WHERE role = 'admin' LIMIT 1").fetchone():
            raise AuthError("The predetermined administrator account already exists.")
        if conn.execute("SELECT 1 FROM staff WHERE username = ?", (admin_name,)).fetchone():
            raise AuthError("That administrator name is already used as a username.")
        cur = conn.execute(
            """INSERT INTO staff (username, email, password_hash, role, full_name)
               VALUES (?, ?, ?, 'admin', ?)""",
            (admin_name, "admin@medical-strongroom.local", hash_password(password), admin_name),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def rename_initial_admin(admin_name: str) -> int:
    """Set the existing administrator's login username and display name."""
    admin_name = admin_name.strip()
    if not admin_name or len(admin_name) > 80:
        raise AuthError("Administrator name must contain 1 to 80 characters.")
    conn = get_db()
    try:
        admins = conn.execute("SELECT id FROM staff WHERE role = 'admin'").fetchall()
        if len(admins) != 1:
            raise AuthError("Expected exactly one administrator account.")
        admin_id = admins[0]["id"]
        collision = conn.execute("SELECT id FROM staff WHERE username = ? AND id != ?", (admin_name, admin_id)).fetchone()
        if collision:
            raise AuthError("That administrator name is already used as a username.")
        conn.execute("UPDATE staff SET username = ?, full_name = ? WHERE id = ?", (admin_name, admin_name, admin_id))
        conn.commit()
        return admin_id
    finally:
        conn.close()


def create_initial_frontdesk(password: str) -> int:
    """Create the predetermined Paris Anderson front-desk identity once."""
    try:
        validate_password(password)
    except ValueError as e:
        raise AuthError(str(e)) from e
    username = "paris"
    email = "paris.anderson@medical-strongroom.local"
    conn = get_db()
    try:
        if conn.execute("SELECT 1 FROM staff WHERE username = ? OR email = ?", (username, email)).fetchone():
            raise AuthError("The predetermined Paris Anderson front-desk account already exists.")
        cur = conn.execute(
            """INSERT INTO staff (username, email, password_hash, role, full_name)
               VALUES (?, ?, ?, 'frontdesk', ?)""",
            (username, email, hash_password(password), "Paris Anderson"),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def create_assignment_doctor(full_name: str, username: str, email: str, password: str) -> int:
    """Create a clinician account allowed to assign patients to clinicians."""
    try:
        validate_password(password)
    except ValueError as e:
        raise AuthError(str(e)) from e
    if not full_name.strip() or not username.strip() or not email.strip():
        raise AuthError("Name, username, and email are required.")
    conn = get_db()
    try:
        existing = conn.execute("SELECT 1 FROM staff WHERE username = ? OR email = ?", (username, email)).fetchone()
        if existing:
            raise AuthError("Username or email already in use.")
        cur = conn.execute(
            """INSERT INTO staff (username, email, password_hash, role, full_name, can_assign_patients)
               VALUES (?, ?, ?, 'clinician', ?, 1)""",
            (username.strip(), email.strip(), hash_password(password), full_name.strip()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ---------- login / lockout ----------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def verify_login_password(username: str, password: str):
    """Verify the first factor and return staff identity without creating a session."""
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM staff WHERE username = ?", (username,)).fetchone()

        # Same generic error whether the username doesn't exist or the
        # password is wrong -- don't let login responses enumerate accounts.
        generic_error = AuthError("Invalid username or password.")
        if user is None:
            # Still spend time hashing something, so response timing doesn't
            # reveal whether the username exists.
            bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            raise generic_error

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if _now() < locked_until:
                raise AuthError("Account temporarily locked. Try again later.")

        if not verify_password(password, user["password_hash"]):
            failed = user["failed_login_count"] + 1
            lock_until = None
            if failed >= MAX_FAILED_ATTEMPTS:
                lock_until = (_now() + LOCKOUT_DURATION).isoformat()
                failed = 0  # reset counter once locked
            conn.execute(
                "UPDATE staff SET failed_login_count = ?, locked_until = ? WHERE id = ?",
                (failed, lock_until, user["id"]),
            )
            conn.commit()
            raise generic_error

        # Password is only the first factor. A session is created after key verification.
        conn.execute(
            "UPDATE staff SET failed_login_count = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        conn.commit()
        if user["approval_status"] == "pending":
            raise AuthError("Account registration is awaiting administrator approval.")
        if user["approval_status"] == "rejected":
            raise AuthError("This account request was not approved. Contact the administrator.")
        return {"id": user["id"], "role": user["role"], "username": user["username"]}
    finally:
        conn.close()


def _create_session(conn, user_id: int, ip_address: str) -> str:
    # 32 bytes of CSPRNG entropy, URL-safe. This is the only place the raw
    # token exists outside the client's cookie -- we hash it before storing.
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = (_now() + SESSION_LIFETIME).isoformat()

    conn.execute(
        """INSERT INTO sessions (user_id, session_token_hash, ip_address, expires_at)
           VALUES (?, ?, ?, ?)""",
        (user_id, token_hash, ip_address, expires_at),
    )
    return raw_token


def create_session_for_user(user_id: int, ip_address: str = None) -> str:
    """Create a session after all required authentication factors succeed."""
    conn = get_db()
    try:
        token = _create_session(conn, user_id, ip_address)
        conn.commit()
        return token
    finally:
        conn.close()


# ---------- session validation / logout ----------

def validate_session(raw_token: str):
    """Returns the staff row for a valid, non-expired session, else None."""
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    conn = get_db()
    try:
        row = conn.execute(
            """SELECT sessions.expires_at, staff.* FROM sessions
               JOIN staff ON staff.id = sessions.user_id
               WHERE sessions.session_token_hash = ?""",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if _now() > datetime.fromisoformat(row["expires_at"]):
            conn.execute("DELETE FROM sessions WHERE session_token_hash = ?", (token_hash,))
            conn.commit()
            return None
        return row
    finally:
        conn.close()


def logout(raw_token: str) -> None:
    if not raw_token:
        return
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    conn = get_db()
    try:
        conn.execute("DELETE FROM sessions WHERE session_token_hash = ?", (token_hash,))
        conn.commit()
    finally:
        conn.close()
