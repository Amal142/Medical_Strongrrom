"""Admin staff-management logic.

Note what's deliberately absent: nothing here reads or returns clinical
note content. Admin's permissions are account management only -- that
boundary is enforced by the route layer (admin routes never call into
patients.get_notes_for_patient) and reinforced by the fact that, once
encryption lands, admin never receives the decryption key at all.
"""
from db import get_db
from auth import hash_password, validate_password


def list_staff():
    conn = get_db()
    try:
        return conn.execute(
            "SELECT id, username, email, role, full_name, locked_until, approval_status, created_at FROM staff ORDER BY full_name"
        ).fetchall()
    finally:
        conn.close()


def get_staff_member(staff_id: int):
    conn = get_db()
    try:
        return conn.execute(
            "SELECT id, username, email, role, full_name, locked_until, approval_status, created_at FROM staff WHERE id = ?",
            (staff_id,),
        ).fetchone()
    finally:
        conn.close()


def approve_staff_request(staff_id: int) -> bool:
    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE staff SET approval_status = 'approved', locked_until = NULL, failed_login_count = 0 WHERE id = ? AND approval_status = 'pending' AND role != 'admin'",
            (staff_id,),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def reject_staff_request(staff_id: int) -> bool:
    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE staff SET approval_status = 'rejected' WHERE id = ? AND approval_status = 'pending' AND role != 'admin'",
            (staff_id,),
        )
        if cur.rowcount:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (staff_id,))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def deactivate_staff(staff_id: int) -> None:
    """'Deactivate' by locking the account indefinitely and invalidating
    any live sessions -- simpler than a separate is_active column, and it
    reuses the lockout mechanism already built and tested in Week 2.
    """
    conn = get_db()
    try:
        conn.execute(
            "UPDATE staff SET locked_until = '9999-12-31T00:00:00+00:00' WHERE id = ?",
            (staff_id,),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (staff_id,))
        conn.commit()
    finally:
        conn.close()


def reset_staff_password(staff_id: int, new_password: str) -> None:
    """Admin can force a reset but the new password still goes straight
    through the same bcrypt hashing as registration -- admin never sees
    or stores it in plaintext, and all live sessions are killed so a
    stolen session can't outlive the reset.
    """
    validate_password(new_password)
    conn = get_db()
    try:
        conn.execute(
            "UPDATE staff SET password_hash = ?, failed_login_count = 0, locked_until = NULL WHERE id = ?",
            (hash_password(new_password), staff_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (staff_id,))
        conn.commit()
    finally:
        conn.close()
