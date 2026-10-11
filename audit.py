"""Append-only application audit events with an HMAC-linked chain."""
from datetime import datetime, timezone

from db import get_db
from security import sign_audit_record, verify_audit_record


def log_event(actor_id, action, target_type=None, target_id=None):
    conn = get_db()
    try:
        previous = conn.execute(
            "SELECT hmac_signature FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_sig = previous["hmac_signature"] if previous else ""
        timestamp = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """INSERT INTO audit_log
               (actor_id, action, target_type, target_id, timestamp, previous_signature, hmac_signature)
               VALUES (?, ?, ?, ?, ?, ?, '')""",
            (actor_id, action, target_type, target_id, timestamp, prev_sig),
        )
        record = {"id": cur.lastrowid, "actor_id": actor_id, "action": action,
                  "target_type": target_type, "target_id": target_id,
                  "timestamp": timestamp, "previous_signature": prev_sig}
        signature = sign_audit_record(record)
        conn.execute("UPDATE audit_log SET hmac_signature = ? WHERE id = ?", (signature, cur.lastrowid))
        conn.commit()
    finally:
        conn.close()


def list_events():
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT audit_log.id, audit_log.actor_id, staff.full_name AS actor_name,
                      audit_log.action, audit_log.target_type, audit_log.target_id,
                      audit_log.timestamp, audit_log.previous_signature, audit_log.hmac_signature
               FROM audit_log LEFT JOIN staff ON staff.id = audit_log.actor_id
               ORDER BY audit_log.id"""
        ).fetchall()
        result, previous = [], ""
        for row in rows:
            record = {key: row[key] for key in ("id", "actor_id", "action", "target_type", "target_id", "timestamp", "previous_signature")}
            valid = row["previous_signature"] == previous and verify_audit_record(record, row["hmac_signature"])
            result.append({**dict(row), "valid": valid})
            previous = row["hmac_signature"]
        return result
    finally:
        conn.close()
