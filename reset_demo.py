"""Back up the demo database, then clear all demo records for a fresh start.

Run this only after stopping the Flask development server. The SQLite schema
and migration history are preserved; application data is cleared.
"""
from datetime import datetime
from pathlib import Path
import sqlite3


DB_PATH = Path(__file__).parent / "medical_strongroom.db"


def main():
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = DB_PATH.with_name(f"medical_strongroom.backup-{stamp}.db")
    source = sqlite3.connect(DB_PATH)
    backup = sqlite3.connect(backup_path)
    try:
        source.backup(backup)
    finally:
        backup.close()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        # Delete referencing rows first so foreign-key checks remain enabled.
        for table in (
            "webauthn_challenges", "sessions", "staff_security_keys",
            "clinical_notes", "audit_log", "patient_assignments",
            "patients", "staff",
        ):
            if table in tables:
                conn.execute(f'DELETE FROM "{table}"')
        if "sqlite_sequence" in tables:
            conn.execute(
                "DELETE FROM sqlite_sequence WHERE name IN "
                "('webauthn_challenges','sessions','staff_security_keys','clinical_notes','audit_log','patient_assignments','patients','staff')"
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
        source.close()
    print(f"Demo data cleared. Backup saved at: {backup_path}")


if __name__ == "__main__":
    main()
