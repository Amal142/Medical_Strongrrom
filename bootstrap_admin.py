"""Create the predetermined administrator once during initial setup."""
from getpass import getpass

from db import init_db
from auth import create_initial_admin, rename_initial_admin, AuthError
from audit import log_event
from db import get_db


def main():
    init_db()
    conn = get_db()
    try:
        existing_admin = conn.execute("SELECT id FROM staff WHERE role = 'admin'").fetchone()
    finally:
        conn.close()
    admin_name = input("Administrator's name (this will be the login username): ").strip()
    try:
        if existing_admin:
            admin_id = rename_initial_admin(admin_name)
            action = "rename_admin_login"
            print(f"Administrator login username changed to '{admin_name}'. Password unchanged.")
        else:
            password = getpass("Set the administrator password (10+ characters, including a number and special character): ")
            confirmation = getpass("Confirm password: ")
            if password != confirmation:
                raise SystemExit("Passwords did not match.")
            admin_id = create_initial_admin(password, admin_name)
            action = "bootstrap_admin"
            print(f"Administrator account created. Sign in with username '{admin_name}'.")
    except AuthError as e:
        raise SystemExit(str(e))
    log_event(admin_id, action, "staff", admin_id)


if __name__ == "__main__":
    main()
