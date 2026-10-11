"""Provision a clinician with the additional patient-assignment permission."""
from getpass import getpass

from db import init_db
from auth import create_assignment_doctor, AuthError
from audit import log_event


def main():
    init_db()
    full_name = input("Assignment doctor's full name: ").strip()
    username = input("Username: ").strip()
    email = input("Email: ").strip()
    password = getpass("Password (10+ characters, including a number and special character): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match.")
    try:
        staff_id = create_assignment_doctor(full_name, username, email, password)
    except AuthError as e:
        raise SystemExit(str(e))
    log_event(staff_id, "bootstrap_assignment_doctor", "staff", staff_id)
    print(f"Clinician account '{username}' created with patient-assignment permission.")


if __name__ == "__main__":
    main()
