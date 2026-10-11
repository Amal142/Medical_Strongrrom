"""Create the predetermined Paris Anderson front-desk account once."""
from getpass import getpass

from db import init_db
from auth import create_initial_frontdesk, AuthError
from audit import log_event


def main():
    init_db()
    password = getpass("Set Paris Anderson's password (10+ characters, including a number and special character): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match.")
    try:
        staff_id = create_initial_frontdesk(password)
    except AuthError as e:
        raise SystemExit(str(e))
    log_event(staff_id, "bootstrap_frontdesk", "staff", staff_id)
    print("Front-desk account 'paris' for Paris Anderson created.")


if __name__ == "__main__":
    main()
