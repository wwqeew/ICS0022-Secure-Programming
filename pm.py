
import getpass
import shlex
import pyperclip
from pathlib import Path

from vault import create_vault, VaultSession


VAULT_PATH = Path.home() / ".ics0022-password-manager" / "vault.json"


def ask_new_password() -> str:
    """Request and confirm new master password"""
    password = getpass.getpass("New master password: ") # use getpass to not echo input
    confirmation = getpass.getpass("Confirm master password: ")

    if not password:
        raise ValueError("Master password cannot be empty")

    if password != confirmation:
        raise ValueError("Passwords do not match")

    return password


def copy_password(password: str) -> None:
    """Copy password to system clipboard."""
    pyperclip.copy(password)  # copy password to clipboard


def print_help() -> None:
    """Display available commands"""
    print("Available commands:")
    print("  add <name>       Add a credential")
    print("  list             List credential names")
    print("  get <name>       Copy credential password")
    print("  update <name>    Update a credential")
    print("  delete <name>    Delete a credential")
    print("  change-password  Change master password")
    print("  lock             Lock the vault")
    print("  exit             Exit password manager")


def run_command(session: VaultSession, command: list[str]) -> str:
    """Execute a command in an unlocked session."""
    action = command[0]

    if action == "help" and len(command) == 1:
        print_help()

    elif action == "list" and len(command) == 1:
        names = session.list_entries()

        if not names:
            print("Vault is empty.")
        else:
            for name in names:
                print(name)

    elif action == "add" and len(command) == 2:
        name = command[1]
        username = input("Username: ")
        password = getpass.getpass("Password: ")

        session.add(name, username, password)
        print("Credential added.")

    elif action == "get" and len(command) == 2:
        entry = session.get(command[1])
        print("Username:", entry["username"])

        try:
            copy_password(entry["password"])
            print("Password copied to clipboard.")
        except pyperclip.PyperclipException:
            print("Clipboard is unavailable.")

    elif action == "update" and len(command) == 2:
        name = command[1]
        current = session.get(name)

        username = input("New username (blank to keep): ")
        password = getpass.getpass(
            "New password (blank to keep): "
        )

        if not username:
            username = current["username"]

        if not password:
            password = current["password"]

        session.update(name, username, password)
        print("Credential updated.")

    elif action == "delete" and len(command) == 2:
        name = command[1]
        session.get(name)  # check entry exists

        confirmation = input("Delete this entry? (yes/no): ")

        if confirmation == "yes":
            session.delete(name)
            print("Credential deleted.")
        else:
            print("Deletion cancelled.")

    elif action == "change-password" and len(command) == 1:
        password = ask_new_password()
        session.change_password(password)

        print("Master password changed.")

    elif action == "lock" and len(command) == 1:
        session.lock()
        print("Vault locked.")
        return "lock"

    elif action == "exit" and len(command) == 1:
        session.lock()
        return "exit"

    else:
        print("Unknown command. Type help for commands.")

    return "continue"


def main() -> None:
    """Run interactive password manager."""
    session = None

    try:
        while True:
            if session is None:
                if VAULT_PATH.exists():
                    command = input("Locked. Enter to unlock or type exit: ").strip().lower()

                    if command == "exit":
                        return

                    if command:
                        print("Unknown command.")
                        continue

                if not VAULT_PATH.exists():
                    print("No vault found.")
                    command = input("pm> ").strip().lower()

                    if command == "exit":
                        return

                    if command != "init":
                        print("Type init to create a vault.")
                        continue

                    try:
                        password = ask_new_password()
                        create_vault(VAULT_PATH, password)
                        print("Vault created.")
                    except (ValueError, OSError) as exc:
                        print("Error:", exc)
                        continue

                password = getpass.getpass("Master password: ")

                try:
                    session = VaultSession(VAULT_PATH, password)
                    print("Vault unlocked. Type help for commands.")
                except (ValueError, OSError) as exc:
                    print("Unable to unlock vault:", exc)
                    continue

            try:
                command = shlex.split(input("pm> "))
            except ValueError:
                print("Invalid command syntax.")
                continue

            if not command:
                continue

            try:
                result = run_command(session, command)

                if result == "lock":
                    session = None

                elif result == "exit":
                    return

            except (ValueError, OSError) as exc:
                print("Error:", exc)

    except (KeyboardInterrupt, EOFError):
        print("\nPassword manager closed.")

    finally:
        if session is not None:
            session.lock()  # release session references


if __name__ == "__main__":
    main()
