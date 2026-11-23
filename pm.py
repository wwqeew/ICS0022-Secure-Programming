"""Interactive command-line interface for the local password manager."""
import getpass
import shlex
from pathlib import Path

import pyperclip

from audit_log import log_event
from crypto import validate_master_password
from vault import create_vault, VaultSession

VAULT_PATH = Path.home() / ".ics0022-password-manager" / "vault.json"


def ask_new_password() -> str:
    password = getpass.getpass("New master password: ")
    confirmation = getpass.getpass("Confirm master password: ")
    validate_master_password(password)
    if password != confirmation:
        raise ValueError("Passwords do not match")
    return password


def copy_password(password: str) -> None:
    pyperclip.copy(password)


def print_help() -> None:
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
    if not command:
        return "continue"
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
        # Validate the name before requesting any secret input.
        session.validate_name(name)
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
            log_event(session.path.parent, "clipboard_failed", "failure")
            print("Clipboard is unavailable.")
    elif action == "update" and len(command) == 2:
        name = command[1]
        current = session.get(name)
        username = input("New username (blank to keep): ") or current["username"]
        password = getpass.getpass("New password (blank to keep): ") or current["password"]
        session.update(name, username, password)
        print("Credential updated.")
    elif action == "delete" and len(command) == 2:
        name = command[1]
        session.get(name)
        if input("Delete this entry? (yes/no): ").strip().lower() == "yes":
            session.delete(name)
            print("Credential deleted.")
        else:
            print("Deletion cancelled.")
    elif action == "change-password" and len(command) == 1:
        session.change_password(ask_new_password())
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
    session = None
    try:
        while True:
            if session is None:
                if VAULT_PATH.exists() or VAULT_PATH.is_symlink():
                    command = input("Locked. Enter to unlock or type exit: ").strip().lower()
                    if command == "exit":
                        return
                    if command:
                        print("Unknown command.")
                        continue
                else:
                    print("No vault found.")
                    command = input("pm> ").strip().lower()
                    if command == "exit":
                        return
                    if command != "init":
                        print("Type init to create a vault.")
                        continue
                    try:
                        create_vault(VAULT_PATH, ask_new_password())
                        print("Vault created.")
                    except (ValueError, TypeError, OSError, RuntimeError):
                        print("Error: request could not be completed.")
                        continue

                try:
                    session = VaultSession(VAULT_PATH, getpass.getpass("Master password: "))
                    print("Vault unlocked. Type help for commands.")
                except (ValueError, TypeError, OSError, RuntimeError):
                    print("Unable to unlock vault.")
                    continue

            try:
                raw = input("pm> ")
                if len(raw) > 2048:
                    raise ValueError("Command is too long")
                command = shlex.split(raw)
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
            except (ValueError, TypeError, OSError, RuntimeError):
                log_event(session.path.parent, "operation_failed", "failure")
                print("Error: request could not be completed.")
    except (KeyboardInterrupt, EOFError):
        print("\nPassword manager closed.")
    finally:
        if session is not None:
            session.lock()


if __name__ == "__main__":
    main()
