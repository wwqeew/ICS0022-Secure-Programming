"""Interactive command-line interface for the local password manager."""
import getpass
import shlex
import hashlib
import threading
import hmac
import warnings
from pathlib import Path

import pyperclip

from audit_log import log_event
from crypto import (
    validate_new_master_password,
    MIN_MASTER_PASSWORD_LENGTH,
)
from vault import create_vault, VaultSession

VAULT_PATH = Path.home() / ".ics0022-password-manager" / "vault.json"

CLIPBOARD_TIMEOUT = 30

_clipboard_lock = threading.Lock()
_clipboard_timer = None
_clipboard_digest = None
_clipboard_token = None


def read_secret(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)

        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning as exc:
            raise ValueError("Secure password input unavailable") from exc

def ask_new_password() -> str:
    print(
        f"Master password must contain at least "
        f"{MIN_MASTER_PASSWORD_LENGTH} characters."
    )
    password = read_secret("New master password: ")
    validate_new_master_password(password)
    confirmation = read_secret("Confirm master password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match")

    return password


def clipboard_digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def clear_copied_password(token=None) -> None:
    global _clipboard_timer
    global _clipboard_digest
    global _clipboard_token

    with _clipboard_lock:
        if token is not None and token is not _clipboard_token:
            return

        if _clipboard_timer is not None:
            _clipboard_timer.cancel()

        try:
            if _clipboard_digest is not None:
                current = pyperclip.paste()

                if hmac.compare_digest(
                    clipboard_digest(current),
                    _clipboard_digest,
                ):
                    pyperclip.copy("")

        except (pyperclip.PyperclipException, OSError, UnicodeError):
            pass

        finally:
            _clipboard_timer = None
            _clipboard_digest = None
            _clipboard_token = None


def copy_password(password: str) -> None:
    global _clipboard_timer
    global _clipboard_digest
    global _clipboard_token

    digest = clipboard_digest(password)

    with _clipboard_lock:
        pyperclip.copy(password)

        if _clipboard_timer is not None:
            _clipboard_timer.cancel()

        _clipboard_digest = digest
        _clipboard_token = object()

        _clipboard_timer = threading.Timer(
            CLIPBOARD_TIMEOUT,
            clear_copied_password,
            args=(_clipboard_token,),
        )

        _clipboard_timer.daemon = True
        _clipboard_timer.start()


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
        password = read_secret("Password: ")
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
        password = read_secret("New password (blank to keep): ") or current["password"]
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
        clear_copied_password()
        session.lock()
        print("Vault locked.")
        return "lock"
    elif action == "exit" and len(command) == 1:
        clear_copied_password()
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
                    session = VaultSession(VAULT_PATH, read_secret("Master password: "))
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
        clear_copied_password()

        if session is not None:
            session.lock()


if __name__ == "__main__":
    main()
