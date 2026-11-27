# ICS0022 Secure Programming: Password Manager

**Author:** Ilja Priimak  
**Project:** Local, single-user command-line password manager (Python 3.10+)

This application stores credential records in a single AES-256-GCM-encrypted local vault. 
Master password is used with Argon2id to derive a key. The vault is decrypted only after successful authentication. 
No network services or multi-user accounts.

## Install and run

```bash
python -m pip install -r requirements.txt
python pm.py
```

If no vault exists, enter `init`, choose a master password, and unlock newly created vault. 
Existing vaults require master password to unlock. Running Windows and WSL normally uses separate home directories and separate vaults.

`pyperclip` library needs a working clipboard provider (Linux/WSL may need an additional clipboard utility).

## Commands

| Command | Behavior |
|---|---|
| `init` | Create vault (only when no vault exists) |
| `help` | Show available commands |
| `add <name>` | Add username and hidden password |
| `list` | List stored entry names |
| `get <name>` | Show username, copy password to clipboard |
| `update <name>` | Change username/password (blank keeps old value) |
| `delete <name>` | Delete after explicit confirmation |
| `change-password` | Re-encrypt with a new master password |
| `lock` | Lock the active session |
| `exit` | Close the application |

Entry names: 1–64 characters, only ASCII letters, digits, `.`, `_`, `-`. 
Usernames: 1-256 characters. Entry passwords: 1-4096 characters. 
Master passwords: 15-4096 characters. Control characters are rejected.
Password input is hidden. If terminal echo cannot be disabled, application refuses to read the password.
Any password may include spaces and ordinary punctuation. User input is never executed as a shell command.

## Cryptography and storage

- **Argon2id:** 16-byte random salt; 3 iterations; 64 MiB memory; 2 lanes.
- **AES-256-GCM:** authenticated encryption, 12-byte fresh random nonce for each save, with vault metadata as authenticated additional data (AAD).
- **Vault file:** `~/.ics0022-password-manager/vault.json` (up to 10 MiB); plaintext entry names/usernames/passwords exist only inside encrypted payload on disk.
- **POSIX permissions:** directory `0700`, vault `0600`; read and write operations verify ownership and permissions. Non-regular vaults and final-component symlinks are rejected.
- **Persistence:** temporary file, `fsync`, atomic replace and directory sync on POSIX. File creation uses exclusive publication.
- **Concurrent access:** cross-process file locking using `fcntl` on POSIX and `msvcrt` on Windows. Ыession checks vault revision while holding the lock to prevent stale writes.
- **File validation:** non-regular files, insecure permissions and final-component symlinks are rejected where supported. Non-blocking file opening prevents hanging on special files such as FIFOs on POSIX.
## Logging and error handling

Security events are written as newline-delimited JSON in the restricted file `~/.ics0022-password-manager/events.jsonl`. Each line has only `timestamp`, a fixed `event` identifier, and `outcome`. **No entry names, usernames, passwords, keys, ciphertext or filesystem paths are logged.** CLI prints generic error messages, while test code can still inspect Python exceptions. Logging is best-effort; errors in log writing do not block password manager.

## Clipboard security

Passwords retrieved using `get` command are copied to the clipboard instead of being displayed in the terminal.

Application attempts to clear copied passwords:

- Automatically after 30 seconds.
- When the vault is locked.
- When the application exits normally or through Ctrl+C.

Before clearing clipboard, application compares its current content with the SHA-256 digest of the copied password. Unrelated clipboard content is preserved where possible.

Clipboard history and external clipboard managers are outside application's control.

## Access control and memory

Scope is **one local user**. Every record operation requires an authenticated, unlocked `VaultSession`. File storage layer checks local ownership and permissions on POSIX. There are no separate record owners or ACLs; introducing multi-user record permissions would contradict single-user architecture.

During unlocked session, Python strings containing decrypted records remain in memory. A derived session key is held in a mutable `bytearray` and overwritten with zeroes when the session is locked or its master password is changed. Decrypted record references are released on lock. **Python cannot guarantee complete zeroization of secrets**, because internal cryptographic buffers can have copies. This is a documented limitation.

## Automated tests

Run from the repository root:

```bash
python -m pytest -q
```

Tests use temporary vaults and fake credentials. They cover encrypt/decrypt, authentication failures, metadata tampering, CRUD, password rotation, validation boundaries, locked-session denial, session-key zeroization, filesystem protection (POSIX), stale writes and secret-free logging.

### Security testing results

Testing performed on 27 November 2026.

| Environment / Tool | Result |
|---|---|
| Windows, Python 3.13 | 77 passed, 2 skipped |
| Linux/WSL, Python 3.12 | 79 passed, 0 skipped |
| Bandit static analysis | No issues identified |
| pip-audit dependency analysis (Windows) | No known vulnerabilities found |

Two platform-specific tests were skipped on Windows and passed on Linux.

## Limitations

- Python cannot guarantee complete zeroization of immutable strings and byte objects.
- Windows ACLs are not validated by POSIX permission checks.
- Malware running with the same user's privileges may access process memory, keystrokes or clipboard contents.
- Automatic clipboard cleanup cannot remove passwords from clipboard history or external clipboard managers.
- Clipboard content may change between verification and cleanup.
- File locking protects cooperating application instances, not external programs that ignore the lock.
- Audit logging is best-effort.
- Master-password length is enforced for new passwords, but password entropy is not measured.
- Power-loss behavior depends on the underlying filesystem.

See [design.md](design.md) for the initial architecture and threat model, and [report.md](report.md) for the Checkpoint 3 report.
