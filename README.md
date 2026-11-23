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
Master passwords: 1-4096 characters. Control characters are rejected.
Any password may include spaces and ordinary punctuation. User input is never executed as a shell command.

## Cryptography and storage

- **Argon2id:** 16-byte random salt; 3 iterations; 64 MiB memory; 2 lanes.
- **AES-256-GCM:** authenticated encryption, 12-byte fresh random nonce for each save, with vault metadata as authenticated additional data (AAD).
- **Vault file:** `~/.ics0022-password-manager/vault.json` (up to 10 MiB); plaintext entry names/usernames/passwords exist only inside encrypted payload on disk.
- **POSIX permissions:** directory `0700`, vault `0600`; read and write operations verify ownership and permissions. Non-regular vaults and final-component symlinks are rejected.
- **Persistence:** temporary file, `fsync`, atomic replace, directory sync on POSIX; file creation uses exclusive publication. Session refuses to overwrite a vault that it detects has changed since last read.

## Logging and error handling

Security events are written as newline-delimited JSON in the restricted file `~/.ics0022-password-manager/events.jsonl`. Each line has only `timestamp`, a fixed `event` identifier, and `outcome`. **No entry names, usernames, passwords, keys, ciphertext or filesystem paths are logged.** CLI prints generic error messages, while test code can still inspect Python exceptions. Logging is best-effort; errors in log writing do not block password manager.

## Access control and memory

Scope is **one local user**. Every record operation requires an authenticated, unlocked `VaultSession`. File storage layer checks local ownership and permissions on POSIX. There are no separate record owners or ACLs; introducing multi-user record permissions would contradict single-user architecture.

During unlocked session, Python strings containing decrypted records remain in memory. A derived session key is held in a mutable `bytearray` and overwritten with zeroes when the session is locked or its master password is changed. Decrypted record references are released on lock. **Python cannot guarantee complete zeroization of secrets**, because internal cryptographic buffers can have copies. This is a documented limitation.

## Automated tests

Run from the repository root:

```bash
python -m pytest -q
```

Tests use temporary vaults and fake credentials. They cover encrypt/decrypt, authentication failures, metadata tampering, CRUD, password rotation, validation boundaries, locked-session denial, session-key zeroization, filesystem protection (POSIX), stale writes and secret-free logging.

## Limitations

Windows ACLs are not validated by the POSIX permission checks; Windows deployments need a separate ACL review. Malicious software running as the same user can read clipboard data and inspect the process. Clipboard contents are not automatically cleared. Python memory erasure is best-effort only. Power-loss behavior depends on the filesystem. Master-password strength is not scored.

See [design.md](design.md) for the initial architecture and threat model, and [report.md](report.md) for the Checkpoint 3 report.
