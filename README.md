
# ICS0022 Secure Programming: Password Manager

Author: Ilja Priimak

## 1. Overview

This project implements local command-line password manager written in Python.

Application is designed for a single local user. It stores credentials in encrypted vault protected by a master password.

The master password is used to derive an encryption key with Argon2id. The vault is encrypted using AES-256-GCM, which provides confidentiality and authenticated integrity protection.

Credentials are stored in encrypted form on disk and are decrypted only after successful master password authentication.

## 2. Features

The password manager supports:

- Creating new encrypted vault
- Unlocking existing vault with a master password
- Adding credential entries
- Listing stored entry names
- Retrieving credentials
- Updating existing entries
- Deleting entries
- Changing master password
- Locking and unlocking the vault
- Saving changes to encrypted local storage

Each entry contains name, username and password.

Passwords are entered using hidden input and are not printed directly to the terminal when retrieved.

## 3. Installation

### Requirements

- Python 3.10 or newer
- cryptography
- argon2-cffi
- pyperclip

### Windows

Clone the repository:

```powershell
git clone https://github.com/wwqeew/ICS0022-Secure-Programming.git
cd ICS0022-Secure-Programming
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

### Linux / WSL

Clone the repository:

```bash
git clone https://github.com/wwqeew/ICS0022-Secure-Programming.git
cd ICS0022-Secure-Programming
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Clipboard functionality on Linux may require an additional system clipboard utility. Support depends on the environment.

## 4. Running application

Start password manager:

```bash
python pm.py
```

### First run

If no vault exists, application allows user to initialize one:

```text
No vault found.
pm> init
New master password:
Confirm master password:
Vault created.
Master password:
Vault unlocked. Type help for commands.
pm>
```

Master password must be entered again to unlock newly created vault.

### Existing vault

When an existing vault is found, user must authenticate:

```text
Locked. Enter to unlock or type exit:
Master password:
Vault unlocked. Type help for commands.
pm>
```

An incorrect master password will not unlock the vault.

## 5. Commands

Commands are available after unlocking the vault.

| Command | Description |
|---|---|
| `init` | Initialize a new vault when none exists |
| `help` | Display available commands |
| `add <name>` | Add a new credential |
| `list` | List stored entry names |
| `get <name>` | Display the username and copy the password to the clipboard |
| `update <name>` | Update an existing credential |
| `delete <name>` | Delete a credential after confirmation |
| `change-password` | Change the master password |
| `lock` | End the current unlocked session |
| `exit` | Close the application |

### Example

```text
pm> add github
Username: testuser
Password:
Credential added.

pm> list
github

pm> get github
Username: testuser
Password copied to clipboard.

pm> update github
New username (blank to keep):
New password (blank to keep):
Credential updated.

pm> delete github
Delete this entry? (yes/no): yes
Credential deleted.

pm> lock
Vault locked.
```

Entry names may contain letters, digits, dots, hyphens and underscores, with a maximum length of 64 characters.

Passwords are not shown during input. The `get` command copies a stored password to the system clipboard instead of displaying it in the terminal.

## 6. Vault Storage

Encrypted vault is stored in the user's home directory:

```text
~/.ics0022-password-manager/vault.json
```

On Windows, this corresponds to the user's Windows home directory. On WSL, the application uses the Linux home directory, so Windows and WSL normally have separate vault files.

The vault is a JSON file containing:

- Vault format version
- Argon2id parameters
- Random salt
- AES-GCM nonce
- Encrypted credential data

Credential entries are stored inside the encrypted portion, not as plaintext JSON fields.

Changes to credentials are encrypted and saved after each modifying operation.

## 7. Security Features

### Key Derivation

Argon2id derives a 256-bit encryption key from the master password and a randomly generated 16-byte salt.

Current parameters:

- Time cost: 3
- Memory cost: 65536 KiB
- Parallelism: 2

The master password itself is not stored in the vault.

### Encryption and Authentication

The vault is encrypted using AES-256-GCM.

A new random 12-byte nonce is generated for every encryption operation.

Vault metadata, including salt, nonce, version and KDF parameters, is authenticated using Additional Authenticated Data (AAD).

Changes to authenticated data or encrypted contents cause authentication to fail.

### File Storage

New vault files are prepared using temporary files before publication.

The application uses exclusive file publication to avoid overwriting an existing vault during initialization.

Vault updates use temporary files and atomic replacement to reduce risk of partial writes.

The maximum accepted vault file size is 10 MiB.

### File Permissions

On Linux and WSL, the application checks that:

- The vault directory is owned by the current user.
- Group and other users have no permissions on the vault directory.
- The vault file is owned by the current user.
- Group and other users have no permissions on the vault file.

Intended POSIX permissions are:

```text
700  .ics0022-password-manager/
600  vault.json
```

Application rejects vault access when these checks fail.

On Windows, file access is controlled by Windows ACLs. Windows permissions should be reviewed separately because POSIX permission checks do not provide equivalent protection.

### Input Validation

Application validates credential names, usernames, passwords and the structure of encrypted vault data.

Invalid or unsupported vault metadata is rejected.

### Session Management

Application keeps decrypted credentials and derived encryption key in memory while the session is unlocked.

The `lock` and `exit` commands release the application's references to session secrets.

## 8. Security Limitations

This is an educational secure programming project, not a professionally audited password manager.

Known limitations include:

- Python does not guarantee secure erasure of passwords and encryption keys from process memory.
- Passwords copied to the system clipboard may be accessible to other applications or clipboard history.
- Windows ACL security is not enforced by the same POSIX checks used on Linux.
- File permission checks do not eliminate every possible symbolic-link or filesystem race condition.
- Concurrent application instances are not coordinated and may overwrite each other's updates.
- Unexpected power loss may require additional filesystem durability guarantees beyond the current implementation.
- Application does not enforce a minimum master password strength.
- Compromised operating system or an attacker running with the user's privileges may access sensitive data.

## 9. Project Structure

```text
ICS0022-Secure-Programming/
├── pm.py             # Command-line interface
├── vault.py          # Vault and session management
├── crypto.py         # Argon2id and AES-256-GCM
├── storage.py        # Secure local file operations
├── requirements.txt  # Python dependencies
├── design.md         # Architecture and threat model
└── README.md         # Project documentation
```


## 11. Design Documentation

For more information about the architecture, cryptographic design, data flow and threat model, see [design.md](design.md).
