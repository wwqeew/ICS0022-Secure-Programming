# ICS0022 Secure Programming - Checkpoint 3 Report

**Project:** Local Command-Line Password Manager  
**Author:** Ilja Priimak  
**Checkpoint:** 3 
**Date:** 23 November 2026

## 1. Introduction

The goal of this project is to implement local command-line password manager that securely stores credentials in an encrypted vault. Application is designed for a single user on a local computer. User creates vault with a master password, unlocks it, and manages credential records using an interactive command-line interface. Each record has a name, username and password. Application does not implement cloud synchronisation, browser integration, multi-user accounts or network API.

Main security requirements are to protect credentials at rest, authenticate changes to the vault, prevent accidental exposure through the interface and logs, validate user-controlled input, restrict file access, and deny record operations whenever the session is locked. Implementation uses established cryptographic libraries instead of custom encryption algorithms.

## 2. Implementation

### 2.1 Architecture

Application is divided into the following components:

| Component | Responsibility |
|---|---|
| `pm.py` | Interactive CLI, hidden password input, command parsing, generic error messages and clipboard integration |
| `vault.py` | Vault file format, authenticated session, CRUD operations, validation and master-password rotation |
| `crypto.py` | Argon2id key derivation and AES-256-GCM authenticated encryption/decryption |
| `storage.py` | Restricted local file operations, size limits, ownership checks, safe creation and atomic replacement |
| `audit_log.py` | Fixed-schema, JSON-lines security event logging without secret fields |
| `tests/` | Automated functional and security tests |

**Data flow:** User input enters `pm.py`. Vault layer validates it and checks unlocked session. 
Modified credential records are serialized into JSON and encrypted by `crypto.py`. 
Storage layer writes only ciphertext and non-secret cryptographic metadata to a local file.

### 2.2 Vault cryptographic format

Encrypted file is JSON with exactly these fields:

- `version`: vault format version (1)
- `kdf`: `argon2id`
- `time_cost`: 3
- `memory_cost`: 65536 KiB
- `parallelism`: 2
- `salt`: Base64-encoded random 16-byte salt
- `nonce`: Base64-encoded random 12-byte AES-GCM nonce
- `ciphertext`: Base64-encoded AES-256-GCM output, including authentication tag

Argon2id derives 256-bit key from the master password. AES-256-GCM encrypts JSON record collection. 
Non-secret metadata (everything except ciphertext) is serialized consistently and supplied as Additional Authenticated Data (AAD). Incorrect passwords or altered authenticated data cause decryption to fail. Every save generates a fresh random nonce; changing master password also generates a new salt and encryption key. Application rejects unsupported KDF settings, unexpected metadata fields, malformed Base64, duplicate JSON fields and oversized files.

### 2.3 Credential operations and validation

The CLI supports `init`, `help`, `add`, `list`, `get`, `update`, `delete`, `change-password`, `lock` and `exit`. New or updated credentials are encrypted and persisted immediately. Record names are restricted to 1–64 ASCII letters, digits, dots, hyphens or underscores. Usernames must contain 1–256 characters and passwords 1–4096 characters. Master passwords have 1–4096-character range. Passwords are entered without terminal echo. `get` operation displays only username and copies the password to clipboard; it does not print the password.

CLI uses `shlex.split()` for tokenizing commands but never executes the parsed input in a shell. All record operations require an active `VaultSession`. Missing, malformed or unauthorized operations fail safely.

### 2.4 Secure storage and event logging

Default vault location is `~/.ics0022-password-manager/vault.json`. On POSIX, application creates the directory 
with `0700` permissions and the vault with `0600` permissions. Access paths are checked for expected file 
types, owner and permissions; vault reads reject symlinks. Active session detects if the vault content has changed since it was unlocked or last saved and refuses a stale write.

Vault updates are first written to a temporary file in the same directory. After flushing and synchronizing the file contents, 
application uses os.replace() to atomically publish updated vault, reducing the risk of partial writes.

Audit log is `~/.ics0022-password-manager/events.jsonl`. Events include vault creation, successful/failed unlocking, record addition/update/deletion, master-password changes and locking. Each JSON event contains only timestamp, fixed event identifier and outcome. Log never includes record names, usernames, master passwords, entry passwords, keys or vault plaintext. CLI returns generic errors rather than exposing cryptographic or filesystem exception details.

### 2.5 Session memory handling

While the session is unlocked, decrypted records and derived key must be retained in process memory to support the CLI. The session key is kept in a mutable `bytearray`. On lock, that buffer is overwritten with zeroes, references to decrypted records are cleared, and the session becomes unusable. On master-password rotation, previous mutable key buffer is overwritten as well.

This is best-effort cleanup. Python creates immutable `str` and `bytes` objects during encoding, serialization and cryptographic operations; such copies cannot reliably be overwritten by Python application code. Therefore the application does not claim full secure memory erasure. Clipboard copies also remain outside the application's control.

## 3. Security Analysis

### 3.1 Threat model and mitigations

| Asset / boundary | Threat | Mitigation or limitation |
|---|---|---|
| Master password | Echo to terminal | `getpass` disables terminal echo; password not logged or persisted |
| Master password | Offline guessing of stolen vault | Argon2id with random salt and memory-hard work factor; weak user passwords remain a risk |
| Vault at rest | Unauthorized reading | AES-256-GCM encrypts all records; restrictive POSIX filesystem permissions |
| Vault integrity | Ciphertext or metadata tampering | AES-GCM authentication tag and metadata AAD; decryption fails on changes |
| Vault format | Crafted JSON / resource exhaustion | Exact schemas, strict field types, duplicate-field rejection, fixed KDF parameters, 10 MiB maximum |
| Filesystem | Symlink and unsafe file replacement | Directory checks, final symlink rejection on read, `O_NOFOLLOW` when available, temporary files, atomic replacement; races still possible |
| File permissions | Access by other local users | POSIX owner and mode checks on each file read/write; Windows ACLs require separate validation |
| Interface | Invalid or unexpected input | Strict validation, bounded fields, no shell execution |
| Session | Record operation after lock | A mandatory unlocked-session check in every record operation |
| Memory | Retention of plaintext and keys | Best-effort mutable key zeroization and cleared session references; no guaranteed Python heap erasure |
| Logging | Sensitive values exposed in logs | Fixed event identifiers and fixed JSON schema without user-controlled payloads |
| Clipboard | Password visible in clipboard/history | Password not printed; clipboard risk explicitly disclosed and is not fully mitigated |
| Concurrent processes | Lost update or stale state | Hash comparison detects sequential stale saves, but there is no atomic multi-process lock |

### 3.2 Access control design

Since the application does not support multiple accounts, there are no separate user roles or record ownership tables. Filesystem permissions provide an additional layer of protection against other local OS users on POSIX systems.

### 3.3 Testing methodology

Automated `pytest` test suite uses isolated temporary folders and fictional credentials. It covers:

- Argon2id key length, deterministic derivation with the same salt, and differing outputs with different salts.
- AES-GCM encryption/decryption correctness and authentication failure after ciphertext or AAD modification.
- Vault initialization, correct and incorrect master-password handling, and refusal to overwrite existing vaults.
- CRUD persistence, duplicate and missing entries, maximum accepted field lengths and invalid input types/control characters.
- Master-password rotation, new salt, invalidation of the old password and key-buffer zeroization.
- Rejection of every record operation after `lock`, including read-only operations.
- Detection of stale session writes, metadata corruption, malformed vault structure, malformed Base64 and file-size limits.
- POSIX file and directory permissions, symlink rejection, and structured logging that excludes credential data.
- Clipboard failure handling without printing passwords.

### 3.4 Known residual risks

1. Python strings and temporary immutable byte buffers cannot be reliably zeroized. Memory-handling verification tests 
confirm only mutable session-key wiping and access denial after lock.
2. Windows file ACLs are not inspected by POSIX `stat` permission checks.
3. Attacker with the current user's privileges, process inspection capability, malware or clipboard access can still steal secrets.
4. No cross-process file lock prevents the narrow race between stale-write detection and atomic replacement.
5. Audit logging is intentionally best-effort; filesystem errors could prevent log event from being recorded.
6. Master-password policy rejects empty/control-character passwords but does not enforce entropy or passphrase strength.

## 4. Conclusion

This implementation provides all planned local operations with authenticated encryption, strict format validation, 
restricted POSIX file storage, consistent unlocked-session checks, structured security-event logging and tests.