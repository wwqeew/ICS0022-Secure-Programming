# Password manager design

## 1. Scope

This project is local single-user command-line password manager.

See full project scope in [README](README.md#scope)

## 2. Architecture

User <-> CLI <-> User Management/Session<-> Encryption <-> Storage <-> Encrypted Vault

Data flows from user through the CLI and user-management module to the encryption module. Encrypted data is then passed to the storage layer and stored in the local vault. When reading data, flow occurs in the opposite direction.

### 2.1 Components

Four main components: CLI interface, user-management module, encryption module and storage layer.

#### Command-Line interface

Interacts directly with the user. 

- receives commands such as `init`, `add`, `get`, `list`, `update` and `delete`
- collects user input
- requests master password without displaying it on the screen
- validates basic input before passing it to other modules
- displays results and error messages

CLI does not directly perform cryptographic operations or access vault file.

#### User-management module

Controls access to password vault and manages current application session.

- creates initial vault
- receives master password from interface
- unlocks the vault
- manages the unlocked session
- keeps decrypted vault and derived encryption key in memory during active session
- locks vault and removes sensitive session data when the user locks or exits the application
- changes master password
- denies access when authentication fails

Master password is passed to the encryption module when cryptographic key needs to be derived. Master password itself is not stored permanently.

#### Encryption module

Responsible for all cryptographic operations used by password manager.

- derives encryption key from the master password
- encrypts vault data before it is written to storage
- decrypts vault data after it is read from storage
- verifies integrity and authenticity of encrypted data

Encryption module is the only component that performs cryptographic operations.

#### Storage layer

All interaction with local filesystem.

- reads encrypted vault from disk
- writes encrypted vault to disk
- stores non-secret cryptographic metadata such as salts and algorithm parameters
- applies restrictive file permissions
- handles filesystem-related errors

### 2.2 Data flow

When the application starts, user enters master password through CLI. User-management module passes it to the encryption module, which derives encryption key and decrypts the vault.

Decrypted vault and derived key remain in memory for the duration of the unlocked session. 

During an unlocked session, read operations such as `get` and `list` use decrypted vault stored in memory.

After any operation that modifies the vault, such as `add`, `update` or `delete`, the updated vault is immediately encrypted and safely written to storage. Session remains unlocked, so the master password does not need to be entered again.

Vault updates are written using a temporary file and atomic replacement to reduce the risk of corruption if the application terminates unexpectedly.

When the user locks the vault or exits the application, sensitive session data is no longer retained by the application.

## 3. Vault and сryptographic design

### 3.1 Vault format

Vault is stored as single local file, containing two types of data:

- non-secret metadata required to decrypt the vault
- encrypted vault contents

The metadata may include:

- vault format version
- salt used for key derivation
- key derivation parameters
- nonce required by the encryption algorithm

The encrypted part contains all password entries and other sensitive user data.

Conceptually, vault file has the following structure:

```text
Encrypted Vault
├── Version
├── Salt
├── KDF parameters
├── Nonce
└── Encrypted vault data
```

### 3.2 Master password and key derivation

Master password is used to derive encryption key and is not stored permanently.

When a vault is created:

1. a random salt is generated
2. master password and salt are passed to a password-based KDF (Argon2id)
3. resulting key is used by the encryption module to encrypt the vault
4. salt and KDF parameters are stored as non-secret metadata in the vault file

When opening an existing vault, the same salt and KDF parameters are read from the vault and used with master password to derive the same encryption key.

Derived encryption key is kept only in memory while it is required and is not written to disk.

### 3.3 Encryption scheme

AES-256-GCM will be used to encrypt the vault as it provides both confidentiality and integrity.

When encrypting the vault:

1. new random nonce is generated
2. plaintext vault data is encrypted using derived encryption key and nonce
3. ciphertext and authentication data are stored in the vault file
4. nonce is stored as non-secret metadata

When decrypting the vault, stored nonce and derived encryption key are used to decrypt and authenticate the data

Cryptographic metadata such as the vault version and KDF parameters is authenticated using AES-GCM additional authenticated data (AAD).

A new nonce must be generated whenever the vault is encrypted. Nonces must not be reused with the same encryption key.

## 4. Threat model

### 4.1 Assets

The following assets require protection:

- master password
- derived encryption key
- stored credentials
- encrypted vault file
- plaintext vault data while loaded in memory

### 4.2 Threats and mitigations

| ID | Area | Threat | Mitigation |
|---|---|---|---|
| 1 | Master password | Master password is exposed or stored in plaintext | Master password is never stored permanently and is entered using hidden input |
| 2 | Master password | Attacker performs offline brute-force attack against stolen vault | Argon2id is used with a random salt and configurable cost parameters |
| 3 | Vault at rest | Attacker reads vault file | Vault contents are encrypted with AES-256-GCM |
| 4 | Vault at rest | Attacker modifies encrypted vault data | AES-GCM authentication detects unauthorized modifications |
| 5 | Vault at rest | Vault file is owned by another user or has unexpected permissions | Storage layer verifies ownership and applies restrictive permissions |
| 6 | Vault in memory | Plaintext credentials remain in memory longer than necessary | Plaintext vault and derived key are kept in memory only while required |
| 7 | Interface | Master password is visible while being entered | CLI disables password echo |
| 8 | Interface | Malformed or unexpected user input causes unsafe behavior | Input is validated before being passed to other modules |
| 9 | Interface | Sensitive data is exposed in error messages or logs | Error messages do not include passwords, encryption keys or plaintext vault contents |
| 10 | Storage | Failure during vault update corrupts or destroys the vault | Vault updates are performed using safe temporary-file and replacement operations |
| 11 | Cryptographic metadata | Attacker modifies salt, KDF parameters or nonce | Cryptographic metadata that affects decryption is authenticated together with the encrypted vault |
| 12 | Encryption | AES-GCM nonce is reused with the same encryption key | New cryptographically random nonce is generated for every encryption |

## 5. Implementation Decisions

### Language

Python 3 will be used to implement the password manager. It provides required functionality with relatively small amount of code and reduces need for manual memory management.

### Cryptographic libraries

The following libraries are planned:

- `cryptography` - AES-256-GCM encryption and decryption
- `argon2-cffi` - Argon2id password-based key derivation
- `PyCryptodome` - optional alternative cryptographic library

### Other libraries

Python standard-library modules will be used where possible:

- `getpass` - hidden master password input
- `secrets` - generation of cryptographically secure random salts and nonces
- `json` - serialization of vault contents before encryption
- `pathlib` / `os` - filesystem operations and file permissions
- `tempfile` - safe temporary files when updating the vault
- `argparse` - command-line interface
