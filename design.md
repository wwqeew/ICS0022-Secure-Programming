# Password manager design

## 1. Scope

The goal of this project is to implement local command-line password manager that securely stores user credentials in encrypted vault.

Password manager is intended for a single local user. Access to the vault is protected by a master password. Master password is used to derive an encryption key, which is then used to encrypt and decrypt the vault.

The application will support following core operations:

- initialize new encrypted vault
- unlock the vault using master password
- add new password entries
- list stored entries
- retrieve stored credentials
- update existing entries
- delete entries
- change master password
- save vault securely to local storage

## 2. Architecture

User <-> CLI <-> User Management <-> Encryption <-> Storage <-> Encrypted Vault

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

When storing or updating credentials, data flows from the user through the CLI and user-management module to the encryption module. 
Encryption module encrypts vault data and passes encrypted data to the storage layer, which writes it to the local vault.

When reading credentials, storage layer reads encrypted vault and passes it to the encryption module. 
Encryption module decrypts the data and returns it through the user-management module and CLI to the user.

Master password is provided through the CLI to the user-management module and is used by encryption module to derive encryption key. Master password and derived key are not stored permanently.
