# ICS0022-Secure-Programming (2026 autumn), Ilja Priimak


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
