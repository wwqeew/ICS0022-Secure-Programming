# ICS0022-Secure-Programming (2026 autumn), Ilja Priimak


## Scope

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

## Planned commands

After starting application, existing vault is unlocked using master password. If no vault exists, user can create one using `init`.

After successful unlock, user enters an interactive CLI session. Decrypted vault and derived encryption key remain in memory only for the duration of active session.

- `python3 pm.py` - run password manager
- `pm> init` - create new encrypted vault and set master password
- `pm> add <name>` - add new credential entry
- `pm> list` - list stored entries
- `pm> get <name>` - retrieve stored credential
- `pm> update <name>` - update an existing entry
- `pm> delete <name>` - delete an entry
- `pm> change-password` - change master password
- `pm> lock` - lock the vault and remove sensitive session data from memory
- `pm> exit` - safely exit application

## Installation

Requirements:

- Python 3
- `cryptography`
- `argon2-cffi`

Install dependencies:

```bash
pip install cryptography argon2-cffi
```

## Running

Start the application with:

```bash
python3 pm.py
```

If an existing vault is found, the user is prompted for the master password. After successful authentication, application enters interactive session.

First run:
```bash
$ python3 pm.py
No vault found.

pm> init
New master password: ********
Confirm master password: ********
Vault created and unlocked.

pm>
```
Existing vault:
```bash
$ python3 pm.py
Master password: ********
Vault unlocked.

pm> list
pm> get github
pm> add taltech
pm> lock
```
