
import base64
import json
import secrets
from pathlib import Path

from crypto import (
    SALT_SIZE,
    NONCE_SIZE,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    generate_salt,
    derive_key,
    encrypt,
    decrypt,
)
from storage import (
    read_vault,
    write_vault,
    create_vault_file,
    MAX_VAULT_SIZE,
)


VAULT_VERSION = 1


def encode_bytes(data: bytes) -> str:
    """encode binary data as Base64"""
    return base64.b64encode(data).decode("ascii")


def decode_bytes(data: str) -> bytes:
    """decode Base64 data"""
    return base64.b64decode(data, validate=True)


def get_metadata(salt: bytes, nonce: bytes) -> dict:
    """build vault metadata"""
    return {
        "version": VAULT_VERSION,
        "kdf": "argon2id",
        "time_cost": ARGON2_TIME_COST,
        "memory_cost": ARGON2_MEMORY_COST,
        "parallelism": ARGON2_PARALLELISM,
        "salt": encode_bytes(salt),
        "nonce": encode_bytes(nonce),
    }


def get_aad(metadata: dict) -> bytes:
    """convert metadata to authenticated data"""
    return json.dumps(
        metadata, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def serialize_vault(
    metadata: dict, ciphertext: bytes
) -> bytes:
    """serialize encrypted vault into JSON"""
    vault_data = metadata.copy()
    vault_data["ciphertext"] = encode_bytes(ciphertext)

    return json.dumps(vault_data).encode("utf-8")


def parse_vault(data: bytes) -> tuple[dict, bytes]:
    """parse and validate encrypted vault"""
    try:
        vault_data = json.loads(data)

        if not isinstance(vault_data, dict):
            raise ValueError("Invalid vault format")

        expected_fields = {
            "version", "kdf", "time_cost",
            "memory_cost", "parallelism",
            "salt", "nonce", "ciphertext",
        }

        if set(vault_data) != expected_fields:
            raise ValueError("Invalid vault fields")

        metadata = {
            key: value for key, value in vault_data.items()
            if key != "ciphertext"
        }

        # validate format and KDF parameters
        if type(metadata["version"]) is not int or metadata["version"] != VAULT_VERSION:
            raise ValueError("Unsupported vault version")

        if metadata["kdf"] != "argon2id":
            raise ValueError("Unsupported KDF")

        for key, expected in (
            ("time_cost", ARGON2_TIME_COST),
            ("memory_cost", ARGON2_MEMORY_COST),
            ("parallelism", ARGON2_PARALLELISM),
        ):
            if type(metadata[key]) is not int or metadata[key] != expected:
                raise ValueError("Invalid KDF parameters")

        salt = decode_bytes(metadata["salt"])
        nonce = decode_bytes(metadata["nonce"])
        ciphertext = decode_bytes(vault_data["ciphertext"])

        if len(salt) != SALT_SIZE:  # validate salt
            raise ValueError("Invalid salt")

        if len(nonce) != NONCE_SIZE:  # validate nonce
            raise ValueError("Invalid nonce")

        if len(ciphertext) < 16:  # minimum GCM tag size
            raise ValueError("Invalid ciphertext")

        return metadata, ciphertext

    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid vault format or metadata") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid vault format") from exc


def create_vault(path: Path, password: str) -> None:
    """Create new encrypted vault"""
    path = Path(path)

    if not isinstance(password, str) or not password:
        raise ValueError("Master password must not be empty")

    salt = generate_salt()  # generate random salt
    key = derive_key(password, salt)  # derive encryption key

    plaintext = json.dumps({"entries": {}}).encode("utf-8")

    nonce = secrets.token_bytes(NONCE_SIZE)  # generate random nonce
    metadata = get_metadata(salt, nonce)  # build metadata
    aad = get_aad(metadata)  # prepare authenticated data

    ciphertext = encrypt(plaintext, key, aad, nonce)  # encrypt vault
    data = serialize_vault(metadata, ciphertext)  # serialize vault

    if len(data) > MAX_VAULT_SIZE:
        raise ValueError("Vault data is too large")

    create_vault_file(path, data)  # safely create encrypted vault


def unlock_vault(path: Path, password: str) -> dict:
    """Unlock vault using master password"""
    data = read_vault(path)
    metadata, ciphertext = parse_vault(data)

    salt = decode_bytes(metadata["salt"])
    nonce = decode_bytes(metadata["nonce"])

    key = derive_key(password, salt)  # derive encryption key
    aad = get_aad(metadata)  # authenticate metadata

    plaintext = decrypt(ciphertext, key, nonce, aad)

    try:
        vault = json.loads(plaintext)  # decode vault contents

        if not isinstance(vault, dict):
            raise ValueError("Invalid vault contents")

        if not isinstance(vault.get("entries"), dict):
            raise ValueError("Invalid vault entries")

        return vault

    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid vault contents") from exc


class VaultSession:
    """Manage unlocked password vault"""

    def __init__(self, path: Path, password: str):
        self.path = Path(path)

        data = read_vault(self.path)  # read encrypted vault
        self.metadata, ciphertext = parse_vault(data)

        salt = decode_bytes(self.metadata["salt"])
        nonce = decode_bytes(self.metadata["nonce"])

        self.key = derive_key(password, salt)  # derive encryption key
        aad = get_aad(self.metadata)

        plaintext = decrypt(ciphertext, self.key, nonce, aad)
        vault = json.loads(plaintext)  # decode vault contents

        if not isinstance(vault, dict):
            raise ValueError("Invalid vault contents")

        if set(vault) != {"entries"}:
            raise ValueError("Invalid vault contents")

        if not isinstance(vault["entries"], dict):
            raise ValueError("Invalid vault entries")

        for name, entry in vault["entries"].items():
            self.validate_entry(name, entry)

        self.entries = vault["entries"]

    @staticmethod
    def validate_name(name: str) -> None:
        """validate entry name"""
        if not isinstance(name, str):
            raise ValueError("Invalid entry name")

        if not 1 <= len(name) <= 64:
            raise ValueError("Entry name must contain 1-64 characters")

        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

        if any(char not in allowed for char in name):
            raise ValueError("Invalid entry name")

    @staticmethod
    def validate_entry(name: str, entry: dict) -> None:
        """Validate credential entry."""
        VaultSession.validate_name(name)

        if not isinstance(entry, dict):
            raise ValueError("Invalid credential entry")

        if set(entry) != {"username", "password"}:
            raise ValueError("Invalid credential fields")

        if not isinstance(entry["username"], str):
            raise ValueError("Invalid username")

        if not isinstance(entry["password"], str):
            raise ValueError("Invalid password")

        if not 1 <= len(entry["username"]) <= 256:
            raise ValueError("Invalid username length")

        if not 1 <= len(entry["password"]) <= 4096:
            raise ValueError("Invalid password length")

    def save(self, entries: dict) -> None:
        """Encrypt and save updated vault"""
        if self.key is None:
            raise ValueError("Vault is locked")

        plaintext = json.dumps(
            {"entries": entries}
        ).encode("utf-8")

        nonce = secrets.token_bytes(NONCE_SIZE)  # fresh nonce
        salt = decode_bytes(self.metadata["salt"])

        metadata = get_metadata(salt, nonce)
        aad = get_aad(metadata)

        ciphertext = encrypt(
            plaintext, self.key, aad, nonce
        )

        data = serialize_vault(metadata, ciphertext)
        write_vault(self.path, data)  # atomic replacement

        self.metadata = metadata
        self.entries = entries

    def add(self, name: str, username: str, password: str) -> None:
        """Add a new credential."""
        entry = {"username": username, "password": password}
        self.validate_entry(name, entry)

        if name in self.entries:
            raise ValueError("Entry already exists")

        updated = self.entries.copy()
        updated[name] = entry

        self.save(updated)  # persist changes

    def list_entries(self) -> list[str]:
        """List credential names"""
        return sorted(self.entries)

    def get(self, name: str) -> dict:
        """Retrieve credential"""
        if name not in self.entries:
            raise ValueError("Entry not found")

        return self.entries[name].copy()

    def update(
        self, name: str, username: str, password: str
    ) -> None:
        """Update existing credential"""
        if name not in self.entries:
            raise ValueError("Entry not found")

        entry = {"username": username, "password": password}
        self.validate_entry(name, entry)

        updated = self.entries.copy()
        updated[name] = entry

        self.save(updated)  # persist changes

    def delete(self, name: str) -> None:
        """Delete existing credential"""
        if name not in self.entries:
            raise ValueError("Entry not found")

        updated = self.entries.copy()
        del updated[name]

        self.save(updated)  # persist changes

    def change_password(self, password: str) -> None:
        """Re-encrypt vault with new master password"""
        if not isinstance(password, str) or not password:
            raise ValueError("Master password must not be empty")

        salt = generate_salt()  # fresh salt
        new_key = derive_key(password, salt)
        nonce = secrets.token_bytes(NONCE_SIZE)

        metadata = get_metadata(salt, nonce)
        aad = get_aad(metadata)

        plaintext = json.dumps(
            {"entries": self.entries}
        ).encode("utf-8")

        ciphertext = encrypt(
            plaintext, new_key, aad, nonce
        )

        data = serialize_vault(metadata, ciphertext)
        write_vault(self.path, data)  # save re-encrypted vault

        self.key = new_key
        self.metadata = metadata

    def lock(self) -> None:
        """Release unlocked session data."""
        self.entries.clear()
        self.key = None
        self.metadata = None

