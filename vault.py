"""Encrypted password vault and authenticated, single-user sessions."""
import base64
import binascii
import hashlib
import json
import secrets
from pathlib import Path

from audit_log import log_event
from crypto import (
    SALT_SIZE, NONCE_SIZE, ARGON2_TIME_COST, ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM, generate_salt, derive_key, encrypt, decrypt,
    validate_new_master_password,
)
from storage import (
    read_vault,
    write_vault,
    create_vault_file,
    MAX_VAULT_SIZE,
    vault_write_lock,
)

VAULT_VERSION = 1
_ALLOWED_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_bytes(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("Invalid encoded value")
    return base64.b64decode(data, validate=True)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def get_metadata(salt: bytes, nonce: bytes) -> dict:
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
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


def serialize_vault(metadata: dict, ciphertext: bytes) -> bytes:
    result = metadata.copy()
    result["ciphertext"] = encode_bytes(ciphertext)
    return json.dumps(result, separators=(",", ":")).encode("utf-8")


def parse_vault(data: bytes) -> tuple[dict, bytes]:
    try:
        if not isinstance(data, bytes) or len(data) > MAX_VAULT_SIZE:
            raise ValueError("Invalid vault data")
        parsed = json.loads(data, object_pairs_hook=_unique_keys)
        required = {
            "version", "kdf", "time_cost", "memory_cost", "parallelism",
            "salt", "nonce", "ciphertext",
        }
        if not isinstance(parsed, dict) or set(parsed) != required:
            raise ValueError("Invalid vault structure")
        metadata = {key: value for key, value in parsed.items() if key != "ciphertext"}
        if type(metadata["version"]) is not int or metadata["version"] != VAULT_VERSION:
            raise ValueError("Unsupported version")
        if metadata["kdf"] != "argon2id":
            raise ValueError("Unsupported KDF")
        for field, expected in (
            ("time_cost", ARGON2_TIME_COST),
            ("memory_cost", ARGON2_MEMORY_COST),
            ("parallelism", ARGON2_PARALLELISM),
        ):
            if type(metadata[field]) is not int or metadata[field] != expected:
                raise ValueError("Invalid KDF parameter")
        salt = decode_bytes(metadata["salt"])
        nonce = decode_bytes(metadata["nonce"])
        ciphertext = decode_bytes(parsed["ciphertext"])
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(ciphertext) < 16:
            raise ValueError("Invalid cryptographic metadata")
        return metadata, ciphertext
    except (
        ValueError,
        TypeError,
        UnicodeError,
        OverflowError,
        binascii.Error,
        RecursionError,
    ) as exc:
        raise ValueError("Invalid vault format or metadata") from exc


def _parse_plaintext(plaintext: bytes) -> dict:
    try:
        content = json.loads(plaintext, object_pairs_hook=_unique_keys)
        if not isinstance(content, dict) or set(content) != {"entries"}:
            raise ValueError("Invalid plaintext structure")
        entries = content["entries"]
        if not isinstance(entries, dict):
            raise ValueError("Invalid entries")
        for name, entry in entries.items():
            VaultSession.validate_entry(name, entry)
        return entries
    except (
        ValueError,
        UnicodeError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise ValueError("Invalid vault contents") from exc


def _wipe(buf: bytearray | None) -> None:
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def create_vault(path: Path, password: str) -> None:
    path = Path(path)
    validate_new_master_password(password)
    salt = generate_salt()
    key = bytearray(derive_key(password, salt))
    try:
        nonce = secrets.token_bytes(NONCE_SIZE)
        metadata = get_metadata(salt, nonce)
        plaintext = json.dumps({"entries": {}}).encode("utf-8")
        ciphertext = encrypt(plaintext, key, get_aad(metadata), nonce)
        data = serialize_vault(metadata, ciphertext)
        create_vault_file(path, data)
    finally:
        _wipe(key)
    log_event(path.parent, "vault_created")


def unlock_vault(path: Path, password: str) -> dict:
    """Compatibility helper; caller is responsible for returned plaintext records."""
    session = VaultSession(path, password)
    try:
        return {"entries": {name: item.copy() for name, item in session.entries.items()}}
    finally:
        session.lock()


class VaultSession:
    """One authenticated local user; no multi-user or per-record roles."""

    def __init__(self, path: Path, password: str):
        self.path = Path(path)
        self.key: bytearray | None = None
        self.metadata: dict | None = None
        self.entries: dict[str, dict[str, str]] = {}
        self._revision: bytes | None = None
        key = None
        try:
            data = read_vault(self.path)
            metadata, ciphertext = parse_vault(data)
            salt = decode_bytes(metadata["salt"])
            nonce = decode_bytes(metadata["nonce"])
            key = bytearray(derive_key(password, salt))
            plaintext = decrypt(ciphertext, key, nonce, get_aad(metadata))
            entries = _parse_plaintext(plaintext)
        except (ValueError, TypeError, OSError, PermissionError):
            _wipe(key)
            log_event(self.path.parent, "unlock_failed", "failure")
            raise
        self.key = key
        self.metadata = metadata
        self.entries = entries
        self._revision = hashlib.sha256(data).digest()
        log_event(self.path.parent, "unlock_success")

    def _require_unlocked(self) -> None:
        if self.key is None or self.metadata is None or self._revision is None:
            raise PermissionError("Vault is locked")

    @staticmethod
    def validate_name(name: str) -> None:
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            raise ValueError("Invalid entry name")
        if any(character not in _ALLOWED_NAME_CHARS for character in name):
            raise ValueError("Invalid entry name")

    @staticmethod
    def validate_entry(name: str, entry: dict) -> None:
        VaultSession.validate_name(name)
        if not isinstance(entry, dict) or set(entry) != {"username", "password"}:
            raise ValueError("Invalid credential entry")
        username, password = entry["username"], entry["password"]
        if not isinstance(username, str) or not 1 <= len(username) <= 256:
            raise ValueError("Invalid username")
        if any(ord(char) < 32 or ord(char) == 127 for char in username):
            raise ValueError("Invalid username")
        if not isinstance(password, str) or not 1 <= len(password) <= 4096:
            raise ValueError("Invalid password")
        if any(ord(char) < 32 or ord(char) == 127 for char in password):
            raise ValueError("Invalid password")

    def _encrypt_entries(self, entries: dict, *, key: bytearray, salt: bytes) -> tuple[dict, bytes]:
        for name, entry in entries.items():
            self.validate_entry(name, entry)
        plaintext = json.dumps({"entries": entries}, ensure_ascii=True).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_SIZE)
        metadata = get_metadata(salt, nonce)
        data = serialize_vault(metadata, encrypt(plaintext, key, get_aad(metadata), nonce))
        if len(data) > MAX_VAULT_SIZE:
            raise ValueError("Vault data is too large")
        return metadata, data

    def _save_encrypted(self, metadata: dict, data: bytes) -> None:
        self._require_unlocked()

        with vault_write_lock(self.path):
            current = read_vault(self.path)

            if hashlib.sha256(current).digest() != self._revision:
                raise RuntimeError(
                    "Vault changed on disk; relock and unlock"
                )

            write_vault(self.path, data)

            self.metadata = metadata
            self._revision = hashlib.sha256(data).digest()

    def save(self, entries: dict) -> None:
        self._require_unlocked()
        if not isinstance(entries, dict):
            raise ValueError("Invalid entries")
        salt = decode_bytes(self.metadata["salt"])
        metadata, data = self._encrypt_entries(entries, key=self.key, salt=salt)
        self._save_encrypted(metadata, data)
        self.entries = {name: entry.copy() for name, entry in entries.items()}

    def add(self, name: str, username: str, password: str) -> None:
        self._require_unlocked()
        entry = {"username": username, "password": password}
        self.validate_entry(name, entry)
        if name in self.entries:
            raise ValueError("Entry already exists")
        updated = self.entries.copy()
        updated[name] = entry
        self.save(updated)
        log_event(self.path.parent, "entry_added")

    def list_entries(self) -> list[str]:
        self._require_unlocked()
        return sorted(self.entries)

    def get(self, name: str) -> dict[str, str]:
        self._require_unlocked()
        self.validate_name(name)
        if name not in self.entries:
            raise ValueError("Entry not found")
        return self.entries[name].copy()

    def update(self, name: str, username: str, password: str) -> None:
        self._require_unlocked()
        self.validate_name(name)
        if name not in self.entries:
            raise ValueError("Entry not found")
        entry = {"username": username, "password": password}
        self.validate_entry(name, entry)
        updated = self.entries.copy()
        updated[name] = entry
        self.save(updated)
        log_event(self.path.parent, "entry_updated")

    def delete(self, name: str) -> None:
        self._require_unlocked()
        self.validate_name(name)
        if name not in self.entries:
            raise ValueError("Entry not found")
        updated = self.entries.copy()
        del updated[name]
        self.save(updated)
        log_event(self.path.parent, "entry_deleted")

    def change_password(self, password: str) -> None:
        self._require_unlocked()
        validate_new_master_password(password)
        salt = generate_salt()
        new_key = bytearray(derive_key(password, salt))
        try:
            metadata, data = self._encrypt_entries(self.entries, key=new_key, salt=salt)
            self._save_encrypted(metadata, data)
        except Exception:
            _wipe(new_key)
            raise
        _wipe(self.key)
        self.key = new_key
        log_event(self.path.parent, "master_password_changed")

    def lock(self) -> None:
        if self.key is None:
            return
        # Python str and immutable temporary bytes cannot be reliably overwritten.
        self.entries.clear()
        _wipe(self.key)  # Best-effort wipe of our mutable key buffer.
        self.key = None
        self.metadata = None
        self._revision = None
        log_event(self.path.parent, "vault_locked")
