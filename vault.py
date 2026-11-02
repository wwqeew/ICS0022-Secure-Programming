
import base64
import json
import os
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
from storage import read_vault, MAX_VAULT_SIZE


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

    path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # exclusive creation
    if hasattr(os, "O_BINARY"):
        flags = flags | os.O_BINARY  # binary mode (windows)

    fd = os.open(path, flags, 0o600)

    try:
        with os.fdopen(fd, "wb", closefd=False) as file:
            file.write(data)  # write encrypted vault
            file.flush()  # flush python buffer
            os.fsync(file.fileno())  # sync file to disk
    except BaseException:
        path.unlink(missing_ok=True)  # remove incomplete vault
        raise
    finally:
        os.close(fd)  # close file descriptor


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
