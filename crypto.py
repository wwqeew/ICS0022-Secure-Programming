
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# Argon2id parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB, expressed in KB
ARGON2_PARALLELISM = 2


def generate_salt() -> bytes:
    """generate cryptographically secure random salt"""
    return secrets.token_bytes(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """derive 256-bit encryption key using Argon2id"""
    if not isinstance(password, str) or not password:
        raise ValueError("Master password must not be empty")

    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt(
    plaintext: bytes, key: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """encrypt data with AES-256-GCM.

    returns tuple containing nonce and ct.
    ct includes the authentication tag.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("Invalid encryption key")

    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")

    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def decrypt(
    ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes
) -> bytes:
    """decrypt and authenticate AES-256-GCM ciphertext."""
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("Invalid encryption key")

    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce")

    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Authentication failed") from exc
