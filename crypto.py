"""Password-based key derivation and authenticated vault encryption."""
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # KiB
ARGON2_PARALLELISM = 2
MAX_MASTER_PASSWORD_LENGTH = 4096


def validate_master_password(password: str) -> None:
    """Validate input without printing or logging the password."""
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_MASTER_PASSWORD_LENGTH:
        raise ValueError("Invalid master password")
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise ValueError("Invalid master password")


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    validate_master_password(password)
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


def _validate_crypto_args(key: bytes | bytearray, nonce: bytes, aad: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError("Invalid encryption key")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce")
    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")


def encrypt(plaintext: bytes, key: bytes | bytearray, aad: bytes, nonce: bytes) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    _validate_crypto_args(key, nonce, aad)
    return AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)


def decrypt(ciphertext: bytes, key: bytes | bytearray, nonce: bytes, aad: bytes) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    _validate_crypto_args(key, nonce, aad)
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Authentication failed") from exc
