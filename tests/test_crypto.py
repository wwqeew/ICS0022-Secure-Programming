
import secrets
import unittest

from crypto import (
    SALT_SIZE,
    NONCE_SIZE,
    KEY_SIZE,
    generate_salt,
    derive_key,
    encrypt,
    decrypt,
)


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.password = "test-master-password"
        self.salt = generate_salt()
        self.key = derive_key(self.password, self.salt)
        self.aad = b"vault-metadata-v1"

    def test_salt_generation(self):
        self.assertEqual(len(generate_salt()), SALT_SIZE)
        self.assertNotEqual(generate_salt(), generate_salt())

    def test_key_derivation(self):
        key = derive_key(self.password, self.salt)

        self.assertEqual(len(key), KEY_SIZE)
        self.assertEqual(key, self.key)

    def test_different_password(self):
        other_key = derive_key("wrong-password", self.salt)

        self.assertNotEqual(other_key, self.key)

    def test_empty_password(self):
        with self.assertRaises(ValueError):
            derive_key("", self.salt)

    def test_invalid_salt(self):
        with self.assertRaises(ValueError):
            derive_key(self.password, b"short")

    def test_encryption_roundtrip(self):
        plaintext = b"secret credential data"
        nonce = secrets.token_bytes(NONCE_SIZE)

        ciphertext = encrypt(plaintext, self.key, self.aad, nonce)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(
            decrypt(ciphertext, self.key, nonce, self.aad),
            plaintext,
        )

    def test_wrong_key(self):
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = encrypt(b"secret", self.key, self.aad, nonce)

        wrong_key = derive_key("wrong-password", self.salt)

        with self.assertRaises(ValueError):
            decrypt(ciphertext, wrong_key, nonce, self.aad)

    def test_tampered_ciphertext(self):
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = encrypt(b"secret", self.key, self.aad, nonce)

        tampered = bytearray(ciphertext)
        tampered[0] ^= 1

        with self.assertRaises(ValueError):
            decrypt(bytes(tampered), self.key, nonce, self.aad)

    def test_tampered_aad(self):
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = encrypt(b"secret", self.key, self.aad, nonce)

        with self.assertRaises(ValueError):
            decrypt(ciphertext, self.key, nonce, b"modified-metadata")

    def test_unique_nonces(self):
        nonce1 = secrets.token_bytes(NONCE_SIZE)
        nonce2 = secrets.token_bytes(NONCE_SIZE)

        self.assertNotEqual(nonce1, nonce2)

        ciphertext1 = encrypt(b"secret", self.key, self.aad, nonce1)
        ciphertext2 = encrypt(b"secret", self.key, self.aad, nonce2)

        self.assertNotEqual(ciphertext1, ciphertext2)


if __name__ == "__main__":
    unittest.main()
