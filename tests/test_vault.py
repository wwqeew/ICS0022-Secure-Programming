
import base64
import json
import tempfile
import unittest
from pathlib import Path

from vault import create_vault, unlock_vault


class TestVault(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "vault.json"
        self.password = "test-master-password"

    def tearDown(self):
        self.directory.cleanup()

    def test_create_vault(self):
        create_vault(self.path, self.password)

        self.assertTrue(self.path.exists())

    def test_unlock_vault(self):
        create_vault(self.path, self.password)
        vault = unlock_vault(self.path, self.password)

        self.assertEqual(vault, {"entries": {}})

    def test_wrong_password(self):
        create_vault(self.path, self.password)

        with self.assertRaises(ValueError):
            unlock_vault(self.path, "wrong-password")

    def test_existing_vault(self):
        create_vault(self.path, self.password)
        original_data = self.path.read_bytes()

        with self.assertRaises(FileExistsError):
            create_vault(self.path, self.password)

        # Existing encrypted data must not change
        self.assertEqual(
            self.path.read_bytes(), original_data
        )

    def test_encrypted_at_rest(self):
        create_vault(self.path, self.password)
        data = self.path.read_bytes()

        self.assertNotIn(self.password.encode(), data)

        vault_data = json.loads(data)

        self.assertIn("ciphertext", vault_data)
        self.assertNotIn("entries", vault_data)

    def test_modified_ciphertext(self):
        create_vault(self.path, self.password)

        data = json.loads(self.path.read_bytes())

        ciphertext = bytearray(
            base64.b64decode(data["ciphertext"])
        )

        ciphertext[0] ^= 1  # modify encrypted data

        data["ciphertext"] = base64.b64encode(
            ciphertext
        ).decode("ascii")

        self.path.write_text(json.dumps(data))

        with self.assertRaises(ValueError):
            unlock_vault(self.path, self.password)


if __name__ == "__main__":
    unittest.main()
