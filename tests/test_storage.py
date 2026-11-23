
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from storage import (
    MAX_VAULT_SIZE,
    read_vault,
    write_vault,
    create_vault_file,
)


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "vault.json"

    def tearDown(self):
        self.directory.cleanup()

    def test_write_and_read(self):
        data = b"encrypted vault data"

        write_vault(self.path, data)
        result = read_vault(self.path)

        self.assertEqual(result, data)

    def test_replace_existing_vault(self):
        write_vault(self.path, b"old data")
        write_vault(self.path, b"new data")

        self.assertEqual(read_vault(self.path), b"new data")

    def test_missing_vault(self):
        with self.assertRaises(FileNotFoundError):
            read_vault(self.path)

    def test_reject_invalid_data(self):
        with self.assertRaises(TypeError):
            write_vault(self.path, "not bytes")

    def test_reject_oversized_data(self):
        data = b"x" * (MAX_VAULT_SIZE + 1)

        with self.assertRaises(ValueError):
            write_vault(self.path, data)

    def test_create_new_vault_safely(self):
        data = b"encrypted vault data"

        create_vault_file(self.path, data)

        self.assertTrue(self.path.exists())
        self.assertEqual(read_vault(self.path), data)

        # Check temporary files were removed
        self.assertEqual(
            list(self.path.parent.glob(".vault-*")), []
        )

    def test_create_does_not_overwrite(self):
        self.path.write_bytes(b"original data")

        with self.assertRaises(FileExistsError):
            create_vault_file(self.path, b"new data")

        # Existing vault must remain unchanged
        self.assertEqual(
            self.path.read_bytes(), b"original data"
        )

        self.assertEqual(
            list(self.path.parent.glob(".vault-*")), []
        )

    def test_create_failure_cleanup(self):
        # Simulate failure during file publication
        with patch(
            "storage.os.link",
            side_effect=OSError("Link failed"),
        ):
            with self.assertRaises(OSError):
                create_vault_file(self.path, b"encrypted data")

        # No final vault or temporary files should remain
        self.assertFalse(self.path.exists())

        self.assertEqual(
            list(self.path.parent.glob(".vault-*")), []
        )


if __name__ == "__main__":
    unittest.main()
