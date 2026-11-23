
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pm import run_command
from vault import create_vault, VaultSession


class TestCommands(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "vault.json"
        self.password = "test-master-password"

        create_vault(self.path, self.password)
        self.session = VaultSession(self.path, self.password)

    def tearDown(self):
        self.directory.cleanup()

    def test_add_command(self):
        with patch("builtins.input", return_value="testuser"):
            with patch("pm.getpass.getpass", return_value="secret123"):
                run_command(self.session, ["add", "github"])

        # Check saved credential
        entry = self.session.get("github")

        self.assertEqual(entry["username"], "testuser")
        self.assertEqual(entry["password"], "secret123")

        # Check persistence after reopening
        reopened = VaultSession(self.path, self.password)
        self.assertEqual(reopened.get("github"), entry)

    def test_list_command(self):
        self.session.add("github", "user1", "password1")
        self.session.add("taltech", "user2", "password2")

        with patch("builtins.print") as mock_print:
            run_command(self.session, ["list"])

        mock_print.assert_any_call("github")
        mock_print.assert_any_call("taltech")

    def test_get_command(self):
        self.session.add("github", "testuser", "secret123")

        with patch("pm.copy_password") as mock_copy:
            with patch("builtins.print") as mock_print:
                run_command(self.session, ["get", "github"])

        # Check clipboard function was called
        mock_copy.assert_called_once_with("secret123")

        # Password must not appear in terminal output
        output = str(mock_print.call_args_list)
        self.assertNotIn("secret123", output)

    def test_update_command(self):
        self.session.add("github", "olduser", "oldpassword")

        with patch("builtins.input", return_value="newuser"):
            with patch("pm.getpass.getpass", return_value="newpassword"):
                run_command(self.session, ["update", "github"])

        entry = self.session.get("github")

        self.assertEqual(entry["username"], "newuser")
        self.assertEqual(entry["password"], "newpassword")

        # Check changes were saved to disk
        reopened = VaultSession(self.path, self.password)
        self.assertEqual(reopened.get("github"), entry)

    def test_delete_command(self):
        self.session.add("github", "testuser", "secret123")

        with patch("builtins.input", return_value="yes"):
            run_command(self.session, ["delete", "github"])

        self.assertNotIn("github", self.session.list_entries())

        # Deleted entry must stay deleted
        reopened = VaultSession(self.path, self.password)
        self.assertEqual(reopened.list_entries(), [])

    def test_delete_cancel(self):
        self.session.add("github", "testuser", "secret123")

        with patch("builtins.input", return_value="no"):
            run_command(self.session, ["delete", "github"])

        # Entry must remain unchanged
        self.assertEqual(
            self.session.get("github")["password"],
            "secret123",
        )

    def test_change_password_command(self):
        self.session.add("github", "testuser", "secret123")

        with patch(
            "pm.ask_new_password",
            return_value="new-master-password",
        ):
            run_command(self.session, ["change-password"])

        # Old master password must fail
        with self.assertRaises(ValueError):
            VaultSession(self.path, self.password)

        # New master password must work
        reopened = VaultSession(
            self.path, "new-master-password"
        )

        self.assertEqual(
            reopened.get("github")["password"],
            "secret123",
        )

    def test_lock_command(self):
        self.session.add("github", "testuser", "secret123")

        result = run_command(self.session, ["lock"])

        self.assertEqual(result, "lock")
        self.assertIsNone(self.session.key)
        self.assertEqual(self.session.entries, {})

        # Vault must still be accessible with master password
        reopened = VaultSession(self.path, self.password)
        self.assertIn("github", reopened.list_entries())

    def test_exit_command(self):
        result = run_command(self.session, ["exit"])

        self.assertEqual(result, "exit")
        self.assertIsNone(self.session.key)

    def test_invalid_command(self):
        with patch("builtins.print") as mock_print:
            result = run_command(self.session, ["unknown"])

        self.assertEqual(result, "continue")
        mock_print.assert_called_with(
            "Unknown command. Type help for commands."
        )

    def test_invalid_entry_name(self):
        with patch("builtins.input", return_value="testuser"):
            with patch("pm.getpass.getpass", return_value="secret123"):
                with self.assertRaises(ValueError):
                    run_command(self.session, ["add", "../invalid"])

        self.assertEqual(self.session.list_entries(), [])


if __name__ == "__main__":
    unittest.main()
