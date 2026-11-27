"""Checkpoint 3 security and functional tests (no real credentials)."""
import json
import os
from pathlib import Path

import pytest

import crypto
import pm
from crypto import decrypt, derive_key, encrypt, generate_salt
from vault import VaultSession, create_vault, parse_vault, encode_bytes
from storage import read_vault, write_vault, MAX_VAULT_SIZE

MASTER = "dummy-master-password-not-for-real-use"
NEW_MASTER = "another-dummy-master-password"
SECRET = "fake-test-secret-#2026"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "vaults" / "vault.json"


@pytest.fixture
def unlocked(path):
    create_vault(path, MASTER)
    session = VaultSession(path, MASTER)
    yield session
    session.lock()


def test_key_derivation_is_deterministic_and_salted():
    salt = generate_salt()
    assert len(derive_key(MASTER, salt)) == 32
    assert derive_key(MASTER, salt) == derive_key(MASTER, salt)
    assert derive_key(MASTER, salt) != derive_key(MASTER, generate_salt())


def test_aes_gcm_roundtrip_and_authentication():
    key = derive_key(MASTER, generate_salt())
    nonce = b"a" * 12
    aad = b"authenticated metadata"
    ciphertext = encrypt(b"secret text", key, aad, nonce)
    assert ciphertext != b"secret text"
    assert decrypt(ciphertext, key, nonce, aad) == b"secret text"
    with pytest.raises(ValueError):
        decrypt(ciphertext, key, nonce, b"modified")
    corrupted = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(ValueError):
        decrypt(corrupted, key, nonce, aad)


def test_initialize_and_unlock_and_reject_wrong_password(path):
    create_vault(path, MASTER)
    assert VaultSession(path, MASTER).list_entries() == []
    with pytest.raises(ValueError):
        VaultSession(path, "incorrect")
    with pytest.raises(FileExistsError):
        create_vault(path, MASTER)


def test_plaintext_never_appears_in_vault_file(unlocked, path):
    unlocked.add("github", "not-a-real-user", SECRET)
    raw = read_vault(path)
    assert SECRET.encode() not in raw
    assert b"not-a-real-user" not in raw
    assert b"github" not in raw
    assert unlocked.get("github") == {"username": "not-a-real-user", "password": SECRET}


def test_crud_and_persistence(unlocked, path):
    unlocked.add("service_one", "a", SECRET)
    unlocked.add("service_two", "b", "pw")
    assert unlocked.list_entries() == ["service_one", "service_two"]
    unlocked.update("service_one", "c", "newpw")
    assert unlocked.get("service_one") == {"username": "c", "password": "newpw"}
    unlocked.delete("service_two")
    assert unlocked.list_entries() == ["service_one"]
    reloaded = VaultSession(path, MASTER)
    try:
        assert reloaded.get("service_one")["password"] == "newpw"
    finally:
        reloaded.lock()


def test_duplicate_missing_and_bad_names(unlocked):
    unlocked.add("github", "a", "b")
    with pytest.raises(ValueError):
        unlocked.add("github", "a", "b")
    for action in (unlocked.get, unlocked.delete):
        with pytest.raises(ValueError):
            action("missing")
    with pytest.raises(ValueError):
        unlocked.update("missing", "a", "b")
    for name in ("", "..\\escape", "a/b", "a b", "é", "x" * 65):
        with pytest.raises(ValueError):
            unlocked.add(name, "a", "b")
    unlocked.add("a._-9", "a", "b")


@pytest.mark.parametrize("username,password", [
    ("", "valid"), ("x" * 257, "valid"), ("a\nb", "valid"),
    ("valid", ""), ("valid", "p" * 4097), ("valid", "abc\x00def"),
    ("valid", 5), (5, "valid"),
])
def test_all_credential_field_edges(unlocked, username, password):
    with pytest.raises(ValueError):
        unlocked.add("entry", username, password)


def test_upper_bound_lengths_allowed(unlocked):
    unlocked.add("x" * 64, "u" * 256, "p" * 4096)
    assert unlocked.get("x" * 64)["password"] == "p" * 4096


def test_master_password_input_validation(path):
    for password in ("", "x\ny", "x\x00y", "x" * 4097):
        with pytest.raises(ValueError):
            create_vault(path, password)


def test_change_master_password_rotates_key_and_salt(unlocked, path):
    unlocked.add("example", "a", SECRET)
    old_key = unlocked.key
    old_salt = unlocked.metadata["salt"]
    unlocked.change_password(NEW_MASTER)
    assert set(old_key) == {0}
    assert unlocked.metadata["salt"] != old_salt
    assert unlocked.get("example")["password"] == SECRET
    with pytest.raises(ValueError):
        VaultSession(path, MASTER)
    reopened = VaultSession(path, NEW_MASTER)
    try:
        assert reopened.get("example")["password"] == SECRET
    finally:
        reopened.lock()


def test_lock_wipes_mutable_session_key_and_denies_every_record_operation(unlocked):
    unlocked.add("entry", "u", "p")
    saved_key_reference = unlocked.key
    unlocked.lock()
    assert unlocked.key is None
    assert all(byte == 0 for byte in saved_key_reference)
    operations = [
        unlocked.list_entries,
        lambda: unlocked.get("entry"),
        lambda: unlocked.add("new", "a", "b"),
        lambda: unlocked.update("entry", "a", "b"),
        lambda: unlocked.delete("entry"),
        lambda: unlocked.change_password(NEW_MASTER),
        lambda: unlocked.save({}),
    ]
    for operation in operations:
        with pytest.raises(PermissionError):
            operation()


def test_stale_session_does_not_overwrite_external_changes(path):
    create_vault(path, MASTER)
    first = VaultSession(path, MASTER)
    second = VaultSession(path, MASTER)
    first.add("newer", "a", "b")
    with pytest.raises(RuntimeError):
        second.add("stale", "a", "b")
    first.lock()
    second.lock()
    current = VaultSession(path, MASTER)
    try:
        assert current.list_entries() == ["newer"]
    finally:
        current.lock()


def test_tampered_metadata_and_ciphertext_are_rejected(path):
    create_vault(path, MASTER)
    original = read_vault(path)
    for field, value in (("nonce", encode_bytes(b"z" * 12)), ("ciphertext", encode_bytes(b"x" * 48))):
        document = json.loads(original)
        document[field] = value
        write_vault(path, json.dumps(document).encode())
        with pytest.raises(ValueError):
            VaultSession(path, MASTER)
        write_vault(path, original)


@pytest.mark.parametrize("document", [
    b"not json", b"{}", b"[]", b'{"version":1,"version":1}',
    b'{"entries":{"a":{"username":"a","password":"p"}}}',
])
def test_malformed_vault_rejected(document):
    with pytest.raises(ValueError):
        parse_vault(document)


def test_invalid_base64_metadata_rejected(path):
    create_vault(path, MASTER)
    doc = json.loads(read_vault(path))
    doc["salt"] = "!!!!"
    write_vault(path, json.dumps(doc).encode())
    with pytest.raises(ValueError):
        VaultSession(path, MASTER)


def test_reject_oversized_vault_data(path):
    create_vault(path, MASTER)
    with pytest.raises(ValueError):
        write_vault(path, b"A" * (MAX_VAULT_SIZE + 1))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_posix_directory_and_file_modes(path):
    create_vault(path, MASTER)
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        read_vault(path)
    os.chmod(path, 0o600)
    os.chmod(path.parent, 0o755)
    with pytest.raises(PermissionError):
        read_vault(path)


@pytest.mark.skipif(os.name != "posix", reason="Symlink behavior depends on OS")
def test_symlinked_vault_rejected(path):
    create_vault(path, MASTER)
    sibling = path.parent / "symlink"
    sibling.symlink_to(path)
    with pytest.raises((PermissionError, OSError)):
        read_vault(sibling)


def test_structured_log_never_includes_credentials(unlocked, path):
    unlocked.add("sensitive-record-name", "sensitive-username", SECRET)
    unlocked.update("sensitive-record-name", "other-name", SECRET)
    unlocked.delete("sensitive-record-name")
    content = (path.parent / "events.jsonl").read_text()
    for sensitive in ("sensitive-record-name", "sensitive-username", SECRET, MASTER):
        assert sensitive not in content
    events = [json.loads(line) for line in content.splitlines()]
    assert all(set(event) == {"timestamp", "event", "outcome"} for event in events)
    assert {"vault_created", "unlock_success", "entry_added", "entry_updated", "entry_deleted"}.issubset(
        {event["event"] for event in events}
    )


def test_cli_clipboard_fallback_does_not_print_password(unlocked, monkeypatch, capsys):
    unlocked.add("name", "username", SECRET)
    import pyperclip
    def fail(_password):
        raise pyperclip.PyperclipException("mock unavailable")
    monkeypatch.setattr(pm, "copy_password", fail)
    assert pm.run_command(unlocked, ["get", "name"]) == "continue"
    captured = capsys.readouterr().out
    assert "Clipboard is unavailable" in captured
    assert SECRET not in captured


def test_scripted_cli_end_to_end(tmp_path, monkeypatch, capsys):
    """Exercise init, unlock, add, list, get, update, delete, lock, exit."""
    vault_path = tmp_path / "cli" / "vault.json"
    monkeypatch.setattr(pm, "VAULT_PATH", vault_path)
    answers = iter([
        "init", "add example", "testuser", "list", "get example",
        "update example", "updated-user", "delete example", "yes", "lock", "exit",
    ])
    passwords = iter([MASTER, MASTER, MASTER, SECRET, "updated-fake-secret"])
    clipboard = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(pm.getpass, "getpass", lambda _prompt="": next(passwords))
    monkeypatch.setattr(pm, "copy_password", clipboard.append)

    pm.main()
    output = capsys.readouterr().out
    assert "Vault created." in output
    assert "Credential added." in output
    assert "Credential updated." in output
    assert "Credential deleted." in output
    assert "Vault locked." in output
    assert clipboard == [SECRET]
    assert SECRET not in output
    session = VaultSession(vault_path, MASTER)
    try:
        assert session.list_entries() == []
    finally:
        session.lock()


@pytest.mark.parametrize("password", ["a", "12345678", "a" * 14])
def test_reject_short_master_password(path, password):
    with pytest.raises(ValueError):
        create_vault(path, password)

    assert not path.exists()


def test_minimum_master_password_length(path):
    password = "a" * 15
    create_vault(path, password)

    session = VaultSession(path, password)
    try:
        assert session.list_entries() == []
    finally:
        session.lock()


def test_reject_short_password_rotation(unlocked, path):
    with pytest.raises(ValueError):
        unlocked.change_password("short")

    session = VaultSession(path, MASTER)
    try:
        assert session.list_entries() == unlocked.list_entries()
    finally:
        session.lock()

@pytest.fixture
def fake_clipboard(monkeypatch):
    clipboard = [""]

    monkeypatch.setattr(
        pm.pyperclip,
        "copy",
        lambda value: clipboard.__setitem__(0, value),
    )

    monkeypatch.setattr(
        pm.pyperclip,
        "paste",
        lambda: clipboard[0],
    )

    yield clipboard

    pm.clear_copied_password()


def test_clipboard_password_is_cleared(fake_clipboard):
    pm.copy_password(SECRET)

    assert fake_clipboard[0] == SECRET

    pm.clear_copied_password()

    assert fake_clipboard[0] == ""


def test_clipboard_preserves_other_text(fake_clipboard):
    pm.copy_password(SECRET)

    fake_clipboard[0] = "unrelated text"

    pm.clear_copied_password()

    assert fake_clipboard[0] == "unrelated text"


def test_old_clipboard_timer_cannot_clear_new_password(
    fake_clipboard,
):
    pm.copy_password(SECRET)
    old_token = pm._clipboard_token

    pm.copy_password("another-fake-secret")

    pm.clear_copied_password(old_token)

    assert fake_clipboard[0] == "another-fake-secret"

    pm.clear_copied_password(pm._clipboard_token)

    assert fake_clipboard[0] == ""

def test_concurrent_write_lock(unlocked, path):
    from storage import vault_write_lock

    with vault_write_lock(path):
        with pytest.raises(RuntimeError, match="Vault is busy"):
            unlocked.add("example", "user", SECRET)

    assert unlocked.list_entries() == []

    unlocked.add("example", "user", SECRET)

    assert unlocked.get("example")["password"] == SECRET


def test_write_lock_released_on_exception(path):
    from storage import vault_write_lock

    with pytest.raises(ValueError):
        with vault_write_lock(path):
            raise ValueError("Simulated failure")

    with vault_write_lock(path):
        pass

def test_secure_password_input_rejects_echo(monkeypatch):
    import warnings
    import getpass

    def insecure_input(prompt):
        warnings.warn(
            "Echo cannot be disabled",
            getpass.GetPassWarning,
        )
        return SECRET

    monkeypatch.setattr(
        pm.getpass,
        "getpass",
        insecure_input,
    )

    with pytest.raises(ValueError):
        pm.read_secret("Password: ")


def test_deeply_nested_json_rejected():
    data = b"[" * 2000 + b"]" * 2000

    with pytest.raises(ValueError):
        parse_vault(data)