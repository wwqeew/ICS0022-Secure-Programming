"""Restricted local storage for encrypted vaults (single-user application)."""
import os
import stat
import tempfile
from pathlib import Path

MAX_VAULT_SIZE = 10 * 1024 * 1024


def check_vault_directory(path: Path) -> None:
    path = Path(path)
    info = path.lstat()  # Never trust symlinked vault directory.
    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError("Invalid vault directory")
    if os.name == "posix":
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Insecure vault directory")
    # Windows requires independent ACL review; POSIX checks are not equivalent.


def _check_fd(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Invalid vault file")
    if os.name == "posix":
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Insecure vault file")
    if info.st_size > MAX_VAULT_SIZE:
        raise ValueError("Vault file is too large")
    return info


def read_vault(path: Path) -> bytes:
    path = Path(path)
    check_vault_directory(path.parent)
    if path.is_symlink():  # Windows fallback when O_NOFOLLOW is unavailable.
        raise PermissionError("Invalid vault file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        _check_fd(fd)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            result = fh.read(MAX_VAULT_SIZE + 1)
        if len(result) > MAX_VAULT_SIZE:
            raise ValueError("Vault file is too large")
        return result
    finally:
        os.close(fd)


def _prepare_parent(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_vault_directory(path.parent)


def _sync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(path: Path, data: bytes, *, replace: bool) -> None:
    path = Path(path)
    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes")
    if len(data) > MAX_VAULT_SIZE:
        raise ValueError("Vault data is too large")
    _prepare_parent(path)

    if replace:
        # Validate existing vault before an update. For backward-compatible
        # first writes, use exclusive creation if the vault does not yet exist.
        try:
            read_vault(path)
        except FileNotFoundError:
            replace = False

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".vault-", delete=False
        ) as fh:
            temporary_path = Path(fh.name)
            os.chmod(temporary_path, 0o600)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

        if replace:
            # A private 0700 directory limits interference between check and replace.
            os.replace(temporary_path, path)
        else:
            # Exclusive publication: never overwrite an existing vault.
            os.link(temporary_path, path)
        _sync_directory(path.parent)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_vault(path: Path, data: bytes) -> None:
    _publish(path, data, replace=True)


def create_vault_file(path: Path, data: bytes) -> None:
    _publish(path, data, replace=False)
