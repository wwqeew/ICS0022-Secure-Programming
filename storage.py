
import os
import stat
import tempfile
from pathlib import Path


MAX_VAULT_SIZE = 10 * 1024 * 1024  # 10 MiB


def read_vault(path: Path) -> bytes:
    """read existing encrypted vault"""
    path = Path(path)

    flags = os.O_RDONLY # read-only
    if hasattr(os, "O_BINARY"):
        flags = flags | os.O_BINARY # binary mode (windows)
    if hasattr(os, "O_NOFOLLOW"):
        flags = flags | os.O_NOFOLLOW # prevent following symbolic links

    fd = os.open(path, flags)

    try:
        file_info = os.fstat(fd)

        if not stat.S_ISREG(file_info.st_mode):
            raise ValueError("Vault must be a regular file")

        if file_info.st_size > MAX_VAULT_SIZE:
            raise ValueError("Vault file is too large")

        with os.fdopen(fd, "rb", closefd=False) as file:
            data = file.read(MAX_VAULT_SIZE + 1)

        if len(data) > MAX_VAULT_SIZE:
            raise ValueError("Vault file is too large")

        return data
    finally:
        os.close(fd) # always close file descriptor


def write_vault(path: Path, data: bytes) -> None:
    """atomically replace encrypted vault."""
    path = Path(path)

    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes")

    if len(data) > MAX_VAULT_SIZE:
        raise ValueError("Vault data is too large")

    path.parent.mkdir(parents=True, exist_ok=True) # create parent directories

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent, # same directory as vault
            prefix=".vault-",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            os.chmod(temporary_path, 0o600) # owner read/write (POSIX)

            file.write(data)
            file.flush() # flush python buffer
            os.fsync(file.fileno())

        os.replace(temporary_path, path) # atomically replace vault

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True) # remove leftover temporary file
