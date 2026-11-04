
import os
import stat
import tempfile
from pathlib import Path


MAX_VAULT_SIZE = 10 * 1024 * 1024  # 10 MiB


def check_vault_directory(path: Path) -> None:
    """Validate vault directory permissions"""
    path = Path(path)

    if os.name != "posix":
        return  # Windows uses ACLs

    info = path.lstat()  # inspect without following symlinks

    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError("Vault directory must be a real directory")

    if info.st_uid != os.getuid():  # check directory owner
        raise PermissionError("Vault directory has unexpected owner")

    if info.st_mode & 0o077:  # reject group and other permissions
        raise PermissionError("Vault directory permissions are too broad")


def read_vault(path: Path) -> bytes:
    """Read existing encrypted vault."""
    path = Path(path)

    check_vault_directory(path.parent)  # validate directory

    flags = os.O_RDONLY  # read-only
    if hasattr(os, "O_BINARY"):
        flags = flags | os.O_BINARY  # binary mode (Windows)
    if hasattr(os, "O_NOFOLLOW"):
        flags = flags | os.O_NOFOLLOW  # reject final symlink

    fd = os.open(path, flags)

    try:
        file_info = os.fstat(fd)  # inspect opened file

        if not stat.S_ISREG(file_info.st_mode):
            raise ValueError("Vault must be a regular file")

        if os.name == "posix":
            if file_info.st_uid != os.getuid():
                raise PermissionError("Vault file has unexpected owner")

            if file_info.st_mode & 0o077:
                raise PermissionError("Vault file permissions are too broad")

        if file_info.st_size > MAX_VAULT_SIZE:
            raise ValueError("Vault file is too large")

        with os.fdopen(fd, "rb", closefd=False) as file:
            data = file.read(MAX_VAULT_SIZE + 1)

        if len(data) > MAX_VAULT_SIZE:
            raise ValueError("Vault file is too large")

        return data

    finally:
        os.close(fd)  # always close descriptor


def write_vault(path: Path, data: bytes) -> None:
    """Atomically replace encrypted vault."""
    path = Path(path)

    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes")

    if len(data) > MAX_VAULT_SIZE:
        raise ValueError("Vault data is too large")

    path.parent.mkdir(
        parents=True, exist_ok=True, mode=0o700
    )  # create directory if missing

    check_vault_directory(path.parent)  # validate directory

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,  # same filesystem
            prefix=".vault-",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            os.chmod(temporary_path, 0o600)  # owner read/write (POSIX)

            file.write(data)
            file.flush()  # flush Python buffer
            os.fsync(file.fileno())  # sync file contents

        os.replace(temporary_path, path)  # atomic replacement

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def create_vault_file(path: Path, data: bytes) -> None:
    """Safely create a new encrypted vault."""
    path = Path(path)

    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes")

    if len(data) > MAX_VAULT_SIZE:
        raise ValueError("Vault data is too large")

    path.parent.mkdir(
        parents=True, exist_ok=True, mode=0o700
    )  # create directory if missing

    check_vault_directory(path.parent)  # validate directory

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,  # same filesystem
            prefix=".vault-",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            os.chmod(temporary_path, 0o600)  # owner read/write (POSIX)

            file.write(data)
            file.flush()  # flush Python buffer
            os.fsync(file.fileno())  # sync file contents

        os.link(temporary_path, path)  # publish without overwriting

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
