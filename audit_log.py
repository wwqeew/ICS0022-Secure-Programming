"""Minimal structured security event log; never accepts arbitrary field values."""
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from storage import check_vault_directory

_EVENTS = frozenset({
    "vault_created", "unlock_success", "unlock_failed", "entry_added",
    "entry_updated", "entry_deleted", "master_password_changed", "vault_locked",
    "operation_failed", "clipboard_failed",
})
_OUTCOMES = frozenset({"success", "failure"})


def log_event(directory: Path, event: str, outcome: str = "success") -> None:
    """Best-effort logging. Caller cannot inject secret fields into log output."""
    if event not in _EVENTS or outcome not in _OUTCOMES:
        raise ValueError("Invalid audit event")
    try:
        directory = Path(directory)
        check_vault_directory(directory)
        path = directory / "events.jsonl"
        if path.is_symlink():
            return
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return
            if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
                return
            payload = json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "outcome": outcome,
            }, separators=(",", ":")) + "\n"
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError):
        # Security event recording is best-effort, and never reveals exception internals.
        pass
