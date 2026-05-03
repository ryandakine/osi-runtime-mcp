"""Append-only JSONL audit log with daily rotation.

Per PLAN.md security model:
    Every tool call → append-only JSONL at `/var/log/osi-runtime-mcp/audit-YYYY-MM-DD.jsonl`.
    File mode `0600` + `chattr +a` (append-only at the FS level). Daily rotate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Default audit dir; can be overridden by OSI_RUNTIME_AUDIT_DIR env var (handy for tests).
_DEFAULT_AUDIT_DIR = Path("/var/log/osi-runtime-mcp")

_lock = threading.Lock()


def _audit_dir() -> Path:
    return Path(os.environ.get("OSI_RUNTIME_AUDIT_DIR", str(_DEFAULT_AUDIT_DIR)))


def _today_path() -> Path:
    return _audit_dir() / f"audit-{datetime.now(UTC).date().isoformat()}.jsonl"


def _try_chattr_append(path: Path) -> bool:
    """Best-effort `chattr +a` on the file. Returns True if applied.

    Silently no-ops on filesystems that don't support it (e.g. tmpfs, overlayfs).
    """
    try:
        subprocess.run(
            ["chattr", "+a", str(path)],
            check=True,
            capture_output=True,
            timeout=2,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _ensure_file(path: Path) -> None:
    """Create parent dir + file with 0600 perms; apply chattr +a once."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        # Create the file with 0600 BEFORE writing anything
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        # chattr +a after creation; ignore failures
        _try_chattr_append(path)


def log_call(
    *,
    tool: str,
    args: dict[str, Any],
    caller_pid: int | None = None,
    result_size_bytes: int | None = None,
    redactions_applied: int | None = None,
    unsafe_locals: bool | None = None,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Append a single audit record to today's JSONL file.

    Best-effort: if writing fails (read-only fs, permission), log warning to stderr
    but DO NOT raise — refusing tool calls because the audit log is unavailable is
    worse than having a missing record (we can run at all).
    """
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
        "tool": tool,
        "args": args,
    }
    if caller_pid is not None:
        record["caller_pid"] = caller_pid
    if result_size_bytes is not None:
        record["result_size_bytes"] = result_size_bytes
    if redactions_applied is not None:
        record["redactions_applied"] = redactions_applied
    if unsafe_locals is not None:
        record["unsafe_locals"] = unsafe_locals
    if error is not None:
        record["error"] = error
    if extra:
        record.update(extra)

    line = json.dumps(record, separators=(",", ":"), default=str) + "\n"
    path = _today_path()

    with _lock:
        try:
            _ensure_file(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            print(
                f"osi-runtime-mcp: WARN: audit write failed at {path}: {e}",
                file=sys.stderr,
            )
