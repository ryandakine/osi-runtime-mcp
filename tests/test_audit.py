"""Tests for the audit log."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from osi_runtime_mcp import audit


def test_audit_writes_record(audit_dir: Path):
    audit.log_call(tool="list_services", args={"project": "msbpv2"}, result_size_bytes=42)
    today = datetime.now(UTC).date().isoformat()
    path = audit_dir / f"audit-{today}.jsonl"
    assert path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["tool"] == "list_services"
    assert rec["args"] == {"project": "msbpv2"}
    assert rec["result_size_bytes"] == 42
    assert "ts" in rec


def test_audit_appends_multiple_calls(audit_dir: Path):
    for i in range(5):
        audit.log_call(tool="t", args={"i": i}, result_size_bytes=i)
    today = datetime.now(UTC).date().isoformat()
    path = audit_dir / f"audit-{today}.jsonl"
    assert path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 5


def test_audit_file_perms_0600(audit_dir: Path):
    audit.log_call(tool="x", args={})
    today = datetime.now(UTC).date().isoformat()
    path = audit_dir / f"audit-{today}.jsonl"
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_audit_records_redactions_applied(audit_dir: Path):
    audit.log_call(
        tool="dump_python_stack",
        args={"service": "backend"},
        redactions_applied=3,
    )
    today = datetime.now(UTC).date().isoformat()
    rec = json.loads((audit_dir / f"audit-{today}.jsonl").read_text().splitlines()[0])
    assert rec["redactions_applied"] == 3


def test_audit_handles_unwriteable_dir(monkeypatch, capsys):
    """If the audit dir can't be created, log_call must not raise."""
    monkeypatch.setenv("OSI_RUNTIME_AUDIT_DIR", "/proc/1/audit_cant_write_here")
    # Should NOT raise
    audit.log_call(tool="t", args={})
    captured = capsys.readouterr()
    assert "WARN" in captured.err or "audit write failed" in captured.err
