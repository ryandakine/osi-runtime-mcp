"""Pytest configuration — point audit log at a tmp dir so we never write to /var/log."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _redirect_audit_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets its own audit dir under tmp_path."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("OSI_RUNTIME_AUDIT_DIR", str(audit_dir))
    return audit_dir


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """Explicitly request the audit dir if a test needs to read records back."""
    return Path(os.environ["OSI_RUNTIME_AUDIT_DIR"])
