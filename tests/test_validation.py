"""Tests for input validation guards (subprocess injection prevention)."""

from __future__ import annotations

import pytest

from osi_runtime_mcp.validation import (
    ValidationError,
    validate_container_name,
    validate_identifier,
    validate_pid,
    validate_workers_selector,
)


@pytest.mark.parametrize(
    "good",
    ["backend", "celery-worker", "msbpv2", "abc_def", "x", "service-1"],
)
def test_validate_identifier_accepts(good):
    assert validate_identifier(good, field="x") == good


@pytest.mark.parametrize(
    "bad",
    [
        "foo; rm -rf /",
        "backend && evil",
        "$(whoami)",
        "`cat /etc/passwd`",
        "service|nc",
        "../../etc/passwd",
        "backend\nrm",
        "BACKEND",  # uppercase rejected
        "",
        " backend",
        "ser vice",
    ],
)
def test_validate_identifier_rejects(bad):
    with pytest.raises(ValidationError):
        validate_identifier(bad, field="x")


def test_validate_identifier_too_long():
    with pytest.raises(ValidationError):
        validate_identifier("a" * 200, field="x")


def test_validate_identifier_non_string():
    with pytest.raises(ValidationError):
        validate_identifier(123, field="x")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "good",
    [
        "multisportsbettingplatformv2-backend-1",
        "congressional-api",
        "container.with.dots",
    ],
)
def test_validate_container_name_accepts(good):
    assert validate_container_name(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "container; rm -rf /",
        "container$(whoami)",
        "",
    ],
)
def test_validate_container_name_rejects(bad):
    with pytest.raises(ValidationError):
        validate_container_name(bad)


def test_validate_pid_accepts_int():
    assert validate_pid(123) == 123


def test_validate_pid_accepts_str():
    assert validate_pid("42") == 42


@pytest.mark.parametrize("bad", [-1, 0, "abc", None, 2**23])
def test_validate_pid_rejects(bad):
    with pytest.raises(ValidationError):
        validate_pid(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("good", ["first", "all", 1, 4, 16, 64, "8"])
def test_validate_workers_selector_accepts(good):
    validate_workers_selector(good)


@pytest.mark.parametrize("bad", ["foo", -1, 0, 65, None])
def test_validate_workers_selector_rejects(bad):
    with pytest.raises(ValidationError):
        validate_workers_selector(bad)
