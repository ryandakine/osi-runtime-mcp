"""Input validation guards for everything that crosses the subprocess boundary.

Per PLAN.md "Subprocess hygiene":
    Every input passed to subprocess validated against `^[a-z0-9_-]+$` *before*
    it touches the process boundary.
"""

from __future__ import annotations

import re

# Strict identifier pattern — service names, project names, container names.
# Lowercase ASCII letters, digits, underscore, hyphen only.
_IDENTIFIER_RE = re.compile(r"^[a-z0-9_-]+$")

# Container names from docker compose can be longer (project_service_N) but still
# only contain the same charset plus dot.
_CONTAINER_NAME_RE = re.compile(r"^[a-z0-9_.-]+$")

# Worker selector
_WORKER_SELECTOR_INT_MAX = 64

# Maximum length for any subprocess argument we accept from a tool input.
_MAX_LEN = 128


class ValidationError(ValueError):
    """Raised when a tool input fails strict validation before reaching subprocess."""


def validate_identifier(value: str, *, field: str) -> str:
    """Strict ^[a-z0-9_-]+$ check; reject anything that could be shell metacharacters.

    Returns the value unchanged if valid; raises ValidationError otherwise.
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string, got {type(value).__name__}")
    if not value:
        raise ValidationError(f"{field} must not be empty")
    if len(value) > _MAX_LEN:
        raise ValidationError(f"{field} too long (max {_MAX_LEN})")
    if not _IDENTIFIER_RE.match(value):
        raise ValidationError(
            f"{field}={value!r} contains illegal characters; "
            f"only [a-z0-9_-] permitted"
        )
    return value


def validate_container_name(value: str, *, field: str = "container") -> str:
    """Slightly looser identifier — allows '.' for legacy container naming."""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if not value or len(value) > _MAX_LEN:
        raise ValidationError(f"{field} bad length")
    if not _CONTAINER_NAME_RE.match(value):
        raise ValidationError(
            f"{field}={value!r} contains illegal characters; "
            f"only [a-z0-9_.-] permitted"
        )
    return value


def validate_pid(value: int | str, *, field: str = "pid") -> int:
    """Coerce to a positive int; reject anything else."""
    try:
        pid = int(value)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"{field} must be an integer") from e
    if pid <= 0 or pid > 2**22:
        raise ValidationError(f"{field}={pid} out of range")
    return pid


def validate_workers_selector(value: object) -> str | int:
    """Accept 'first', 'all', or a positive int <= 64."""
    if value == "first" or value == "all":
        return value  # type: ignore[return-value]
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as e:
        raise ValidationError(
            f"workers must be 'first', 'all', or a positive int, got {value!r}"
        ) from e
    if n < 1 or n > _WORKER_SELECTOR_INT_MAX:
        raise ValidationError(f"workers int out of range [1, {_WORKER_SELECTOR_INT_MAX}]")
    return n
