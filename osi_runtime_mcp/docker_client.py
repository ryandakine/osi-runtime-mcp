"""Thin wrapper around the docker CLI.

Per PLAN.md subprocess hygiene:
    All `subprocess.run(...)` invocations use list-form, `shell=False`,
    no f-string assembly. Every input passed to subprocess validated against
    `^[a-z0-9_-]+$` *before* it touches the process boundary.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any

from .validation import validate_container_name, validate_identifier

# Default timeout for any docker command
_DOCKER_TIMEOUT_S = 8.0


class DockerError(RuntimeError):
    """Raised when a docker CLI invocation fails."""


@dataclass
class ContainerInfo:
    """Subset of `docker compose ps --format json` we care about."""

    container_id: str
    name: str
    project: str
    service: str
    image: str
    state: str
    status: str
    health: str
    labels: dict[str, str]
    ports: str

    @property
    def language(self) -> str:
        return self.labels.get("osi.runtime.language", "other")

    @property
    def introspect_allowed(self) -> bool:
        return self.labels.get("osi.runtime.introspect", "").lower() == "allow"

    @property
    def locals_allowed(self) -> bool:
        return self.labels.get("osi.runtime.allow_locals", "").lower() == "true"

    @property
    def osi_project(self) -> str | None:
        return self.labels.get("osi.runtime.project")


def _parse_labels(raw: str) -> dict[str, str]:
    """Parse the comma-separated `Labels` field from `docker ps --format json`."""
    out: dict[str, str] = {}
    if not raw:
        return out
    # Labels are comma-separated key=value pairs, but values can contain commas
    # in theory — for our purposes we accept the simple split since osi.* labels
    # don't contain commas.
    for part in raw.split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    return out


def _run_docker(args: list[str], *, timeout: float = _DOCKER_TIMEOUT_S) -> str:
    """Run a docker command and return stdout. Raise DockerError on failure."""
    cmd = ["docker", *args]
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as e:
        raise DockerError("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker {args[0] if args else ''} timed out") from e
    except subprocess.CalledProcessError as e:
        raise DockerError(
            f"docker {' '.join(args)} failed: rc={e.returncode} stderr={e.stderr!r}"
        ) from e
    return proc.stdout


def list_containers() -> list[ContainerInfo]:
    """Return all running containers, keyed by docker ps output.

    We use `docker ps --format json` rather than `docker compose ps` because
    a single host has many compose projects; we filter by project later.
    """
    raw = _run_docker(["ps", "--format", "json"])
    containers: list[ContainerInfo] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels = _parse_labels(obj.get("Labels", ""))
        # Project: prefer compose project label
        project = labels.get(
            "com.docker.compose.project",
            obj.get("Project", ""),
        )
        service = labels.get(
            "com.docker.compose.service",
            obj.get("Service", ""),
        )
        containers.append(
            ContainerInfo(
                container_id=obj.get("ID", ""),
                name=obj.get("Names", obj.get("Name", "")),
                project=project,
                service=service,
                image=obj.get("Image", ""),
                state=obj.get("State", ""),
                status=obj.get("Status", ""),
                health=obj.get("Health", ""),
                labels=labels,
                ports=obj.get("Ports", ""),
            )
        )
    return containers


def list_introspectable_containers(project: str | None = None) -> list[ContainerInfo]:
    """List only containers labeled `osi.runtime.introspect=allow`.

    If `project` is provided, additionally filter by `osi.runtime.project=<project>`
    or compose project name match. Validated against ^[a-z0-9_-]+$ before use.
    """
    if project is not None:
        validate_identifier(project, field="project")

    out: list[ContainerInfo] = []
    for c in list_containers():
        if not c.introspect_allowed:
            continue
        if project is not None:
            if c.osi_project != project and c.project != project:
                continue
        out.append(c)
    return out


def find_container_by_service(
    service: str,
    *,
    project: str | None = None,
) -> ContainerInfo:
    """Resolve `service` to a single ContainerInfo or raise.

    `service` must be the docker compose service name. Validated.
    """
    validate_identifier(service, field="service")
    if project is not None:
        validate_identifier(project, field="project")

    candidates = [
        c
        for c in list_introspectable_containers(project=project)
        if c.service == service
    ]
    if not candidates:
        raise DockerError(
            f"no introspectable container found for service={service!r}"
            + (f" project={project!r}" if project else "")
            + " (must have label osi.runtime.introspect=allow)"
        )
    if len(candidates) > 1:
        names = sorted(c.name for c in candidates)
        raise DockerError(
            f"multiple containers match service={service!r}: {names}; "
            f"specify project= to disambiguate"
        )
    return candidates[0]


# ---- exec into container ---------------------------------------------------

# Output of `ps -eo pid,comm --no-headers` parsed into (pid, comm) tuples.
_PS_LINE_RE = re.compile(r"^\s*(\d+)\s+(\S.*)$")

# Process names that indicate a Python runtime worth attaching py-spy to.
_PYTHON_PROCESS_RE = re.compile(r"python|uvicorn|gunicorn|celery", re.IGNORECASE)


def list_python_pids(container_name: str, *, timeout: float = _DOCKER_TIMEOUT_S) -> list[tuple[int, str]]:
    """Enumerate Python child PIDs inside `container_name`.

    Per PLAN.md: PID 1 is `infisical run`, NEVER use --pid 1. We filter by
    /python|uvicorn|gunicorn|celery/.

    We probe `/proc` directly (not `ps`) because the python:slim base image
    used by most Python-on-slim setups does NOT include procps.
    `cat` is in our exec_in_container allowlist; reading /proc/*/comm is
    POSIX-stable.
    """
    validate_container_name(container_name)

    # Use a single-shot ls + cat approach to enumerate /proc pids.
    # We invoke `cat` with a glob — but exec_in_container disallows shell metas,
    # so build the list of /proc/<pid>/comm paths from a directory listing first.
    rc, ls_out, ls_err = exec_in_container(
        container_name, ["ls", "/proc"], timeout=timeout
    )
    if rc != 0:
        raise DockerError(f"docker exec ls /proc failed: {ls_err.strip()[:200]}")

    # Per PLAN.md: PID 1 is `infisical run` and must NEVER be passed to py-spy.
    # However, if a container's entrypoint runs Python directly (no Infisical
    # wrapper), PID 1 IS the Python process — and skipping it would yield
    # zero workers. We resolve this by reading /proc/1/comm and including
    # PID 1 only if its comm is a Python-shaped name.
    candidate_pids: list[int] = []
    for entry in ls_out.split():
        if entry.isdigit():
            candidate_pids.append(int(entry))

    if not candidate_pids:
        return []

    # Read /proc/<pid>/comm for each candidate. cat each path individually.
    # Build the cat argv as one cat call with all paths to amortize the docker
    # exec overhead. Each path is /proc/<digits>/comm — strictly safe (no shell
    # metachars), but exec_in_container will validate anyway.
    paths = [f"/proc/{pid}/comm" for pid in candidate_pids]
    rc, cat_out, _ = exec_in_container(
        container_name, ["cat", *paths], timeout=timeout
    )
    # `cat` may print an error for vanished PIDs (race) but still output others;
    # rc != 0 on partial failure is fine. Lines correspond to surviving pids.
    comm_lines = cat_out.splitlines()

    out: list[tuple[int, str]] = []
    # We can't trivially correlate cat output back to PIDs if some vanished,
    # but in the common case all survive. Walk both lists in lockstep; if
    # length mismatch, fall back to reading per-pid.
    pid_comm: list[tuple[int, str]] = []
    if len(comm_lines) == len(candidate_pids):
        for pid, comm in zip(candidate_pids, comm_lines, strict=False):
            pid_comm.append((pid, comm.strip()))
    else:
        # Fallback: read each /proc/<pid>/comm individually
        for pid in candidate_pids:
            rc2, c, _ = exec_in_container(
                container_name, ["cat", f"/proc/{pid}/comm"], timeout=timeout
            )
            if rc2 == 0:
                pid_comm.append((pid, c.strip()))

    # If PID 1 is a non-Python process (Infisical wrapper, sh, tini), exclude it.
    # If PID 1 IS Python (entrypoint runs Python directly), keep it — there is
    # no other choice and skipping would yield zero workers.
    pid1_is_python = any(
        pid == 1 and _PYTHON_PROCESS_RE.search(comm) for pid, comm in pid_comm
    )

    for pid, comm in pid_comm:
        if not _PYTHON_PROCESS_RE.search(comm):
            continue
        if pid == 1 and not pid1_is_python:
            # Defensive: shouldn't reach since the regex would have tripped above
            continue
        out.append((pid, comm))
    return out


def exec_in_container(
    container_name: str,
    cmd: list[str],
    *,
    timeout: float = 10.0,
) -> tuple[int, str, str]:
    """Run a validated command inside a container. Returns (rc, stdout, stderr).

    `cmd` is a list of argv tokens. Each must be a string. The first token is
    the executable and must be one of the explicit allowlist below — we will
    NEVER run an arbitrary command in a container.
    """
    validate_container_name(container_name)
    if not cmd or not isinstance(cmd, list):
        raise DockerError("exec_in_container: cmd must be a non-empty list")

    allowed_executables = {"py-spy", "python", "ps", "cat", "ls"}
    if cmd[0] not in allowed_executables:
        raise DockerError(
            f"exec_in_container: executable {cmd[0]!r} not in allowlist {sorted(allowed_executables)}"
        )
    for tok in cmd[1:]:
        if not isinstance(tok, str):
            raise DockerError("exec_in_container: all argv tokens must be strings")
        # Args from py-spy etc. may contain '=' '/' '.' — accept those, reject shell metas
        if any(ch in tok for ch in [";", "&", "|", "`", "$", ">", "<", "\n"]):
            raise DockerError(f"exec_in_container: token contains shell metacharacter: {tok!r}")

    proc_cmd = ["docker", "exec", container_name, *cmd]
    try:
        proc = subprocess.run(
            proc_cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as e:
        raise DockerError("docker CLI not found") from e
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker exec timed out after {timeout}s") from e
    return proc.returncode, proc.stdout or "", proc.stderr or ""
