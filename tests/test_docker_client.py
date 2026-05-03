"""Tests for docker_client (mocked subprocess)."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from osi_runtime_mcp import docker_client
from osi_runtime_mcp.docker_client import (
    DockerError,
    _parse_labels,
    find_container_by_service,
    list_containers,
    list_introspectable_containers,
    list_python_pids,
)
from osi_runtime_mcp.validation import ValidationError

# Sample docker ps --format json output
SAMPLE_DOCKER_PS = "\n".join(
    [
        json.dumps(
            {
                "ID": "abc123",
                "Names": "msbpv2-backend-1",
                "Service": "backend",
                "Image": "msbpv2-backend",
                "State": "running",
                "Status": "Up 2 hours (healthy)",
                "Health": "healthy",
                "Ports": "0.0.0.0:8007->8000/tcp",
                "Labels": ",".join(
                    [
                        "com.docker.compose.project=multisportsbettingplatformv2",
                        "com.docker.compose.service=backend",
                        "osi.runtime.introspect=allow",
                        "osi.runtime.allow_locals=true",
                        "osi.runtime.language=python",
                        "osi.runtime.project=msbpv2",
                    ]
                ),
            }
        ),
        json.dumps(
            {
                "ID": "def456",
                "Names": "msbpv2-celery-worker-1",
                "Service": "celery-worker",
                "Image": "msbpv2-celery",
                "State": "running",
                "Status": "Up 1 hour",
                "Health": "",
                "Ports": "",
                "Labels": ",".join(
                    [
                        "com.docker.compose.project=multisportsbettingplatformv2",
                        "com.docker.compose.service=celery-worker",
                        "osi.runtime.introspect=allow",
                        "osi.runtime.allow_locals=true",
                        "osi.runtime.language=python",
                        "osi.runtime.project=msbpv2",
                    ]
                ),
            }
        ),
        json.dumps(
            {
                "ID": "ghi789",
                "Names": "congressional-api",
                "Service": "api",
                "Image": "congressional-api",
                "State": "running",
                "Status": "Up 5 hours",
                "Health": "healthy",
                "Ports": "0.0.0.0:8020->8000/tcp",
                "Labels": "com.docker.compose.project=sample-app,com.docker.compose.service=api",
            }
        ),
        json.dumps(
            {
                "ID": "jkl012",
                "Names": "redis",
                "Service": "redis",
                "Image": "redis:7",
                "State": "running",
                "Status": "Up",
                "Health": "",
                "Ports": "",
                "Labels": "com.docker.compose.project=multisportsbettingplatformv2,com.docker.compose.service=redis",
            }
        ),
    ]
)


@pytest.fixture
def mock_docker_ps(monkeypatch):
    """Replace _run_docker so list_containers returns SAMPLE_DOCKER_PS."""

    def fake_run(args: list[str], **_: Any) -> str:
        if args[:1] == ["ps"]:
            return SAMPLE_DOCKER_PS
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(docker_client, "_run_docker", fake_run)
    return fake_run


def test_parse_labels_basic():
    raw = "k1=v1,k2=v2,osi.runtime.introspect=allow"
    out = _parse_labels(raw)
    assert out == {"k1": "v1", "k2": "v2", "osi.runtime.introspect": "allow"}


def test_parse_labels_empty():
    assert _parse_labels("") == {}


def test_list_containers_parses_output(mock_docker_ps):
    containers = list_containers()
    assert len(containers) == 4
    backend = next(c for c in containers if c.service == "backend")
    assert backend.introspect_allowed
    assert backend.locals_allowed
    assert backend.language == "python"
    assert backend.osi_project == "msbpv2"


def test_list_introspectable_filters_by_label(mock_docker_ps):
    """Only containers with osi.runtime.introspect=allow appear."""
    out = list_introspectable_containers()
    services = sorted(c.service for c in out)
    # backend + celery-worker have the label; api + redis don't
    assert services == ["backend", "celery-worker"]


def test_list_introspectable_filters_by_project(mock_docker_ps):
    out = list_introspectable_containers(project="msbpv2")
    assert len(out) == 2
    out2 = list_introspectable_containers(project="other")
    assert len(out2) == 0


def test_list_introspectable_rejects_invalid_project():
    with pytest.raises(ValidationError):
        list_introspectable_containers(project="evil; rm -rf /")


def test_find_container_by_service(mock_docker_ps):
    c = find_container_by_service("backend")
    assert c.name == "msbpv2-backend-1"


def test_find_container_by_service_unlabeled_refused(mock_docker_ps):
    """`api` exists but has no osi.runtime.introspect label."""
    with pytest.raises(DockerError) as exc:
        find_container_by_service("api")
    assert "no introspectable container" in str(exc.value)


def test_find_container_by_service_validates(mock_docker_ps):
    with pytest.raises(ValidationError):
        find_container_by_service("backend; rm -rf /")


# ---- list_python_pids -----------------------------------------------------


def test_list_python_pids_filters_pid1_and_non_python(monkeypatch):
    """PID 1 (infisical) must be excluded; non-Python procs must be excluded.

    list_python_pids uses /proc (not `ps`, which is absent from python:slim)
    via two exec calls: `ls /proc` then `cat /proc/<pid>/comm` for candidates.
    """
    pids_in_proc = ["1", "7", "12", "13", "42", "55", "99", "self", "stat"]
    comms_for_pids = {
        "1": "infisical",
        "7": "sh",
        "12": "python",
        "13": "python",
        "42": "uvicorn",
        "55": "celery",
        "99": "not-relevant",
    }

    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd == ["ls", "/proc"]:
            return 0, " ".join(pids_in_proc) + "\n", ""
        if cmd[0] == "cat":
            # cmd is ["cat", "/proc/7/comm", "/proc/12/comm", ...]
            comms_out: list[str] = []
            for path in cmd[1:]:
                # path is "/proc/<pid>/comm"
                pid = path.split("/")[2]
                comms_out.append(comms_for_pids.get(pid, "unknown"))
            return 0, "\n".join(comms_out) + "\n", ""
        return 1, "", "unexpected"

    monkeypatch.setattr(docker_client, "exec_in_container", fake_exec)

    pids = list_python_pids("multisportsbettingplatformv2-backend-1")
    pid_set = {pid for pid, _ in pids}
    assert 1 not in pid_set, "PID 1 (infisical) must be excluded"
    assert 7 not in pid_set, "sh must be excluded"
    assert pid_set == {12, 13, 42, 55}


def test_list_python_pids_keeps_pid1_when_python(monkeypatch):
    """If PID 1 IS the Python process (no Infisical wrapper), include it.

    This matches a typical infisical-wrapped container where entrypoint.sh runs
    `exec uvicorn ...` directly when INFISICAL_TOKEN is unset.
    """

    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd == ["ls", "/proc"]:
            return 0, "1 6 7 8 9\n", ""
        if cmd[0] == "cat":
            comms_for = {"1": "uvicorn", "6": "python3.11", "7": "python3.11", "8": "python3.11", "9": "python3.11"}
            return 0, "\n".join(comms_for[p.split("/")[2]] for p in cmd[1:]) + "\n", ""
        return 1, "", "unexpected"

    monkeypatch.setattr(docker_client, "exec_in_container", fake_exec)
    pids = list_python_pids("backend-1")
    pid_set = {pid for pid, _ in pids}
    assert 1 in pid_set, "PID 1 IS python (uvicorn) — must be included"
    assert pid_set == {1, 6, 7, 8, 9}


def test_list_python_pids_validates_container_name():
    with pytest.raises(ValidationError):
        list_python_pids("evil; rm -rf /")


# ---- exec_in_container subprocess hygiene ---------------------------------


def test_exec_in_container_rejects_unallowed_executable():
    from osi_runtime_mcp.docker_client import exec_in_container

    with pytest.raises(DockerError) as exc:
        exec_in_container("backend-1", ["bash", "-c", "ls"])
    assert "not in allowlist" in str(exc.value)


def test_exec_in_container_rejects_shell_metacharacter():
    from osi_runtime_mcp.docker_client import exec_in_container

    with pytest.raises(DockerError) as exc:
        exec_in_container("backend-1", ["py-spy", "dump", "--pid", "$(rm -rf /)"])
    assert "metacharacter" in str(exc.value)


def test_exec_in_container_validates_container_name():
    from osi_runtime_mcp.docker_client import exec_in_container

    with pytest.raises(ValidationError):
        exec_in_container("evil; rm -rf /", ["py-spy", "--version"])


# ---- _run_docker error paths ----------------------------------------------


def test_run_docker_handles_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1.0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DockerError) as exc:
        docker_client._run_docker(["ps"])
    assert "timed out" in str(exc.value)


def test_run_docker_handles_missing_binary(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DockerError) as exc:
        docker_client._run_docker(["ps"])
    assert "not found" in str(exc.value)
