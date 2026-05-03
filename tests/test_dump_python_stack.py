"""Tests for dump_python_stack — mostly mocked subprocess.

Real py-spy invocation is exercised in the live acceptance test (see
docs/acceptance.md or run scripts/live_acceptance.py).
"""

from __future__ import annotations

import json

import pytest

from osi_runtime_mcp import docker_client
from osi_runtime_mcp.allowlist import AllowlistError
from osi_runtime_mcp.tools.dump_python_stack import (
    RESPONSE_BUDGET_BYTES,
    _select_pids,
    dump_python_stack,
)
from osi_runtime_mcp.validation import ValidationError
from tests.test_docker_client import SAMPLE_DOCKER_PS

# Sample py-spy --json output (from a real local capture, see PLAN.md prereq #4)
SAMPLE_PY_SPY_JSON = json.dumps(
    [
        {
            "pid": 12,
            "thread_id": 140000000000000,
            "thread_name": None,
            "os_thread_id": 12,
            "active": True,
            "owns_gil": True,
            "frames": [
                {
                    "name": "handler",
                    "filename": "/app/v2/api/routes/predictions.py",
                    "module": None,
                    "short_filename": "predictions.py",
                    "line": 42,
                    "locals": [
                        {"name": "request", "addr": 1, "arg": True,
                         "repr": "<starlette.requests.Request object at 0x7f1234>"},
                        {"name": "user_id", "addr": 2, "arg": False,
                         "repr": '"user_42"'},
                        {"name": "DATABASE_URL", "addr": 3, "arg": False,
                         "repr": '"postgresql://user:hunter2@db/app"'},
                    ],
                },
                {
                    "name": "<module>",
                    "filename": "<string>",
                    "module": None,
                    "short_filename": "<string>",
                    "line": 1,
                    "locals": [],
                },
            ],
            "process_info": None,
        }
    ]
)


@pytest.fixture
def fake_docker(monkeypatch):
    """Mock docker calls: list_containers / list_python_pids via exec_in_container."""

    def fake_run(args, **kwargs):
        if args[:1] == ["ps"]:
            return SAMPLE_DOCKER_PS
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(docker_client, "_run_docker", fake_run)

    # Mock the /proc-based PID enumeration
    pids_in_proc = ["1", "12", "13"]
    comms = {"1": "infisical", "12": "python", "13": "python"}

    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd == ["ls", "/proc"]:
            return 0, " ".join(pids_in_proc) + "\n", ""
        if cmd[0] == "cat":
            comms_out = [comms.get(p.split("/")[2], "unknown") for p in cmd[1:]]
            return 0, "\n".join(comms_out) + "\n", ""
        return 1, "", "unhandled"

    monkeypatch.setattr(docker_client, "exec_in_container", fake_exec)
    return fake_run


@pytest.fixture
def fake_pyspy(monkeypatch):
    """Mock exec_in_container for py-spy + /proc enumeration."""
    calls: list[list[str]] = []
    pids_in_proc = ["1", "12", "13"]
    comms = {"1": "infisical", "12": "python", "13": "python"}

    def fake_exec(container_name, cmd, *, timeout=10.0):
        calls.append(cmd)
        if cmd == ["ls", "/proc"]:
            return 0, " ".join(pids_in_proc) + "\n", ""
        if cmd[0] == "cat":
            return 0, "\n".join(comms.get(p.split("/")[2], "x") for p in cmd[1:]) + "\n", ""
        if cmd[0] == "py-spy" and cmd[1] == "dump":
            return 0, SAMPLE_PY_SPY_JSON, ""
        if cmd[0] == "py-spy" and cmd[1] == "--version":
            return 0, "py-spy 0.3.14\n", ""
        return 1, "", "unexpected"

    monkeypatch.setattr(
        "osi_runtime_mcp.tools.dump_python_stack.exec_in_container",
        fake_exec,
    )
    monkeypatch.setattr(
        "osi_runtime_mcp.docker_client.exec_in_container",
        fake_exec,
    )
    return calls


def test_dump_validates_service():
    with pytest.raises(ValidationError):
        dump_python_stack(service="evil; rm -rf /")


def test_dump_refuses_unlabeled_service(fake_docker):
    """`api` (congressional) has no osi.runtime.introspect label.

    The container lookup raises DockerError because `find_container_by_service`
    only walks the introspectable list — same outcome (refused), different
    exception type.
    """
    from osi_runtime_mcp.docker_client import DockerError

    with pytest.raises((AllowlistError, DockerError)) as exc:
        dump_python_stack(service="api")
    assert "introspectable" in str(exc.value) or "introspect=allow" in str(exc.value)


def test_dump_refuses_locals_without_label(fake_docker, fake_pyspy, monkeypatch):
    """Container without osi.runtime.allow_locals=true must refuse with_locals."""
    # Synthesize a labeled-but-not-locals container
    payload = json.dumps(
        {
            "ID": "x",
            "Names": "x-svc-1",
            "Service": "limited",
            "Image": "x",
            "State": "running",
            "Status": "Up",
            "Health": "",
            "Ports": "",
            "Labels": "osi.runtime.introspect=allow,com.docker.compose.service=limited,com.docker.compose.project=x",
        }
    )
    monkeypatch.setattr(docker_client, "_run_docker", lambda a, **k: payload)
    with pytest.raises(AllowlistError):
        dump_python_stack(service="limited", with_locals=True)


def test_dump_default_workers_first(fake_docker, fake_pyspy):
    resp = dump_python_stack(service="backend")
    assert len(resp.workers) == 1
    assert resp.workers[0].pid == 12


def test_dump_workers_all_returns_all(fake_docker, fake_pyspy):
    resp = dump_python_stack(service="backend", workers="all")
    assert len(resp.workers) == 2  # PIDs 12, 13


def test_dump_with_locals_redacts_request(fake_docker, fake_pyspy):
    resp = dump_python_stack(service="backend", with_locals=True)
    frame = resp.workers[0].threads[0].frames[0]
    assert frame.locals is not None
    by_name = {l.name: l for l in frame.locals}
    # request -> type-aware redacted
    assert by_name["request"].redacted
    assert "Request" not in by_name["request"].repr or "redacted" in by_name["request"].repr
    # DATABASE_URL -> name-allowlist redacted, hunter2 must NOT appear
    assert by_name["DATABASE_URL"].redacted
    assert "hunter2" not in by_name["DATABASE_URL"].repr
    # user_id -> NOT redacted
    assert not by_name["user_id"].redacted
    assert resp.redactions_applied >= 2


def test_dump_without_locals_omits_locals_field(fake_docker, fake_pyspy):
    resp = dump_python_stack(service="backend", with_locals=False)
    frame = resp.workers[0].threads[0].frames[0]
    assert frame.locals is None


def test_dump_records_audit(fake_docker, fake_pyspy, audit_dir):
    dump_python_stack(service="backend", with_locals=True)
    files = list(audit_dir.glob("audit-*.jsonl"))
    assert files
    lines = files[0].read_text().splitlines()
    rec = json.loads(lines[-1])
    assert rec["tool"] == "dump_python_stack"
    assert "redactions_applied" in rec
    assert rec["unsafe_locals"] is False


def test_select_pids_first():
    pids = [(12, "python"), (13, "python"), (14, "celery")]
    assert _select_pids(pids, "first") == [(12, "python")]


def test_select_pids_all():
    pids = [(12, "python"), (13, "python")]
    assert _select_pids(pids, "all") == pids


def test_select_pids_int():
    pids = [(12, "python"), (13, "python"), (14, "celery"), (15, "celery")]
    assert _select_pids(pids, 2) == pids[:2]


def test_dump_byte_budget(monkeypatch):
    """If a worker's dump pushes us over 256KB, we drop the trailing worker."""
    # Build a huge fake py-spy output
    locals_ = [
        {"name": f"var_{i}", "arg": False, "repr": '"' + "x" * 1000 + '"', "addr": i}
        for i in range(100)
    ]
    big_thread = {
        "pid": 1,
        "thread_id": 0,
        "thread_name": None,
        "os_thread_id": 0,
        "active": False,
        "owns_gil": False,
        "frames": [
            {
                "name": "f",
                "filename": "x.py",
                "short_filename": "x.py",
                "line": 1,
                "locals": locals_,
            }
        ],
        "process_info": None,
    }
    big_dump = json.dumps([big_thread])

    def fake_run(args, **k):
        if args[:1] == ["ps"]:
            return SAMPLE_DOCKER_PS

    monkeypatch.setattr(docker_client, "_run_docker", fake_run)

    pids_in_proc = ["1", "12", "13", "14", "15"]
    comms = {"1": "infisical", "12": "python", "13": "python", "14": "python", "15": "python"}

    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd == ["ls", "/proc"]:
            return 0, " ".join(pids_in_proc) + "\n", ""
        if cmd[0] == "cat":
            return 0, "\n".join(comms.get(p.split("/")[2], "x") for p in cmd[1:]) + "\n", ""
        if cmd[0] == "py-spy" and cmd[1] == "dump":
            return 0, big_dump, ""
        return 0, "", ""

    monkeypatch.setattr(
        "osi_runtime_mcp.tools.dump_python_stack.exec_in_container", fake_exec
    )
    monkeypatch.setattr(docker_client, "exec_in_container", fake_exec)

    resp = dump_python_stack(service="backend", workers="all", with_locals=True)
    size = len(resp.model_dump_json().encode("utf-8"))
    assert size <= RESPONSE_BUDGET_BYTES
    if len(resp.workers) < 4:
        assert resp.truncated
        assert resp.dropped_workers


def test_dump_handles_pyspy_failure(fake_docker, monkeypatch):
    """If py-spy returns nonzero, worker dump records error, no exception raised."""

    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd[0] == "py-spy" and cmd[1] == "dump":
            return 1, "", "Operation not permitted (ptrace)"
        return 0, "", ""

    monkeypatch.setattr(
        "osi_runtime_mcp.tools.dump_python_stack.exec_in_container", fake_exec
    )
    resp = dump_python_stack(service="backend")
    assert len(resp.workers) == 1
    assert resp.workers[0].error is not None
    assert "Operation not permitted" in resp.workers[0].error


def test_dump_handles_invalid_json(fake_docker, monkeypatch):
    def fake_exec(container_name, cmd, *, timeout=10.0):
        if cmd[0] == "py-spy" and cmd[1] == "dump":
            return 0, "not json at all", ""
        return 0, "", ""

    monkeypatch.setattr(
        "osi_runtime_mcp.tools.dump_python_stack.exec_in_container", fake_exec
    )
    resp = dump_python_stack(service="backend")
    assert resp.workers[0].error is not None
