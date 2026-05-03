"""dump_python_stack — capture live frames from a running Python container.

Pipeline:
    1. Validate `service` (^[a-z0-9_-]+$).
    2. Resolve via allowlist; refuse unlabeled containers.
    3. Enumerate child Python PIDs with `docker exec ... ps`.
    4. Choose worker(s) per `workers="first"|"all"|N`.
    5. Run `py-spy dump --pid <pid> --json [--locals]` per worker.
    6. Parse JSON; apply 4-stage redaction to every local repr.
    7. Truncate to 256KB; record dropped workers.
    8. Audit-log.
"""

from __future__ import annotations

import json
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from .. import audit
from ..allowlist import (
    AllowlistError,
    assert_locals_allowed,
    resolve_service_for_introspection,
)
from ..docker_client import (
    ContainerInfo,
    DockerError,
    exec_in_container,
    list_python_pids,
)
from ..redact import (
    RedactionResult,
    redact_blob,
    redact_local,
)
from ..validation import (
    ValidationError,
    validate_identifier,
    validate_workers_selector,
)

# Hard byte budget for the whole response, per PLAN.md.
RESPONSE_BUDGET_BYTES = 256 * 1024

# Per-worker py-spy timeout. Kept short — non-blocking dump should be sub-second.
PY_SPY_TIMEOUT_S = 8.0

# Top-level call timeout.
TOOL_TIMEOUT_S = 10.0

# Caps for what we keep per worker
MAX_FRAMES_PER_THREAD = 50
MAX_THREADS_PER_WORKER = 16


# ---- output models --------------------------------------------------------


class FrameLocal(BaseModel):
    name: str
    repr: str
    redacted: bool = False
    redaction_stages: list[str] = Field(default_factory=list)


class Frame(BaseModel):
    name: str
    filename: str
    line: int
    locals: list[FrameLocal] | None = None


class Thread(BaseModel):
    thread_id: int
    thread_name: str | None
    os_thread_id: int | None
    active: bool
    owns_gil: bool
    frames: list[Frame]


class WorkerDump(BaseModel):
    pid: int
    comm: str
    threads: list[Thread]
    error: str | None = None


class PythonDumpResponse(BaseModel):
    service: str
    container: str
    workers: list[WorkerDump]
    truncated: bool = False
    dropped_workers: list[int] = Field(default_factory=list)
    redactions_applied: int = 0
    duration_ms: int = 0


# ---- helpers --------------------------------------------------------------


def _select_pids(
    pids: list[tuple[int, str]],
    workers: str | int,
) -> list[tuple[int, str]]:
    """Apply the workers selector to the discovered PID list."""
    if not pids:
        return []
    if workers == "first":
        return pids[:1]
    if workers == "all":
        return pids
    # int
    n = int(workers)
    return pids[:n]


def _run_py_spy(
    container_name: str,
    pid: int,
    *,
    with_locals: bool,
) -> tuple[int, str, str]:
    """Invoke `py-spy dump` inside the container. Returns (rc, stdout, stderr)."""
    cmd = ["py-spy", "dump", "--pid", str(pid), "--json"]
    if with_locals:
        cmd.append("--locals")
    return exec_in_container(container_name, cmd, timeout=PY_SPY_TIMEOUT_S)


def _redact_frame_locals(
    raw_locals: list[dict[str, Any]] | None,
) -> tuple[list[FrameLocal] | None, int]:
    """Apply redaction to a list of py-spy locals; return (locals, redaction_count)."""
    if raw_locals is None:
        return None, 0
    redaction_count = 0
    out: list[FrameLocal] = []
    for loc in raw_locals:
        name = loc.get("name", "")
        repr_ = loc.get("repr", "")
        result: RedactionResult = redact_local(name, repr_)
        if result.was_redacted:
            redaction_count += 1
            out.append(
                FrameLocal(
                    name=name,
                    repr=result.redacted_value,
                    redacted=True,
                    redaction_stages=result.triggered_stages,
                )
            )
        else:
            out.append(FrameLocal(name=name, repr=repr_, redacted=False))
    return out, redaction_count


def _parse_py_spy_json(
    stdout: str,
    *,
    with_locals: bool,
) -> tuple[list[Thread], int]:
    """Parse py-spy JSON output into our Thread model. Returns (threads, redaction_count)."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise DockerError(f"py-spy returned non-JSON output: {e}") from e

    if not isinstance(data, list):
        raise DockerError(f"py-spy JSON output is not a list: type={type(data).__name__}")

    threads: list[Thread] = []
    total_redactions = 0
    for thread_obj in data[:MAX_THREADS_PER_WORKER]:
        if not isinstance(thread_obj, dict):
            continue
        frames_raw = thread_obj.get("frames", [])[:MAX_FRAMES_PER_THREAD]
        frames: list[Frame] = []
        for fr in frames_raw:
            if not isinstance(fr, dict):
                continue
            locals_raw = fr.get("locals") if with_locals else None
            redacted_locals, n = _redact_frame_locals(locals_raw)
            total_redactions += n
            # Even if locals are off, scrub the frame text fields with regex pass
            fname = fr.get("name", "")
            filename = fr.get("short_filename") or fr.get("filename", "")
            fname_red, n1 = redact_blob(fname)
            filename_red, n2 = redact_blob(filename)
            total_redactions += n1 + n2
            frames.append(
                Frame(
                    name=fname_red,
                    filename=filename_red,
                    line=int(fr.get("line", 0) or 0),
                    locals=redacted_locals,
                )
            )
        threads.append(
            Thread(
                thread_id=int(thread_obj.get("thread_id", 0) or 0),
                thread_name=thread_obj.get("thread_name"),
                os_thread_id=thread_obj.get("os_thread_id"),
                active=bool(thread_obj.get("active", False)),
                owns_gil=bool(thread_obj.get("owns_gil", False)),
                frames=frames,
            )
        )
    return threads, total_redactions


def _truncate_to_budget(resp: PythonDumpResponse) -> PythonDumpResponse:
    """If the JSON-serialized response exceeds 256KB, drop trailing workers."""
    while resp.workers:
        size = len(resp.model_dump_json().encode("utf-8"))
        if size <= RESPONSE_BUDGET_BYTES:
            break
        dropped = resp.workers.pop()
        resp.dropped_workers.append(dropped.pid)
        resp.truncated = True
    return resp


# ---- public entry point ---------------------------------------------------


def dump_python_stack(
    service: str,
    workers: Literal["first", "all"] | int = "first",
    with_locals: bool = False,
    unsafe_locals: bool = False,
    project: str | None = None,
) -> PythonDumpResponse:
    """Capture a live thread/frame snapshot of a running Python container.

    See module docstring for pipeline detail.
    """
    t0 = time.monotonic()

    # Stage 1: validation
    validate_identifier(service, field="service")
    if project is not None:
        validate_identifier(project, field="project")
    workers_sel = validate_workers_selector(workers)

    audit_args: dict[str, Any] = {
        "service": service,
        "workers": workers,
        "with_locals": with_locals,
        "unsafe_locals": unsafe_locals,
        "project": project,
    }

    # Stage 2: allowlist resolution
    container: ContainerInfo
    try:
        container = resolve_service_for_introspection(service, project=project)
    except AllowlistError as e:
        audit.log_call(
            tool="dump_python_stack",
            args=audit_args,
            error=f"AllowlistError: {e}",
        )
        raise
    except DockerError as e:
        # Container not found / not introspectable — log + re-raise
        audit.log_call(
            tool="dump_python_stack",
            args=audit_args,
            error=f"DockerError: {e}",
        )
        raise

    if with_locals:
        try:
            assert_locals_allowed(container)
        except AllowlistError as e:
            audit.log_call(
                tool="dump_python_stack",
                args=audit_args,
                error=f"AllowlistError(locals): {e}",
            )
            raise

    # Stage 3: enumerate child Python PIDs
    try:
        pids = list_python_pids(container.name)
    except DockerError as e:
        audit.log_call(
            tool="dump_python_stack",
            args=audit_args,
            error=f"DockerError(list_pids): {e}",
        )
        raise

    if not pids:
        resp = PythonDumpResponse(
            service=service,
            container=container.name,
            workers=[],
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
        audit.log_call(
            tool="dump_python_stack",
            args=audit_args,
            result_size_bytes=len(resp.model_dump_json().encode("utf-8")),
            redactions_applied=0,
            unsafe_locals=unsafe_locals,
            extra={"warning": "no_python_pids_found"},
        )
        return resp

    selected = _select_pids(pids, workers_sel)

    # Stage 5: run py-spy per worker (with overall budget)
    worker_dumps: list[WorkerDump] = []
    total_redactions = 0
    for pid, comm in selected:
        if time.monotonic() - t0 > TOOL_TIMEOUT_S:
            # Budget exhausted; record as dropped
            worker_dumps.append(
                WorkerDump(pid=pid, comm=comm, threads=[], error="tool_timeout_exceeded")
            )
            continue
        try:
            rc, stdout, stderr = _run_py_spy(container.name, pid, with_locals=with_locals)
        except DockerError as e:
            worker_dumps.append(WorkerDump(pid=pid, comm=comm, threads=[], error=str(e)))
            continue
        if rc != 0:
            worker_dumps.append(
                WorkerDump(
                    pid=pid,
                    comm=comm,
                    threads=[],
                    error=f"py-spy rc={rc} stderr={stderr.strip()[:300]}",
                )
            )
            continue
        try:
            threads, n_red = _parse_py_spy_json(stdout, with_locals=with_locals)
        except DockerError as e:
            worker_dumps.append(WorkerDump(pid=pid, comm=comm, threads=[], error=str(e)))
            continue
        total_redactions += n_red
        worker_dumps.append(WorkerDump(pid=pid, comm=comm, threads=threads))

    resp = PythonDumpResponse(
        service=service,
        container=container.name,
        workers=worker_dumps,
        redactions_applied=total_redactions,
        duration_ms=int((time.monotonic() - t0) * 1000),
    )

    # Stage 7: byte budget
    resp = _truncate_to_budget(resp)

    # Stage 8: audit
    audit.log_call(
        tool="dump_python_stack",
        args=audit_args,
        result_size_bytes=len(resp.model_dump_json().encode("utf-8")),
        redactions_applied=resp.redactions_applied,
        unsafe_locals=unsafe_locals,
        extra={
            "workers_returned": len(resp.workers),
            "truncated": resp.truncated,
            "dropped_workers": resp.dropped_workers,
        },
    )

    return resp


# Re-export for the smoke test exception
__all__ = ["dump_python_stack", "PythonDumpResponse", "ValidationError", "AllowlistError"]
