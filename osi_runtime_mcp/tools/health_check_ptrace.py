"""health_check_ptrace — verify py-spy can actually attach inside a target container.

Per PLAN.md prereqs:
    Add a `health_check_ptrace(service)` MCP tool that runs the verification
    on demand and returns `{ptrace_ok, child_pid_found, py_spy_version}`.
"""

from __future__ import annotations

from pydantic import BaseModel

from .. import audit
from ..allowlist import resolve_service_for_introspection
from ..docker_client import DockerError, exec_in_container, list_python_pids
from ..validation import validate_identifier


class PtraceHealth(BaseModel):
    service: str
    container: str
    ptrace_ok: bool
    child_pid_found: int | None = None
    child_comm: str | None = None
    py_spy_version: str | None = None
    py_spy_available: bool = False
    error: str | None = None
    hint: str | None = None


def _ps_grep_python(container_name: str) -> tuple[int, str] | None:
    pids = list_python_pids(container_name)
    return pids[0] if pids else None


def health_check_ptrace(service: str, project: str | None = None) -> PtraceHealth:
    validate_identifier(service, field="service")
    if project is not None:
        validate_identifier(project, field="project")

    audit_args = {"service": service, "project": project}

    try:
        container = resolve_service_for_introspection(service, project=project)
    except (DockerError, PermissionError) as e:
        audit.log_call(tool="health_check_ptrace", args=audit_args, error=str(e))
        raise

    out = PtraceHealth(service=service, container=container.name, ptrace_ok=False)

    # Probe 1: py-spy version
    try:
        rc, stdout, stderr = exec_in_container(
            container.name, ["py-spy", "--version"], timeout=5.0
        )
        if rc == 0 and stdout:
            out.py_spy_available = True
            out.py_spy_version = stdout.strip().split("\n")[0]
        else:
            out.py_spy_available = False
            out.error = (
                f"py-spy not invokable: rc={rc} stderr={stderr.strip()[:200]}"
            )
            out.hint = "Add `RUN pip install 'py-spy>=0.3.14,<0.4'` to the base Dockerfile stage."
            audit.log_call(tool="health_check_ptrace", args=audit_args, extra=out.model_dump())
            return out
    except DockerError as e:
        out.error = f"docker exec failed: {e}"
        out.hint = "Is the container running?"
        audit.log_call(tool="health_check_ptrace", args=audit_args, error=str(e))
        return out

    # Probe 2: child PID
    pid_comm = _ps_grep_python(container.name)
    if pid_comm is None:
        out.error = "no python child PIDs found"
        out.hint = (
            "Container has no /python|uvicorn|gunicorn|celery/ child process. "
            "Check the entrypoint."
        )
        audit.log_call(tool="health_check_ptrace", args=audit_args, extra=out.model_dump())
        return out
    pid, comm = pid_comm
    out.child_pid_found = pid
    out.child_comm = comm

    # Probe 3: actually attempt a py-spy dump (non-locals, very small)
    try:
        rc, stdout, stderr = exec_in_container(
            container.name,
            ["py-spy", "dump", "--pid", str(pid), "--json"],
            timeout=8.0,
        )
    except DockerError as e:
        out.error = f"py-spy dump exec error: {e}"
        out.hint = "Check that the container has cap_add: [SYS_PTRACE]."
        audit.log_call(tool="health_check_ptrace", args=audit_args, error=str(e))
        return out

    if rc == 0:
        out.ptrace_ok = True
    else:
        out.ptrace_ok = False
        out.error = (
            f"py-spy dump failed: rc={rc} stderr={stderr.strip()[:300]}"
        )
        if "Operation not permitted" in stderr or "ptrace" in stderr.lower():
            out.hint = (
                "ptrace_scope=1 may be blocking py-spy. Add `cap_add: [SYS_PTRACE]` "
                "to the service in docker-compose.yml, recreate the container."
            )
        elif "Unsupported version of Python" in stderr:
            out.hint = (
                "py-spy 0.3.x doesn't support Python 3.12+. Use Python 3.11 image "
                "or upgrade py-spy when 0.4.x ships."
            )

    audit.log_call(tool="health_check_ptrace", args=audit_args, extra=out.model_dump())
    return out
