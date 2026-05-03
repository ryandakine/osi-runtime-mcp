"""FastMCP server entry point. Registers four tools and runs stdio transport.

To run: `uv run osi-runtime-mcp`
"""

from __future__ import annotations

import sys
from typing import Literal

from fastmcp import FastMCP

from .tools.dump_python_stack import (
    PythonDumpResponse,
    dump_python_stack as _dump_python_stack,
)
from .tools.health_check_ptrace import PtraceHealth, health_check_ptrace as _health_check_ptrace
from .tools.list_services import ListServicesResponse, list_services as _list_services
from .tools.read_metrics import MetricsResponse, read_metrics as _read_metrics

mcp: FastMCP = FastMCP(
    name="osi-runtime-mcp",
    instructions=(
        "Live, read-only runtime introspection for Docker'd Python services. "
        "Tools: list_services, dump_python_stack, read_metrics, health_check_ptrace. "
        "All access gated by Docker label `osi.runtime.introspect=allow`. "
        "Locals require additional `osi.runtime.allow_locals=true` label. "
        "Every call audited to /var/log/osi-runtime-mcp/."
    ),
)


@mcp.tool
def list_services(project: str | None = None) -> ListServicesResponse:
    """List Docker services available for runtime inspection.

    Reads `docker ps --format json`, filters by the `osi.runtime.introspect=allow`
    label. Optionally filters by `osi.runtime.project=<project>` if `project` is
    provided. Returns container_name, project, service, image, status, language,
    locals_allowed.

    Args:
        project: optional ^[a-z0-9_-]+$ project filter (matches osi.runtime.project label).
    """
    return _list_services(project=project)


@mcp.tool
def dump_python_stack(
    service: str,
    workers: Literal["first", "all"] | int = "first",
    with_locals: bool = False,
    unsafe_locals: bool = False,
    project: str | None = None,
) -> PythonDumpResponse:
    """Capture a live thread/frame snapshot of a running Python container.

    Resolves `service` against the allowlist, enumerates child Python PIDs
    (PID 1 is `infisical run` and is skipped), runs `py-spy dump --json [--locals]`
    against each, applies a 4-stage redaction pipeline, and returns a structured
    dump bounded to 256KB. Read-only, non-stopping. 10s timeout.

    Args:
        service: docker compose service name (^[a-z0-9_-]+$).
        workers: 'first' (default, one worker) | 'all' | positive int <= 64.
        with_locals: include local variables. Requires container label
            osi.runtime.allow_locals=true.
        unsafe_locals: bypass type-aware redaction guard (NOT recommended).
        project: optional project filter for disambiguation.
    """
    return _dump_python_stack(
        service=service,
        workers=workers,
        with_locals=with_locals,
        unsafe_locals=unsafe_locals,
        project=project,
    )


@mcp.tool
def read_metrics(
    service: str,
    format: Literal["prometheus", "json"] = "json",
    project: str | None = None,
) -> MetricsResponse:
    """Scrape the service's /metrics endpoint and parse Prometheus exposition format.

    v1 requires the service to publish a TCP port to the host. Auth-protected
    endpoints return a clear error.

    Args:
        service: docker compose service name (^[a-z0-9_-]+$).
        format: 'json' (default, parsed dict) | 'prometheus' (raw redacted text).
        project: optional project filter.
    """
    return _read_metrics(service=service, format=format, project=project)


@mcp.tool
def health_check_ptrace(service: str, project: str | None = None) -> PtraceHealth:
    """Verify py-spy can attach inside the target container.

    Probes:
        1. `py-spy --version` available.
        2. A child Python PID exists.
        3. `py-spy dump` succeeds against that PID.

    Returns ptrace_ok=True only on full success; otherwise an actionable hint.
    Run this BEFORE invoking dump_python_stack on a new container.

    Args:
        service: docker compose service name (^[a-z0-9_-]+$).
        project: optional project filter.
    """
    return _health_check_ptrace(service=service, project=project)


def main() -> None:
    """Entry point for `osi-runtime-mcp` script."""
    # FastMCP defaults to stdio transport
    try:
        mcp.run()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
