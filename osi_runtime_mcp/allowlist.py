"""Label-driven allowlist for runtime introspection.

Per PLAN.md security model:
    Discovery: Allowlist via Docker label `osi.runtime.introspect=allow`. No label = invisible.
    Authz: Per-tool ACL: `dump_python_stack` requires the container's compose label
    `osi.runtime.introspect=allow` AND label `osi.runtime.allow_locals=true`
    if `with_locals=True`.

The allowlist is NOT cached — per Claude/eng-review finding M3, the 5s cache had
a TOCTOU window. We just re-query `docker ps` every call (~50ms).
"""

from __future__ import annotations

from .docker_client import ContainerInfo, find_container_by_service


class AllowlistError(PermissionError):
    """Raised when a tool call is refused by the allowlist."""


def resolve_service_for_introspection(
    service: str,
    *,
    project: str | None = None,
) -> ContainerInfo:
    """Resolve a service name to its container, refusing if not allowlisted."""
    container = find_container_by_service(service, project=project)
    if not container.introspect_allowed:
        raise AllowlistError(
            f"service={service!r} container={container.name!r} is not labeled "
            f"osi.runtime.introspect=allow; refusing introspection"
        )
    return container


def assert_locals_allowed(container: ContainerInfo) -> None:
    """Refuse `with_locals=True` unless the container opts in via label."""
    if not container.locals_allowed:
        raise AllowlistError(
            f"service={container.service!r} container={container.name!r} does NOT "
            f"have label osi.runtime.allow_locals=true; refusing with_locals=True. "
            f"Set the label to opt in, or call without with_locals."
        )
