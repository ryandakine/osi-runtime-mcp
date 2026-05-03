"""list_services — discover containers labeled for runtime introspection."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .. import audit
from ..docker_client import DockerError, list_introspectable_containers
from ..validation import validate_identifier


class ServiceInfo(BaseModel):
    container_name: str
    project: str
    service: str
    image: str
    state: str
    status: str
    health: str | None = None
    exposed_ports: str | None = None
    language: str = "other"
    osi_project: str | None = None
    locals_allowed: bool = False


class ListServicesResponse(BaseModel):
    services: list[ServiceInfo] = Field(default_factory=list)
    error: str | None = None


def list_services(project: str | None = None) -> ListServicesResponse:
    """List Docker services available for runtime inspection.

    Filters `docker ps --format json` by the `osi.runtime.introspect=allow` label.
    If `project` is provided, additionally filters by `osi.runtime.project` label
    or compose project name.
    """
    if project is not None:
        validate_identifier(project, field="project")

    args = {"project": project}
    try:
        containers = list_introspectable_containers(project=project)
    except DockerError as e:
        audit.log_call(tool="list_services", args=args, error=f"DockerError: {e}")
        return ListServicesResponse(services=[], error=str(e))

    services = [
        ServiceInfo(
            container_name=c.name,
            project=c.project,
            service=c.service,
            image=c.image,
            state=c.state,
            status=c.status,
            health=c.health or None,
            exposed_ports=c.ports or None,
            language=c.language,
            osi_project=c.osi_project,
            locals_allowed=c.locals_allowed,
        )
        for c in containers
    ]
    resp = ListServicesResponse(services=services)
    audit.log_call(
        tool="list_services",
        args=args,
        result_size_bytes=len(resp.model_dump_json().encode("utf-8")),
        extra={"count": len(services)},
    )
    return resp
