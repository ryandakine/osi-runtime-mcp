"""read_metrics — scrape /metrics from an allowlisted container, parse Prometheus exposition.

We use `urllib.request` (stdlib) rather than adding an httpx dep. Networking
goes via `docker exec <c> python -c ...` since the metrics endpoint may be
container-local — but that conflicts with our subprocess-allowlist policy
(only py-spy/python/ps/cat/ls are exec-allowed, and `python -c` is broad).

Cleaner approach: use the host's published port if available; otherwise
run a controlled `python` exec that writes `urllib` calls (validated).

For v1 we restrict to host-published ports — the container must expose
its /metrics on a published port, which is the common case for prom scraping.
"""

from __future__ import annotations

import re
import socket
import time
import urllib.error
import urllib.request
from typing import Literal

from pydantic import BaseModel, Field

from .. import audit
from ..allowlist import resolve_service_for_introspection
from ..docker_client import DockerError
from ..redact import redact_blob
from ..validation import validate_identifier


class MetricsResponse(BaseModel):
    service: str
    container: str
    format: str
    metrics: dict[str, dict] = Field(default_factory=dict)
    raw_text: str | None = None
    error: str | None = None
    duration_ms: int = 0


# Prometheus exposition format parser — minimal, intentionally not feature-complete.
# Lines look like:
#     # HELP name help text
#     # TYPE name counter
#     name{label1="v1",label2="v2"} 12345 [timestamp]
#     name 99
_METRIC_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+"
    r"(?P<value>-?[\d.eE+-]+|NaN|[+-]?Inf)"
    r"(?:\s+\d+)?"  # optional timestamp
    r"\s*$"
)
_LABEL_RE = re.compile(r'(?P<k>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<v>(?:[^"\\]|\\.)*)"')


def parse_prom_exposition(text: str) -> dict[str, dict]:
    """Parse Prometheus exposition format into {metric_name: {label_str: value}}.

    Each metric_name maps to a dict keyed by a stable label-string (or '' for unlabeled).
    Value is a float, or string 'NaN'/'+Inf'/'-Inf'.
    """
    out: dict[str, dict] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _METRIC_LINE_RE.match(s)
        if not m:
            continue
        name = m.group("name")
        labels_raw = m.group("labels") or ""
        value_str = m.group("value")
        # Parse value
        value: float | str
        try:
            value = float(value_str)
        except ValueError:
            value = value_str  # NaN/Inf
        # Parse labels into a stable string key
        labels: list[tuple[str, str]] = [
            (lm.group("k"), lm.group("v")) for lm in _LABEL_RE.finditer(labels_raw)
        ]
        labels.sort()
        label_key = ",".join(f"{k}={v}" for k, v in labels)
        out.setdefault(name, {})[label_key] = value
    return out


def _extract_metrics_url(container_ports: str) -> str | None:
    """Inspect docker ps `Ports` field for an HTTP-style published port.

    Format examples:
        "0.0.0.0:8007->8000/tcp"
        "0.0.0.0:5435->5432/tcp, [::]:5435->5432/tcp"
    Returns "http://127.0.0.1:<published>/metrics" on first hit, else None.
    """
    if not container_ports:
        return None
    for chunk in container_ports.split(","):
        chunk = chunk.strip()
        m = re.match(r"(?:\[?[\d.:a-fA-F]+\]?:)?(\d+)->\d+/tcp", chunk)
        if m:
            port = int(m.group(1))
            return f"http://127.0.0.1:{port}/metrics"
    return None


def read_metrics(
    service: str,
    format: Literal["prometheus", "json"] = "json",
    project: str | None = None,
    timeout_s: float = 5.0,
) -> MetricsResponse:
    """Scrape the service's /metrics endpoint over its published port and parse it."""
    t0 = time.monotonic()
    if format not in ("prometheus", "json"):
        raise ValueError(f"format must be 'prometheus' or 'json', got {format!r}")
    validate_identifier(service, field="service")
    if project is not None:
        validate_identifier(project, field="project")

    audit_args = {"service": service, "format": format, "project": project}

    try:
        container = resolve_service_for_introspection(service, project=project)
    except (DockerError, PermissionError) as e:
        audit.log_call(tool="read_metrics", args=audit_args, error=str(e))
        raise

    url = _extract_metrics_url(container.ports)
    if url is None:
        msg = (
            f"service={service!r} has no published TCP port; "
            f"v1 read_metrics requires a host-published port. "
            f"Add a `ports:` mapping to docker-compose.yml or wait for v2."
        )
        resp = MetricsResponse(
            service=service, container=container.name, format=format, error=msg
        )
        audit.log_call(tool="read_metrics", args=audit_args, error=msg)
        return resp

    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as r:  # noqa: S310 (validated host)
            raw_bytes = r.read(2 * 1024 * 1024)  # cap at 2MB
            text = raw_bytes.decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as e:
        msg = f"failed to scrape {url}: {e}"
        resp = MetricsResponse(
            service=service, container=container.name, format=format, error=msg
        )
        audit.log_call(tool="read_metrics", args=audit_args, error=msg)
        return resp

    # Apply blob redaction in case any metric label echoes a secret
    redacted_text, redactions = redact_blob(text)

    if format == "prometheus":
        resp = MetricsResponse(
            service=service,
            container=container.name,
            format=format,
            raw_text=redacted_text,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
    else:
        metrics = parse_prom_exposition(redacted_text)
        resp = MetricsResponse(
            service=service,
            container=container.name,
            format=format,
            metrics=metrics,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    audit.log_call(
        tool="read_metrics",
        args=audit_args,
        result_size_bytes=len(resp.model_dump_json().encode("utf-8")),
        redactions_applied=redactions,
    )
    return resp
