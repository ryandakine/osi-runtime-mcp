"""Tests for the list_services tool."""

from __future__ import annotations

import pytest

from osi_runtime_mcp import docker_client
from osi_runtime_mcp.tools.list_services import list_services
from osi_runtime_mcp.validation import ValidationError
from tests.test_docker_client import SAMPLE_DOCKER_PS


@pytest.fixture
def mock_docker_ps(monkeypatch):
    monkeypatch.setattr(docker_client, "_run_docker", lambda args, **_: SAMPLE_DOCKER_PS)


def test_list_services_returns_only_labeled(mock_docker_ps):
    resp = list_services()
    services = sorted(s.service for s in resp.services)
    assert services == ["backend", "celery-worker"]


def test_list_services_filters_by_project(mock_docker_ps):
    resp = list_services(project="msbpv2")
    assert len(resp.services) == 2
    resp2 = list_services(project="other")
    assert len(resp2.services) == 0


def test_list_services_validates_project():
    with pytest.raises(ValidationError):
        list_services(project="evil; rm -rf /")


def test_list_services_carries_labels(mock_docker_ps):
    resp = list_services()
    backend = next(s for s in resp.services if s.service == "backend")
    assert backend.language == "python"
    assert backend.locals_allowed is True
    assert backend.osi_project == "msbpv2"
