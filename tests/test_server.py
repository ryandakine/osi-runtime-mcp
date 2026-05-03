"""Smoke test that the FastMCP server registers all 4 tools with valid schemas."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastmcp")  # only present in the project venv, not the system Python


def _gather_tools():
    from osi_runtime_mcp.server import mcp

    async def _list():
        return await mcp.list_tools()

    return asyncio.run(_list())


def test_server_registers_four_tools():
    tools = _gather_tools()
    names = {t.name for t in tools}
    assert names == {
        "list_services",
        "dump_python_stack",
        "read_metrics",
        "health_check_ptrace",
    }


def test_server_tool_schemas_present():
    tools = _gather_tools()
    for t in tools:
        # FastMCP's FunctionTool exposes parameters
        assert t.parameters is not None, f"tool {t.name} has no parameters"
        assert "properties" in t.parameters or "type" in t.parameters
