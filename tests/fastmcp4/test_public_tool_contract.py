"""Compatibility-only public FastMCP tool contracts."""

import pytest
from fastmcp import Client, FastMCP


@pytest.mark.anyio
@pytest.mark.fastmcp4_compat
async def test_mounted_tool_lists_and_calls_through_public_client() -> None:
    """Exercise real mounting, schema conversion, dispatch, and result decoding."""
    child = FastMCP("fastmcp4-child")

    @child.tool
    def echo(value: str) -> str:
        """Return the supplied compatibility probe value."""
        return value

    parent = FastMCP("fastmcp4-parent")
    parent.mount(child, namespace="probe")

    async with Client(parent) as client:
        tools = await client.list_tools()
        assert [tool.name for tool in tools] == ["probe_echo"]

        result = await client.call_tool("probe_echo", {"value": "ready"})
        assert result.data == "ready"
