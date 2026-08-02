"""Public schema contracts for the MCP SDK v2 boundary."""

import pytest
from fastmcp import Client, FastMCP


@pytest.mark.anyio
@pytest.mark.fastmcp4_compat
@pytest.mark.fastmcp4_protocol
async def test_sdk_v2_schema_is_snake_case_and_wire_alias_is_camel_case() -> None:
    """Confirm Python and serialized MCP schema names on the public path."""
    server = FastMCP("fastmcp4-schema")

    @server.tool
    def lookup(key: str, limit: int = 10) -> str:
        """Return a deterministic schema probe value."""
        return f"{key}:{limit}"

    async with Client(server) as client:
        [tool] = await client.list_tools()

    assert tool.input_schema["type"] == "object"
    assert tool.input_schema["properties"]["limit"]["type"] == "integer"
    assert tool.model_dump(by_alias=True)["inputSchema"] == tool.input_schema
