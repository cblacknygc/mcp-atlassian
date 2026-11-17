"""Dependency provenance contracts for FastMCP 4 readiness targets."""

import os
from importlib import metadata

import pytest
from packaging.version import Version


def _version(distribution: str) -> Version:
    """Return a parsed installed distribution version."""
    return Version(metadata.version(distribution))


@pytest.mark.fastmcp4_smoke
def test_fastmcp4_dependency_family_is_coherent() -> None:
    """Verify the selected published readiness target is internally coherent."""
    assert _version("fastmcp") == _version("fastmcp-slim")
    if os.getenv("FASTMCP4_TARGET", "published") == "published":
        assert _version("fastmcp") == Version("4.2.0")
        assert _version("mcp") == Version("2.3.0")
        assert _version("mcp-types") == Version("2.3.0")
    else:
        assert _version("mcp").major == 2
        assert _version("mcp-types").major == 2
    assert _version("pydantic") >= Version("2.12.0")
    assert _version("starlette") >= Version("1.0.1")
