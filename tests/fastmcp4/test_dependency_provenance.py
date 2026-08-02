"""Dependency provenance contracts for FastMCP 4 readiness targets."""

from importlib import metadata

import pytest
from packaging.version import Version


def _version(distribution: str) -> Version:
    """Return a parsed installed distribution version."""
    return Version(metadata.version(distribution))


@pytest.mark.fastmcp4_smoke
def test_fastmcp4_dependency_family_is_coherent() -> None:
    """Verify the selected published readiness target is internally coherent."""
    assert _version("fastmcp") == Version("4.0.0a2")
    assert _version("fastmcp-slim") == Version("4.0.0a2")
    assert _version("mcp") == Version("2.0.0b2")
    assert _version("mcp-types") == Version("2.0.0b2")
    assert _version("pydantic") >= Version("2.12.0")
    assert _version("starlette") >= Version("1.0.1")
