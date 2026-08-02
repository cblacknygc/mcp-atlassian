"""Dependency provenance contracts for FastMCP 4 readiness targets."""

import json
import os
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from packaging.version import Version


def _version(distribution: str) -> Version:
    """Return a parsed installed distribution version."""
    return Version(metadata.version(distribution))


@pytest.mark.fastmcp4_smoke
def test_fastmcp4_dependency_family_is_coherent() -> None:
    """Verify the selected readiness target is internally coherent."""
    target = os.getenv("FASTMCP4_TARGET", "published")
    fastmcp_version = _version("fastmcp")
    slim_version = _version("fastmcp-slim")

    assert fastmcp_version == slim_version
    if target == "published":
        assert fastmcp_version == Version("4.0.0a2")
        assert _version("mcp") == Version("2.0.0b2")
        assert _version("mcp-types") == Version("2.0.0b2")
    elif target == "upstream-main":
        fastmcp_direct = metadata.distribution("fastmcp").read_text("direct_url.json")
        slim_direct = metadata.distribution("fastmcp-slim").read_text("direct_url.json")
        assert fastmcp_direct and slim_direct
        fastmcp_url = json.loads(fastmcp_direct)["url"]
        slim_url = json.loads(slim_direct)["url"]
        fastmcp_source = Path(unquote(urlparse(fastmcp_url).path)).resolve()
        slim_source = Path(unquote(urlparse(slim_url).path)).resolve()
        assert slim_source == fastmcp_source / "fastmcp_slim"
        assert os.getenv("FASTMCP_GIT_SHA")
    else:
        pytest.fail(f"Unknown FASTMCP4_TARGET: {target}")

    assert _version("pydantic") >= Version("2.12.0")
    assert _version("starlette") >= Version("1.0.1")
