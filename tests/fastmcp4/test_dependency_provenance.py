"""Dependency provenance contracts for FastMCP 4 readiness targets."""

import json
import os
import subprocess
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from packaging.version import Version


def _version(distribution: str) -> Version:
    """Return a parsed installed distribution version."""
    return Version(metadata.version(distribution))


def _editable_source(distribution: str) -> Path:
    """Return the editable local source recorded by the package installer."""
    direct_url = metadata.distribution(distribution).read_text("direct_url.json")
    assert direct_url, f"{distribution} has no editable source provenance"
    source = json.loads(direct_url)
    parsed = urlparse(source["url"])
    assert parsed.scheme == "file" and parsed.netloc in {"", "localhost"}
    assert source.get("dir_info", {}).get("editable") is True
    return Path(unquote(parsed.path)).resolve()


@pytest.mark.fastmcp4_smoke
def test_fastmcp4_dependency_family_is_coherent() -> None:
    """Verify the selected published readiness target is internally coherent."""
    assert _version("fastmcp") == _version("fastmcp-slim")
    if os.getenv("FASTMCP4_TARGET", "published") == "published":
        for name in ("fastmcp", "fastmcp-slim"):
            assert not metadata.distribution(name).read_text("direct_url.json"), (
                f"{name} must come from the published lock, not a direct source"
            )
        assert _version("fastmcp") == Version("4.2.0")
        assert _version("mcp") == Version("2.3.0")
        assert _version("mcp-types") == Version("2.3.0")
    else:
        assert _version("mcp").major == 2
        assert _version("mcp-types").major == 2
        fastmcp_source = _editable_source("fastmcp")
        slim_source = _editable_source("fastmcp-slim")
        assert slim_source == fastmcp_source / "fastmcp_slim"
        expected_sha = os.environ.get("FASTMCP_GIT_SHA")
        assert expected_sha, "upstream-main requires an exact FASTMCP_GIT_SHA"
        actual_sha = subprocess.run(
            ["git", "-C", str(fastmcp_source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert actual_sha == expected_sha
        status = subprocess.run(
            ["git", "-C", str(fastmcp_source), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert not status, "upstream-main checkout must be clean"
    assert _version("pydantic") >= Version("2.12.0")
    assert _version("starlette") >= Version("1.0.1")
