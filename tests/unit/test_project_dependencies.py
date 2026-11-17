"""Tests for project dependency declarations."""

import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version


def test_fastmcp_dependency_targets_the_tested_v4_release() -> None:
    """Require the FastMCP 4 release used by the readiness suite."""
    pyproject = Path("pyproject.toml").read_text()

    requirement = re.search(r'"fastmcp(?P<specifiers>[^\"]+)"', pyproject)
    assert requirement is not None

    specifier = Requirement(f"fastmcp{requirement.group('specifiers')}").specifier
    assert Version("4.2.0") in specifier
    assert Version("3.4.11") not in specifier


def test_starlette_minimum_version_includes_host_header_fix() -> None:
    """Ensure Starlette includes the fixed Host header parsing behavior."""
    pyproject = Path("pyproject.toml").read_text()

    requirement = re.search(r'"starlette(?P<specifiers>[^\"]+)"', pyproject)
    assert requirement is not None

    lower_bound = re.search(
        r"(?:^|,)\s*>=\s*(?P<version>\d+(?:\.\d+)*)",
        requirement.group("specifiers"),
    )
    assert lower_bound is not None

    minimum_version = tuple(
        int(part) for part in lower_bound.group("version").split(".")
    )
    assert minimum_version >= (1, 0, 1)


def test_atlassian_python_api_is_pinned_before_server_dc_breaking_release() -> None:
    """Keep Confluence Server/DC compatible with the v4 URL layout."""
    pyproject = Path("pyproject.toml").read_text()

    requirement = re.search(r'"atlassian-python-api(?P<specifiers>[^\"]+)"', pyproject)
    assert requirement is not None
    assert "<5.0.0" in requirement.group("specifiers")
