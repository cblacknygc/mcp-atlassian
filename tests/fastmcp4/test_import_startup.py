"""Production import and construction smoke tests."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.fastmcp4_smoke
def test_production_modules_import_and_construct(tmp_path: Path) -> None:
    """Import every FastMCP-facing module and construct the HTTP application."""
    probe = """
from mcp_atlassian.servers import confluence, error_handling, jira, oauth_proxy
from mcp_atlassian.servers.main import AtlassianMCP, main_mcp

assert AtlassianMCP(name="fastmcp4-import-probe")
assert error_handling.ErrorPreservingFastMCP(name="fastmcp4-error-probe")
assert main_mcp.http_app()
assert confluence.confluence_mcp
assert jira.jira_mcp
assert oauth_proxy.HardenedOAuthProxy
"""
    env = os.environ.copy()
    env["FASTMCP_HOME"] = str(tmp_path / "fastmcp-home")
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        check=False,
        capture_output=True,
        env=env,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, (
        "FastMCP 4 production import/startup failed:\n"
        f"{completed.stdout}{completed.stderr}"
    )
