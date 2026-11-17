"""Public-protocol FastMCP 4 tool-policy canary."""

import importlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp import Client


@pytest.mark.anyio
@pytest.mark.fastmcp4_policy
async def test_hidden_tool_cannot_be_called(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A read-only-hidden write tool must be unknown on list and call paths."""
    monkeypatch.setenv("READ_ONLY_MODE", "true")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.test")
    monkeypatch.setenv("JIRA_PERSONAL_TOKEN", "readiness-only-placeholder")
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "false")
    monkeypatch.setenv("TOOLSETS", "all")
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp-home"))

    main_module = importlib.import_module("mcp_atlassian.servers.main")

    with patch(
        "mcp_atlassian.servers.jira.get_jira_fetcher",
        new_callable=AsyncMock,
        side_effect=AssertionError("hidden write reached the Jira fetcher"),
    ) as fetcher:
        async with Client(main_module.main_mcp) as client:
            tools = await client.list_tools()
            hidden_call = await client.call_tool_mcp(
                "jira_create_issue",
                {
                    "project_key": "TEST",
                    "summary": "Policy canary",
                    "issue_type": "Task",
                },
            )
            unknown_call = await client.call_tool_mcp("jira_no_such_tool", {})

    hidden_error = " ".join(
        getattr(content, "text", "") for content in hidden_call.content
    )
    is_error = getattr(hidden_call, "is_error", None)
    if is_error is None:
        is_error = hidden_call.isError
    assert is_error
    unknown_is_error = getattr(unknown_call, "is_error", None)
    if unknown_is_error is None:
        unknown_is_error = unknown_call.isError
    assert unknown_is_error
    assert "Unknown tool" in hidden_error
    assert "jira_create_issue" not in {tool.name for tool in tools}
    assert "jira_get_issue" in {tool.name for tool in tools}
    unknown_error = " ".join(
        getattr(content, "text", "") for content in unknown_call.content
    )
    assert hidden_error.replace("jira_create_issue", "<tool>") == (
        unknown_error.replace("jira_no_such_tool", "<tool>")
    )
    fetcher.assert_not_awaited()
