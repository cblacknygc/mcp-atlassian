"""Hermetic MCP SDK integration against the production HTTP application."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import httpx2
import pytest
from fastmcp import Context
from fastmcp.utilities.asgi_transport import StreamingASGITransport
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


@pytest.mark.anyio
@pytest.mark.fastmcp4_integration
@pytest.mark.fastmcp4_policy
@pytest.mark.parametrize("stateless", [False, True], ids=["stateful", "stateless"])
async def test_http_sdk_read_and_hidden_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stateless: bool
) -> None:
    """Exercise the real server through the SDK without contacting Jira."""
    monkeypatch.setenv("JIRA_URL", "https://jira.example.test")
    monkeypatch.setenv("JIRA_PERSONAL_TOKEN", "http-integration-placeholder")
    monkeypatch.setenv("READ_ONLY_MODE", "true")
    monkeypatch.setenv("ENABLED_TOOLS", "jira_get_issue")
    monkeypatch.setenv("TOOLSETS", "all")
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "false")
    monkeypatch.setenv("ALLOW_GLOBAL_CRED_FALLBACK", "true")
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp-home"))
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    monkeypatch.setenv("MCP_ATLASSIAN_FILES_DIR", str(files_dir))

    from mcp_atlassian.servers.main import main_mcp

    app = main_mcp.http_app(
        transport="streamable-http", stateless_http=stateless, json_response=True
    )
    issue = MagicMock()
    issue.to_simplified_dict.return_value = {"id": "10001", "key": "TEST-1"}
    fetcher = MagicMock()
    fetcher.get_issue.return_value = issue

    with patch(
        "mcp_atlassian.servers.jira.get_jira_fetcher",
        new_callable=AsyncMock,
        return_value=fetcher,
    ) as get_jira_fetcher:
        with anyio.fail_after(15):
            async with app.router.lifespan_context(app):
                async with httpx2.AsyncClient(
                    transport=StreamingASGITransport(app),
                    base_url="http://127.0.0.1",
                ) as http:
                    async with streamable_http_client(
                        "http://127.0.0.1/mcp", http_client=http
                    ) as (read_stream, write_stream):
                        async with ClientSession(read_stream, write_stream) as client:
                            initialized = await client.initialize()
                            listed = await client.list_tools()
                            read = await client.call_tool(
                                "jira_get_issue", {"issue_key": "TEST-1"}
                            )
                            hidden = await client.call_tool(
                                "jira_create_issue",
                                {
                                    "project_key": "TEST",
                                    "summary": "Policy canary",
                                    "issue_type": "Task",
                                },
                            )
                            unknown = await client.call_tool("jira_no_such_tool", {})

    assert initialized.protocol_version == "2025-11-25"
    assert {tool.name for tool in listed.tools} == {"jira_get_issue"}
    assert not read.is_error
    assert hidden.is_error and unknown.is_error
    hidden_text = " ".join(getattr(item, "text", "") for item in hidden.content)
    unknown_text = " ".join(getattr(item, "text", "") for item in unknown.content)
    assert "Unknown tool" in hidden_text
    assert hidden_text.replace("jira_create_issue", "<tool>") == unknown_text.replace(
        "jira_no_such_tool", "<tool>"
    )
    get_jira_fetcher.assert_awaited_once()
    fetcher.get_issue.assert_called_once()


@pytest.mark.anyio
@pytest.mark.fastmcp4_integration
@pytest.mark.fastmcp4_policy
async def test_stateless_http_uses_each_requests_service_headers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Successive clients must not reuse one another's Jira credentials."""
    for name in ("JIRA_URL", "JIRA_PERSONAL_TOKEN", "CONFLUENCE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("READ_ONLY_MODE", "true")
    monkeypatch.setenv("ENABLED_TOOLS", "jira_get_issue")
    monkeypatch.setenv("TOOLSETS", "all")
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "false")
    monkeypatch.setenv("ALLOW_GLOBAL_CRED_FALLBACK", "false")
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp-home"))
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    monkeypatch.setenv("MCP_ATLASSIAN_FILES_DIR", str(files_dir))

    from mcp_atlassian.servers.main import main_mcp

    app = main_mcp.http_app(
        transport="streamable-http", stateless_http=True, json_response=True
    )
    issue = MagicMock()
    issue.to_simplified_dict.return_value = {"id": "10001", "key": "TEST-1"}
    fetcher = MagicMock()
    fetcher.get_issue.return_value = issue
    observed_tokens: list[str] = []

    async def get_fetcher(ctx: Context) -> MagicMock:
        request = ctx.request_context.request
        observed_tokens.append(
            request.state.atlassian_service_headers["X-Atlassian-Jira-Personal-Token"]
        )
        return fetcher

    with (
        patch(
            "mcp_atlassian.servers.jira.get_jira_fetcher",
            new_callable=AsyncMock,
            side_effect=get_fetcher,
        ),
        # The URL is a placeholder; avoid DNS or any external network access.
        patch("mcp_atlassian.servers.main.validate_url_for_ssrf", return_value=None),
    ):
        with anyio.fail_after(15):
            async with app.router.lifespan_context(app):
                for token in ("test-token-a", "test-token-b"):
                    headers = {
                        "X-Atlassian-Jira-Url": "https://jira.example.test",
                        "X-Atlassian-Jira-Personal-Token": token,
                    }
                    async with httpx2.AsyncClient(
                        transport=StreamingASGITransport(app),
                        base_url="http://127.0.0.1",
                        headers=headers,
                    ) as http:
                        async with streamable_http_client(
                            "http://127.0.0.1/mcp", http_client=http
                        ) as (read_stream, write_stream):
                            async with ClientSession(
                                read_stream, write_stream
                            ) as client:
                                await client.initialize()
                                listed = await client.list_tools()
                                start = len(observed_tokens)
                                read = await client.call_tool(
                                    "jira_get_issue", {"issue_key": "TEST-1"}
                                )
                    assert {tool.name for tool in listed.tools} == {"jira_get_issue"}
                    assert not read.is_error
                    assert observed_tokens[start:]
                    assert set(observed_tokens[start:]) == {token}
