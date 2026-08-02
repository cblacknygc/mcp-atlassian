#!/usr/bin/env python3
"""Probe an mcp-atlassian subprocess using only the public MCP SDK."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

DEFAULT_MAX_RPM = 30
MAX_ALLOWED_RPM = 30
STAGING_ENV_MAP = {
    "MCP4_STAGE_JIRA_URL": "JIRA_URL",
    "MCP4_STAGE_JIRA_PAT": "JIRA_PERSONAL_TOKEN",
    "MCP4_STAGE_CONFLUENCE_URL": "CONFLUENCE_URL",
    "MCP4_STAGE_CONFLUENCE_PAT": "CONFLUENCE_PERSONAL_TOKEN",
}
STAGING_INHERITED_ENV = (
    "HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "PATH",
    "PATHEXT",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMPDIR",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


@dataclass(frozen=True)
class StagingProfile:
    """Validated, read-only Jira DC and Confluence DC staging profile."""

    child_env: dict[str, str]
    jira_issue_key: str
    confluence_page_id: str
    max_rpm: int


def _required(env: dict[str, str], name: str) -> str:
    """Return a nonempty staging value without logging its contents."""
    value = env.get(name, "").strip()
    if not value:
        message = f"Missing required staging environment variable: {name}"
        raise ValueError(message)
    return value


def build_staging_profile(env: dict[str, str]) -> StagingProfile:
    """Build a fail-closed subprocess environment for live read probes."""
    max_rpm = int(env.get("MCP4_STAGE_MAX_RPM", str(DEFAULT_MAX_RPM)))
    if not 1 <= max_rpm <= MAX_ALLOWED_RPM:
        message = f"MCP4_STAGE_MAX_RPM must be between 1 and {MAX_ALLOWED_RPM}"
        raise ValueError(message)

    child_env = {name: env[name] for name in STAGING_INHERITED_ENV if name in env}
    for staging_name, child_name in STAGING_ENV_MAP.items():
        child_env[child_name] = _required(env, staging_name)
    child_env.update(
        {
            "READ_ONLY_MODE": "true",
            "ATLASSIAN_OAUTH_PROXY_ENABLE": "false",
            "MCP_LOGGING_STDOUT": "false",
            "TOOLSETS": "all",
            "ENABLED_TOOLS": "jira_get_issue,confluence_get_page",
            "ATLASSIAN_REQUESTS_PER_SECOND": f"{max_rpm / 60:.6g}",
            "ATLASSIAN_MAX_CONCURRENT_REQUESTS": "1",
            "ATLASSIAN_RETRY_TOTAL": "0",
            "MCP4_STAGE_MAX_RPM": str(max_rpm),
        }
    )
    return StagingProfile(
        child_env=child_env,
        jira_issue_key=_required(env, "MCP4_STAGE_JIRA_ISSUE_KEY"),
        confluence_page_id=_required(env, "MCP4_STAGE_CONFLUENCE_PAGE_ID"),
        max_rpm=max_rpm,
    )


def _sdk_field(
    value: Any,
    snake_case: str,
    camel_case: str,
    *,
    default: Any,
) -> Any:
    """Read an MCP SDK field across the v1/v2 Python naming boundary."""
    snake_value = getattr(value, snake_case, None)
    return (
        snake_value
        if snake_value is not None
        else getattr(
            value,
            camel_case,
            default,
        )
    )


def _result_record(name: str, result: Any) -> dict[str, Any]:
    """Record only protocol shape, never Atlassian response content."""
    return {
        "tool": name,
        "is_error": bool(_sdk_field(result, "is_error", "isError", default=False)),
        "content_types": [
            getattr(item, "type", "unknown") for item in getattr(result, "content", [])
        ],
    }


async def probe(args: argparse.Namespace) -> dict[str, Any]:
    """Initialize, list tools, and optionally run paced staging reads."""
    profile = (
        build_staging_profile(os.environ.copy()) if args.staging_stdio_pat else None
    )
    child_env = profile.child_env if profile else os.environ.copy()
    parameters = StdioServerParameters(
        command=args.server_command,
        args=args.server_arg,
        env=child_env,
        cwd=args.cwd,
    )
    started = time.monotonic()
    probes: list[dict[str, Any]] = []

    with anyio.fail_after(args.timeout):
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                listed = await session.list_tools()
                tool_names = sorted(tool.name for tool in listed.tools)

                if profile:
                    hidden_writes = {
                        "jira_create_issue",
                        "confluence_create_page",
                    }.intersection(tool_names)
                    if hidden_writes:
                        message = (
                            "Read-only policy bypass exposed write tools: "
                            f"{sorted(hidden_writes)}"
                        )
                        raise RuntimeError(message)

                    jira_result = await session.call_tool(
                        "jira_get_issue",
                        {"issue_key": profile.jira_issue_key},
                    )
                    probes.append(_result_record("jira_get_issue", jira_result))
                    await anyio.sleep(60 / profile.max_rpm)
                    confluence_result = await session.call_tool(
                        "confluence_get_page",
                        {"page_id": profile.confluence_page_id},
                    )
                    probes.append(
                        _result_record("confluence_get_page", confluence_result)
                    )

    return {
        "transport": "stdio",
        "staging_profile": "jira-dc-confluence-dc-pat" if profile else None,
        "max_rpm": profile.max_rpm if profile else None,
        "protocol_version": str(
            _sdk_field(
                initialized,
                "protocol_version",
                "protocolVersion",
                default="unknown",
            )
        ),
        "tool_count": len(tool_names),
        "tool_names": tool_names,
        "probes": probes,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _parser() -> argparse.ArgumentParser:
    """Build the wire-probe argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-command", default="mcp-atlassian")
    parser.add_argument("--server-arg", action="append", default=[])
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--staging-stdio-pat", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    """Run the probe and optionally persist its sanitized evidence."""
    args = _parser().parse_args()
    result = anyio.run(probe, args)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
