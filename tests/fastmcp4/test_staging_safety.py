"""Hermetic safety contracts for the opt-in live staging probe."""

import pytest

from scripts import mcp_wire_probe


def _staging_env() -> dict[str, str]:
    """Return placeholder staging values; no network is contacted."""
    return {
        "MCP4_STAGE_JIRA_URL": "https://jira-staging.example.test",
        "MCP4_STAGE_JIRA_PAT": "jira-placeholder",
        "MCP4_STAGE_JIRA_ISSUE_KEY": "TEST-1",
        "MCP4_STAGE_CONFLUENCE_URL": "https://wiki-staging.example.test",
        "MCP4_STAGE_CONFLUENCE_PAT": "confluence-placeholder",
        "MCP4_STAGE_CONFLUENCE_PAGE_ID": "12345",
    }


@pytest.mark.fastmcp4_protocol
def test_staging_profile_enforces_read_only_and_30_rpm_default() -> None:
    """The live profile must fail closed with bounded Atlassian traffic."""
    profile = mcp_wire_probe.build_staging_profile(_staging_env())

    assert profile.max_rpm == 30
    assert profile.child_env["READ_ONLY_MODE"] == "true"
    assert profile.child_env["ATLASSIAN_REQUESTS_PER_SECOND"] == "0.5"
    assert profile.child_env["ATLASSIAN_MAX_CONCURRENT_REQUESTS"] == "1"
    assert profile.child_env["ATLASSIAN_RETRY_TOTAL"] == "0"


@pytest.mark.fastmcp4_protocol
def test_staging_profile_rejects_rate_above_30_rpm() -> None:
    """A caller cannot loosen the initial live-system traffic ceiling."""
    env = _staging_env() | {"MCP4_STAGE_MAX_RPM": "31"}

    with pytest.raises(ValueError, match="between 1 and 30"):
        mcp_wire_probe.build_staging_profile(env)
