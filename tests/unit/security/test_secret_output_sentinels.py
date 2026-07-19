"""No-network sentinel regressions for authentication output boundaries."""

from __future__ import annotations

import importlib.util
import logging
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from mcp_atlassian.confluence.client import ConfluenceClient
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira.client import JiraClient
from mcp_atlassian.servers.main import UserTokenMiddleware
from mcp_atlassian.utils import oauth_setup
from mcp_atlassian.utils.logging import get_masked_session_headers
from mcp_atlassian.utils.oauth import (
    BYOAccessTokenOAuthConfig,
    OAuthConfig,
    configure_oauth_session,
)
from tests.utils.sentinels import SecretSentinels, format_log_records


@pytest.fixture
def sentinels(request: pytest.FixtureRequest) -> SecretSentinels:
    """Return deterministic, test-specific inert secret values."""
    return SecretSentinels.create(request.node.nodeid)


@pytest.fixture
def standalone_oauth_helper() -> Iterator[ModuleType]:
    """Load the standalone helper without installing its global log handler."""
    logger_names = ("oauth-authorize", "mcp-atlassian.oauth")
    old_levels = {name: logging.getLogger(name).level for name in logger_names}
    helper_path = Path(__file__).parents[3] / "scripts" / "oauth_authorize.py"
    spec = importlib.util.spec_from_file_location(
        "test_standalone_oauth_authorize", helper_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch("logging.basicConfig"):
        spec.loader.exec_module(module)
    try:
        yield module
    finally:
        for name, level in old_levels.items():
            logging.getLogger(name).setLevel(level)


def _run_packaged_oauth_flow(
    monkeypatch: pytest.MonkeyPatch,
    *,
    client_secret: str,
    state: str,
) -> None:
    """Run the packaged OAuth helper with all external effects replaced."""

    class FakeOAuthConfig:
        def __init__(self, **kwargs: str) -> None:
            self.client_id = kwargs["client_id"]
            self.client_secret = kwargs["client_secret"]
            self.redirect_uri = kwargs["redirect_uri"]
            self.scope = kwargs["scope"]
            self.cloud_id = "inert-cloud-id"

        def get_authorization_url(self, state: str) -> str:
            return f"https://example.invalid/authorize?state={state}"

        def exchange_code_for_tokens(self, code: str) -> bool:
            return bool(code)

    def callback_ready() -> bool:
        oauth_setup.authorization_code = "inert-code"
        oauth_setup.authorization_state = state
        return True

    monkeypatch.setattr(oauth_setup, "OAuthConfig", FakeOAuthConfig)
    monkeypatch.setattr(oauth_setup, "wait_for_callback", callback_ready)
    monkeypatch.setattr(oauth_setup.webbrowser, "open", lambda url: True)
    monkeypatch.setattr("secrets.token_urlsafe", lambda size: state)
    args = oauth_setup.OAuthSetupArgs(
        client_id="inert-client-id",
        client_secret=client_secret,
        redirect_uri="https://callback.example.invalid/callback",
        scope="offline_access",
    )

    assert oauth_setup.run_oauth_flow(args) is True


def test_canonical_sensitive_headers_hide_complete_values(
    sentinels: SecretSentinels,
) -> None:
    """Canonical HTTP credential headers must hide complete sentinel values."""
    masked = get_masked_session_headers(
        {
            "Authorization": f"Bearer {sentinels['authorization_header']}",
            "Cookie": sentinels["cookie_header"],
            "Set-Cookie": sentinels["set_cookie_header"],
            "Proxy-Authorization": sentinels["proxy_authorization_header"],
        }
    )

    sentinels.assert_absent(masked, context="canonical masked header mapping")


def test_oauth_session_setup_logs_presence_without_token(
    sentinels: SecretSentinels, caplog: pytest.LogCaptureFixture
) -> None:
    """OAuth session diagnostics must not print the configured bearer token."""
    config = BYOAccessTokenOAuthConfig(
        access_token=sentinels["access_token"],
        base_url="https://jira.example.invalid",
    )
    session = Session()

    with caplog.at_level(logging.DEBUG, logger="mcp-atlassian.oauth"):
        assert configure_oauth_session(session, config) is True

    assert sentinels["access_token"] in session.headers["Authorization"]
    sentinels.assert_absent(
        format_log_records(caplog.records), context="OAuth session setup logs"
    )


def test_packaged_helper_redacts_client_secret(
    sentinels: SecretSentinels,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The packaged setup helper must retain its literal client-secret redaction."""
    with caplog.at_level(logging.INFO, logger="mcp-atlassian.oauth-setup"):
        _run_packaged_oauth_flow(
            monkeypatch,
            client_secret=sentinels["client_secret"],
            state="inert-state",
        )

    assert "ATLASSIAN_OAUTH_CLIENT_SECRET=<redacted>" in caplog.text
    sentinels.assert_absent(
        format_log_records(caplog.records), context="packaged OAuth helper logs"
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must omit OAuth state from packaged helper authorization logs",
)
def test_packaged_helper_does_not_log_complete_state(
    sentinels: SecretSentinels,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verbose packaged setup logs must not duplicate the complete OAuth state."""
    with caplog.at_level(logging.INFO, logger="mcp-atlassian.oauth-setup"):
        _run_packaged_oauth_flow(
            monkeypatch,
            client_secret="inert-client-secret",
            state=sentinels["expected_state"],
        )

    sentinels.assert_absent(
        format_log_records(caplog.records), context="packaged OAuth helper logs"
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must classify HTTP header names case-insensitively",
)
def test_sensitive_header_redaction_is_case_insensitive(
    sentinels: SecretSentinels,
) -> None:
    """Equivalent noncanonical credential headers must remain secret."""
    masked = get_masked_session_headers(
        {
            "authorization": f"Bearer {sentinels['authorization_header']}",
            "cOoKiE": sentinels["cookie_header"],
            "proxy-authorization": sentinels["proxy_authorization_header"],
        }
    )

    sentinels.assert_absent(masked, context="case-variant masked header mapping")


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must remove complete header values from client failure logs",
)
@pytest.mark.parametrize(
    ("service", "logger_name"),
    (("jira", "mcp-jira"), ("confluence", "mcp-atlassian")),
)
def test_client_auth_failure_does_not_log_complete_sensitive_headers(
    service: str,
    logger_name: str,
    sentinels: SecretSentinels,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Jira and Confluence failures must not serialize credential values."""
    headers = {
        "authorization": f"Bearer {sentinels['authorization_header']}",
        "cookie": sentinels["cookie_header"],
        "proxy-authorization": sentinels["proxy_authorization_header"],
    }
    client: Any
    if service == "jira":
        client = JiraClient.__new__(JiraClient)
        client.config = SimpleNamespace(url="https://jira.example.invalid")
        client.jira = SimpleNamespace(
            myself=MagicMock(side_effect=RuntimeError("inert failure")),
            _session=SimpleNamespace(headers=headers),
        )
    else:
        client = ConfluenceClient.__new__(ConfluenceClient)
        client.config = SimpleNamespace(url="https://confluence.example.invalid")
        client.confluence = SimpleNamespace(
            get_all_spaces=MagicMock(side_effect=RuntimeError("inert failure")),
            _session=SimpleNamespace(headers=headers),
        )

    with (
        caplog.at_level(logging.DEBUG, logger=logger_name),
        pytest.raises(MCPAtlassianAuthenticationError),
    ):
        client._validate_authentication()

    sentinels.assert_absent(
        format_log_records(caplog.records),
        context=f"{service} authentication failure logs",
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must remove complete MCP session identifiers from logs",
)
def test_mcp_middleware_does_not_log_complete_session_id(
    sentinels: SecretSentinels, caplog: pytest.LogCaptureFixture
) -> None:
    """MCP diagnostics must not expose a complete session identifier."""
    middleware = UserTokenMiddleware.__new__(UserTokenMiddleware)
    scope = {
        "path": "/mcp",
        "headers": [
            (b"authorization", b"Bearer inert-token"),
            (b"mcp-session-id", sentinels["mcp_session_id"].encode()),
        ],
        "state": {},
    }

    with caplog.at_level(logging.DEBUG, logger="mcp-atlassian.server.main"):
        middleware._process_authentication_headers(scope)

    sentinels.assert_absent(
        format_log_records(caplog.records), context="MCP middleware logs"
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must omit callback queries and secrets from standalone logs",
)
def test_standalone_callback_does_not_log_code_or_state(
    standalone_oauth_helper: ModuleType,
    sentinels: SecretSentinels,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The standalone callback must not log complete code or state values."""
    handler = standalone_oauth_helper.CallbackHandler.__new__(
        standalone_oauth_helper.CallbackHandler
    )
    handler.path = (
        f"/callback?code={sentinels['authorization_code']}"
        f"&state={sentinels['received_state']}"
    )
    handler._send_response = MagicMock()

    with caplog.at_level(logging.DEBUG, logger="oauth-authorize"):
        handler.do_GET()

    sentinels.assert_absent(
        format_log_records(caplog.records), context="standalone callback logs"
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must redact the standalone helper client secret",
)
def test_standalone_success_does_not_log_client_secret(
    standalone_oauth_helper: ModuleType,
    sentinels: SecretSentinels,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful standalone setup must not print the OAuth client secret."""

    class FakeOAuthConfig:
        def __init__(self, **kwargs: str) -> None:
            self.client_id = kwargs["client_id"]
            self.client_secret = kwargs["client_secret"]
            self.redirect_uri = kwargs["redirect_uri"]
            self.scope = kwargs["scope"]
            self.cloud_id = "inert-cloud-id"

        def get_authorization_url(self, state: str) -> str:
            return f"https://example.invalid/authorize?state={state}"

        def exchange_code_for_tokens(self, code: str) -> bool:
            return bool(code)

    standalone_vars = vars(standalone_oauth_helper)
    standalone_vars["authorization_code"] = "inert-code"
    standalone_vars["received_state"] = "inert-state"
    monkeypatch.setattr(standalone_oauth_helper, "OAuthConfig", FakeOAuthConfig)
    monkeypatch.setattr(
        standalone_oauth_helper.secrets, "token_urlsafe", lambda size: "inert-state"
    )
    monkeypatch.setattr(standalone_oauth_helper, "wait_for_callback", lambda: True)
    monkeypatch.setattr(standalone_oauth_helper.webbrowser, "open", lambda url: True)
    args = SimpleNamespace(
        client_id="inert-client-id",
        client_secret=sentinels["client_secret"],
        redirect_uri="https://callback.example.invalid/callback",
        scope="offline_access",
    )

    with caplog.at_level(logging.DEBUG, logger="oauth-authorize"):
        assert standalone_oauth_helper.run_oauth_flow(args) is True

    sentinels.assert_absent(
        format_log_records(caplog.records), context="standalone success logs"
    )


@pytest.mark.security_regression
@pytest.mark.xfail(
    strict=True,
    reason="Phase B must not log complete OAuth token-endpoint response bodies",
)
def test_oauth_exchange_failure_does_not_log_echoed_secrets(
    sentinels: SecretSentinels, caplog: pytest.LogCaptureFixture
) -> None:
    """OAuth exchange errors must omit submitted or returned secret material."""
    config = OAuthConfig(
        client_id="inert-client-id",
        client_secret=sentinels["client_secret"],
        redirect_uri="https://callback.example.invalid/callback",
        scope="WRITE",
        base_url="https://jira.example.invalid",
    )
    response = SimpleNamespace(
        ok=False,
        status_code=400,
        text=(
            f"code={sentinels['authorization_code']} "
            f"client_secret={sentinels['client_secret']} "
            f"access_token={sentinels['access_token']} "
            f"refresh_token={sentinels['refresh_token']}"
        ),
    )

    with (
        patch("mcp_atlassian.utils.oauth.requests.post", return_value=response),
        caplog.at_level(logging.ERROR, logger="mcp-atlassian.oauth"),
    ):
        assert config.exchange_code_for_tokens(sentinels["authorization_code"]) is False

    sentinels.assert_absent(
        format_log_records(caplog.records), context="OAuth exchange failure logs"
    )
