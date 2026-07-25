"""Unit tests for OAuth proxy provider construction and hardening."""

from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oauth_proxy.models import ClientCode
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    authorization_context,
)
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from mcp_atlassian.servers.main import AtlassianMCP, _build_auth_provider
from mcp_atlassian.servers.oauth_proxy import HardenedOAuthProxy
from mcp_atlassian.utils.oauth import CLOUD_AUTHORIZE_URL, CLOUD_TOKEN_URL
from mcp_atlassian.utils.token_verifier import AtlassianOpaqueTokenVerifier

SCOPES = ["read:jira-work"]
BASE_URL = "https://mcp.test"
REDIRECT_URI = AnyUrl("http://127.0.0.1:12345/callback")
SIGNING_MATERIAL = "0123456789abcdef0123456789abcdef"
INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "security-test", "version": "1"},
    },
}
MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}


def _set_required_oauth_env(monkeypatch, *, redirect_uri: str) -> None:
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("ATLASSIAN_OAUTH_REDIRECT_URI", redirect_uri)


class _DummyProviderStorage:
    def __init__(self, config=None):
        self.factory_config = config

    async def get(self, *args, **kwargs):
        _ = args, kwargs
        return None

    async def put(self, *args, **kwargs):
        _ = args, kwargs
        return None

    async def delete(self, *args, **kwargs):
        _ = args, kwargs
        return True

    async def ttl(self, *args, **kwargs):
        _ = args, kwargs
        return None

    async def get_many(self, *args, **kwargs):
        _ = args, kwargs
        return {}

    async def put_many(self, *args, **kwargs):
        _ = args, kwargs
        return None

    async def delete_many(self, *args, **kwargs):
        _ = args, kwargs
        return 0

    async def ttl_many(self, *args, **kwargs):
        _ = args, kwargs
        return {}


def _dummy_provider_storage_factory(config=None):
    return _DummyProviderStorage(config=config)


class RecordingAtlassianVerifier(AtlassianOpaqueTokenVerifier):
    """Record upstream tokens that reach the Jira validation boundary."""

    def __init__(self) -> None:
        super().__init__(required_scopes=SCOPES)
        self.seen: list[str] = []

    async def verify_token(self, token: str) -> AccessToken | None:
        self.seen.append(token)
        return await super().verify_token(token)


@dataclass
class ProviderHarness:
    provider: HardenedOAuthProxy
    verifier: RecordingAtlassianVerifier


def _make_provider() -> ProviderHarness:
    """Build an entirely in-memory OAuth proxy with an inert verifier."""
    verifier = RecordingAtlassianVerifier()
    provider = HardenedOAuthProxy(
        upstream_authorization_endpoint="https://jira.invalid/authorize",
        upstream_token_endpoint="https://jira.invalid/token",
        upstream_client_id="upstream-client",
        upstream_client_secret=SIGNING_MATERIAL,
        token_verifier=verifier,
        base_url=BASE_URL,
        resource_base_url=BASE_URL,
        valid_scopes=SCOPES,
        client_storage=MemoryStore(),
        require_authorization_consent=False,
    )
    provider.set_mcp_path("/mcp")
    return ProviderHarness(provider=provider, verifier=verifier)


async def _issue_outer_token(
    harness: ProviderHarness,
    *,
    client_id: str,
    upstream_token: str,
    code: str,
) -> str:
    """Issue a real outer JWT for an inert upstream Jira token."""
    client = OAuthClientInformationFull(
        redirect_uris=[REDIRECT_URI],
        client_id=client_id,
        token_endpoint_auth_method="none",
    )
    authorization_code = AuthorizationCode(
        code=code,
        scopes=SCOPES,
        expires_at=time.time() + 60,
        client_id=client_id,
        code_challenge="challenge",
        redirect_uri=REDIRECT_URI,
        redirect_uri_provided_explicitly=True,
    )
    await harness.provider._code_store.put(
        key=code,
        value=ClientCode(
            code=code,
            client_id=client_id,
            redirect_uri=str(REDIRECT_URI),
            code_challenge="challenge",
            code_challenge_method="S256",
            scopes=SCOPES,
            idp_tokens={
                "access_token": upstream_token,
                "token_type": "Bearer",
                "scope": " ".join(SCOPES),
                "expires_in": 3600,
            },
            expires_at=time.time() + 60,
            created_at=time.time(),
        ),
        ttl=60,
    )
    result = await harness.provider.exchange_authorization_code(
        client,
        authorization_code,
    )
    return result.access_token


async def _assert_asgi_401_before_mcp_run(
    provider: HardenedOAuthProxy,
    outer_token: str,
) -> None:
    """Prove FastMCP rejects a token before MCP protocol execution."""
    server = AtlassianMCP("token-security-probe", auth=provider)
    app = server.http_app(path="/mcp", stateless_http=True, json_response=True)
    headers = {**MCP_HEADERS, "authorization": f"Bearer {outer_token}"}

    with patch.object(server._mcp_server, "run", new=AsyncMock()) as run_mock:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url=BASE_URL,
            ) as client:
                response = await client.post(
                    "/mcp",
                    headers=headers,
                    json=INITIALIZE_REQUEST,
                )

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith(
        'Bearer error="invalid_token"'
    )
    run_mock.assert_not_awaited()


def test_build_auth_provider_disabled_by_default(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("ATLASSIAN_OAUTH_REDIRECT_URI", "http://localhost:3000/callback")
    monkeypatch.delenv("ATLASSIAN_OAUTH_PROXY_ENABLE", raising=False)

    provider = _build_auth_provider()

    assert provider is None


def test_build_auth_provider_disabled_when_flag_false(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "false")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("ATLASSIAN_OAUTH_REDIRECT_URI", "http://localhost:3000/callback")

    provider = _build_auth_provider()

    assert provider is None


def test_build_auth_provider_falls_back_to_jira_url(monkeypatch):
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.delenv("CONFLUENCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None


def test_build_auth_provider_supports_service_specific_credentials(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.delenv("ATLASSIAN_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "jira-client-id")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "jira-client-secret")
    monkeypatch.setenv("ATLASSIAN_OAUTH_REDIRECT_URI", "http://localhost:3000/callback")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")

    provider = _build_auth_provider()

    assert provider is not None
    assert provider._upstream_client_id == "jira-client-id"
    assert provider._upstream_client_secret.get_secret_value() == "jira-client-secret"


def test_build_auth_provider_uses_cloud_endpoints_for_atlassian_cloud(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://acme.atlassian.net")
    _set_required_oauth_env(monkeypatch, redirect_uri="http://localhost:3000/callback")

    provider = _build_auth_provider()

    assert provider is not None
    assert provider._upstream_authorization_endpoint == CLOUD_AUTHORIZE_URL
    assert provider._upstream_token_endpoint == CLOUD_TOKEN_URL
    assert provider._extra_authorize_params == {
        "audience": "api.atlassian.com",
        "prompt": "consent",
    }


def test_build_auth_provider_uses_dc_endpoints_for_datacenter_url(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(monkeypatch, redirect_uri="http://localhost:3000/callback")

    provider = _build_auth_provider()

    assert provider is not None
    assert (
        provider._upstream_authorization_endpoint
        == "https://jira.example.com/rest/oauth2/latest/authorize"
    )
    assert (
        provider._upstream_token_endpoint
        == "https://jira.example.com/rest/oauth2/latest/token"
    )


def test_build_auth_provider_infers_base_url_from_redirect_uri(monkeypatch):
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert str(provider.base_url) == "https://mcp.example.com/mcp-atlassian"
    assert provider._redirect_path == "/callback"


def test_build_auth_provider_prefers_public_base_url(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com/mcp-atlassian")
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert str(provider.base_url) == "https://mcp.example.com/mcp-atlassian"
    assert provider._redirect_path == "/callback"


def test_build_auth_provider_supports_root_redirect_uri(monkeypatch):
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(monkeypatch, redirect_uri="http://localhost:3000/callback")

    provider = _build_auth_provider()

    assert provider is not None
    assert str(provider.base_url).rstrip("/") == "http://localhost:3000"
    assert provider._redirect_path == "/callback"


def test_build_auth_provider_allows_chatgpt_oauth_redirect(monkeypatch):
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert (
        "https://chatgpt.com/connector_platform_oauth_redirect"
        in provider._allowed_client_redirect_uris
    )


def test_build_auth_provider_uses_env_redirect_uris(monkeypatch):
    monkeypatch.setenv(
        "ATLASSIAN_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS", "https://example.com/callback"
    )
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert provider._allowed_client_redirect_uris == ["https://example.com/callback"]


def test_build_auth_provider_can_disable_consent(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_REQUIRE_CONSENT", "false")
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert provider._require_authorization_consent is False


def test_build_auth_provider_exposes_discovery_and_dcr_routes(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(monkeypatch, redirect_uri="http://localhost:3000/callback")

    provider = _build_auth_provider()

    assert provider is not None
    route_paths = {route.path for route in provider.get_routes("/mcp")}
    assert "/authorize" in route_paths
    assert "/token" in route_paths
    assert "/register" in route_paths
    assert "/.well-known/oauth-authorization-server" in route_paths
    assert "/.well-known/oauth-protected-resource/mcp" in route_paths
    assert "/callback" in route_paths


def test_build_auth_provider_supports_custom_client_storage_factory(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(monkeypatch, redirect_uri="http://localhost:3000/callback")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_STORAGE_MODE", "factory")
    monkeypatch.setenv(
        "ATLASSIAN_OAUTH_CLIENT_STORAGE_FACTORY",
        "tests.unit.servers.test_oauth_proxy_build:_dummy_provider_storage_factory",
    )
    monkeypatch.setenv(
        "ATLASSIAN_OAUTH_CLIENT_STORAGE_CONFIG_JSON", '{"collection":"registrations"}'
    )

    provider = _build_auth_provider()

    assert provider is not None
    assert provider._client_storage is not None
    assert provider._client_storage.__class__.__name__ == "_DummyProviderStorage"
    assert callable(getattr(provider._client_storage, "get", None))
    assert callable(getattr(provider._client_storage, "put", None))
    assert callable(getattr(provider._client_storage, "delete", None))
    assert callable(getattr(provider._client_storage, "ttl", None))
    assert callable(getattr(provider._client_storage, "get_many", None))
    assert callable(getattr(provider._client_storage, "put_many", None))
    assert callable(getattr(provider._client_storage, "delete_many", None))
    assert callable(getattr(provider._client_storage, "ttl_many", None))
    assert provider._client_storage.factory_config == {"collection": "registrations"}


@pytest.mark.anyio
async def test_register_client_hardens_grant_types_and_scopes(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_SCOPE", "read:jira-work")
    monkeypatch.setenv("ATLASSIAN_OAUTH_ALLOWED_GRANT_TYPES", "authorization_code")
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASSIAN_OAUTH_INSTANCE_URL", raising=False)
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    _set_required_oauth_env(
        monkeypatch, redirect_uri="https://mcp.example.com/mcp-atlassian/callback"
    )

    provider = _build_auth_provider()

    assert provider is not None
    client = OAuthClientInformationFull(
        client_id="client-123",
        client_secret="secret",
        redirect_uris=["http://localhost:1234/callback"],
        grant_types=[
            "refresh_token",
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ],
        scope="read:jira-work write:jira-work",
    )

    await provider.register_client(client)
    stored = await provider._client_store.get(key="client-123")

    assert stored is not None
    assert stored.grant_types == ["authorization_code"]
    assert stored.scope == "read:jira-work"


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_valid_outer_token_resolves_only_its_upstream_jira_token():
    """The outer JWT is swapped for its associated upstream Jira token."""
    harness = _make_provider()
    outer = await _issue_outer_token(
        harness,
        client_id="mcp-client-a",
        upstream_token="upstream-jira-user-a",
        code="code-a",
    )

    resolved = await harness.provider.load_access_token(outer)

    assert resolved is not None
    assert resolved.token == "upstream-jira-user-a"
    assert resolved.subject is not None
    assert harness.verifier.seen == ["upstream-jira-user-a"]
    assert outer not in harness.verifier.seen


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_distinct_users_get_distinct_session_owner_subjects():
    """Different upstream users must not collapse to one session owner."""
    harness = _make_provider()
    outer_a = await _issue_outer_token(
        harness,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-a",
        code="code-a",
    )
    outer_b = await _issue_outer_token(
        harness,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-b",
        code="code-b",
    )

    access_a = await harness.provider.load_access_token(outer_a)
    access_b = await harness.provider.load_access_token(outer_b)

    assert access_a is not None and access_b is not None
    owner_a = authorization_context(AuthenticatedUser(access_a))
    owner_b = authorization_context(AuthenticatedUser(access_b))
    assert owner_a["subject"] is not None
    assert owner_b["subject"] is not None
    assert owner_a != owner_b


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_cross_user_token_cannot_reuse_another_users_mcp_session():
    """A bearer for user B cannot enter user A's stateful MCP session."""
    harness = _make_provider()
    outer_a = await _issue_outer_token(
        harness,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-a",
        code="code-session-a",
    )
    outer_b = await _issue_outer_token(
        harness,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-b",
        code="code-session-b",
    )
    server = AtlassianMCP("session-owner-probe", auth=harness.provider)
    app = server.http_app(path="/mcp", stateless_http=False, json_response=True)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as client:
            initialize = await client.post(
                "/mcp",
                headers={
                    **MCP_HEADERS,
                    "authorization": f"Bearer {outer_a}",
                },
                json=INITIALIZE_REQUEST,
            )
            assert initialize.status_code == 200
            session_id = initialize.headers["mcp-session-id"]

            cross_user = await client.post(
                "/mcp",
                headers={
                    **MCP_HEADERS,
                    "authorization": f"Bearer {outer_b}",
                    "mcp-session-id": session_id,
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )

    assert cross_user.status_code == 404
    assert cross_user.json()["error"]["message"] == "Session not found"


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_invalid_outer_token_never_reaches_upstream_or_mcp():
    """A malformed JWT is rejected before upstream validation or MCP."""
    harness = _make_provider()

    assert await harness.provider.load_access_token("not-a-jwt") is None
    assert harness.verifier.seen == []
    await _assert_asgi_401_before_mcp_run(harness.provider, "not-a-jwt")
    assert harness.verifier.seen == []


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_unknown_jti_never_reaches_upstream_or_mcp():
    """A signed JWT without a server-side mapping is rejected."""
    harness = _make_provider()
    unknown = harness.provider.jwt_issuer.issue_access_token(
        client_id="mcp-client",
        scopes=SCOPES,
        jti="unknown-jti",
        expires_in=3600,
    )

    assert await harness.provider.load_access_token(unknown) is None
    assert harness.verifier.seen == []
    await _assert_asgi_401_before_mcp_run(harness.provider, unknown)
    assert harness.verifier.seen == []


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_stale_replayed_jti_never_reaches_upstream_or_mcp():
    """A JWT replay after its server-side mapping is removed is rejected."""
    harness = _make_provider()
    outer = await _issue_outer_token(
        harness,
        client_id="mcp-client",
        upstream_token="upstream-jira-user",
        code="code-stale",
    )
    first = await harness.provider.load_access_token(outer)
    assert first is not None
    assert harness.verifier.seen == ["upstream-jira-user"]

    payload = harness.provider.jwt_issuer.verify_token(outer)
    await harness.provider._jti_mapping_store.delete(key=payload["jti"])
    harness.verifier.seen.clear()

    assert await harness.provider.load_access_token(outer) is None
    assert harness.verifier.seen == []
    await _assert_asgi_401_before_mcp_run(harness.provider, outer)
    assert harness.verifier.seen == []


@pytest.mark.security_regression
@pytest.mark.anyio
async def test_foreign_provider_token_never_reaches_upstream_or_mcp():
    """A valid token from an isolated provider store is rejected."""
    user_a = _make_provider()
    user_b = _make_provider()
    outer_a = await _issue_outer_token(
        user_a,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-a",
        code="code-foreign-a",
    )
    outer_b = await _issue_outer_token(
        user_b,
        client_id="mcp-client",
        upstream_token="upstream-jira-user-b",
        code="code-foreign-b",
    )

    resolved_b = await user_b.provider.load_access_token(outer_b)
    assert resolved_b is not None
    user_b.verifier.seen.clear()

    assert await user_b.provider.load_access_token(outer_a) is None
    assert user_b.verifier.seen == []
    await _assert_asgi_401_before_mcp_run(user_b.provider, outer_a)
    assert user_b.verifier.seen == []
