"""OAuth 2.0 utilities for Atlassian Cloud and Data Center authentication.

This module provides utilities for OAuth 2.0 (3LO) authentication with Atlassian.
It handles:
- OAuth configuration for both Cloud and Data Center
- Token acquisition, storage, and refresh
- Session configuration for API clients
"""

import hashlib
import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

import keyring
import requests

from .urls import is_atlassian_cloud_url

# Configure logging
logger = logging.getLogger("mcp-atlassian.oauth")

# Cloud OAuth endpoints
CLOUD_TOKEN_URL = "https://auth.atlassian.com/oauth/token"  # noqa: S105 - This is a public API endpoint URL, not a password
CLOUD_AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
CLOUD_ID_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

# Legacy aliases for backward compatibility
TOKEN_URL = CLOUD_TOKEN_URL  # noqa: S105
AUTHORIZE_URL = CLOUD_AUTHORIZE_URL

# Data Center OAuth endpoint paths (appended to base_url)
DC_TOKEN_PATH = "/rest/oauth2/latest/token"  # noqa: S105
DC_AUTHORIZE_PATH = "/rest/oauth2/latest/authorize"

TOKEN_EXPIRY_MARGIN = 300  # 5 minutes in seconds

# HTTP request timeouts (in seconds)
# Connection timeout: Time to establish TCP connection
# Read timeout: Time to receive response after connection established
HTTP_CONNECT_TIMEOUT = 5
HTTP_READ_TIMEOUT = 20
HTTP_TIMEOUT = (HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT)
KEYRING_SERVICE_NAME = "mcp-atlassian-oauth"
OAUTH_STORAGE_VERSION = 2
CLOUD_ISSUER = "https://auth.atlassian.com"
DEFAULT_TOKEN_PROFILE = "default"  # noqa: S105 - profile label, not a secret


@dataclass
class OAuthConfig:
    """OAuth 2.0 configuration for Atlassian Cloud and Data Center.

    This class manages the OAuth configuration and tokens. It handles:
    - Authentication configuration (client credentials)
    - Token acquisition and refreshing
    - Token storage and retrieval
    - Cloud ID identification (Cloud) or base URL routing (Data Center)
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    cloud_id: str | None = None
    base_url: str | None = None
    refresh_token: str | None = None
    access_token: str | None = None
    expires_at: float | None = None
    token_profile: str = DEFAULT_TOKEN_PROFILE

    def __post_init__(self) -> None:
        """Validate mutual exclusivity of cloud_id and base_url."""
        self.token_profile = self.token_profile.strip() or DEFAULT_TOKEN_PROFILE
        if self.cloud_id and self.base_url:
            # Check if base_url is a Cloud URL — if so, cloud_id takes precedence
            if is_atlassian_cloud_url(self.base_url):
                self.base_url = None
            else:
                raise ValueError(
                    "OAuthConfig cannot have both cloud_id and base_url set. "
                    "Use cloud_id for Cloud or base_url for Data Center."
                )

    @property
    def is_data_center(self) -> bool:
        """Check if this is a Data Center OAuth configuration.

        Returns:
            True if base_url is set and is not a Cloud URL.
        """
        if not self.base_url:
            return False
        return not is_atlassian_cloud_url(self.base_url)

    @property
    def token_url(self) -> str:
        """Get the token endpoint URL for the configured environment.

        Returns:
            Cloud token URL or Data Center instance-specific token URL.
        """
        if self.is_data_center and self.base_url:
            return f"{self.base_url.rstrip('/')}{DC_TOKEN_PATH}"
        return CLOUD_TOKEN_URL

    @property
    def authorize_url(self) -> str:
        """Get the authorization endpoint URL for the configured environment.

        Returns:
            Cloud authorize URL or Data Center instance-specific authorize URL.
        """
        if self.is_data_center and self.base_url:
            return f"{self.base_url.rstrip('/')}{DC_AUTHORIZE_PATH}"
        return CLOUD_AUTHORIZE_URL

    @property
    def is_token_expired(self) -> bool:
        """Check if the access token is expired or will expire soon.

        Returns:
            True if the token is expired or will expire soon, False otherwise.
        """
        # If we don't have a token or expiry time, consider it expired
        if not self.access_token or not self.expires_at:
            return True

        # Consider the token expired if it will expire within the margin
        return time.time() + TOKEN_EXPIRY_MARGIN >= self.expires_at

    def get_authorization_url(self, state: str) -> str:
        """Get the authorization URL for the OAuth 2.0 flow.

        Args:
            state: Random state string for CSRF protection

        Returns:
            The authorization URL to redirect the user to.
        """
        params: dict[str, str] = {
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
        }
        # Cloud-specific params (DC doesn't use audience or prompt)
        if not self.is_data_center:
            params["audience"] = "api.atlassian.com"
            params["prompt"] = "consent"

        return f"{self.authorize_url}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> bool:
        """Exchange the authorization code for access and refresh tokens.

        Args:
            code: The authorization code from the callback

        Returns:
            True if tokens were successfully acquired, False otherwise.
        """
        try:
            payload = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            }

            token_endpoint = self.token_url
            logger.info(f"Exchanging authorization code for tokens at {token_endpoint}")
            logger.debug("Sending token exchange request")

            response = requests.post(token_endpoint, data=payload, timeout=HTTP_TIMEOUT)

            # Log more details about the response
            logger.debug(f"Token exchange response status: {response.status_code}")

            if not response.ok:
                logger.error(
                    f"Token exchange failed with status {response.status_code}. "
                    f"Response: {response.text}"
                )
                return False

            # Parse the response
            token_data = response.json()

            # Check if required tokens are present
            if "access_token" not in token_data:
                logger.error(
                    f"Access token not found in response. "
                    f"Keys found: {list(token_data.keys())}"
                )
                return False

            # DC does NOT require refresh_token (no offline_access scope needed)
            if "refresh_token" not in token_data:
                if self.is_data_center:
                    logger.warning(
                        "No refresh_token in DC response — token cannot be refreshed. "
                        "Re-authenticate when the token expires."
                    )
                else:
                    logger.error(
                        "Refresh token not found in response. "
                        "Ensure 'offline_access' scope is included. "
                        f"Keys found: {list(token_data.keys())}"
                    )
                    return False

            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")
            self.expires_at = time.time() + token_data.get("expires_in", 3600)

            # Only get cloud ID for Cloud OAuth
            if not self.is_data_center:
                self._get_cloud_id()

            # Save the tokens
            self._save_tokens()

            # Log success message with token details
            logger.info(
                f"OAuth token exchange successful! "
                f"Access token expires in {token_data.get('expires_in', 3600)}s."
            )
            logger.info("Access token obtained successfully.")
            logger.info("Refresh token obtained successfully.")
            if self.cloud_id:
                logger.info(f"Cloud ID successfully retrieved: {self.cloud_id}")
            elif not self.is_data_center:
                logger.warning(
                    "Cloud ID was not retrieved after token exchange. "
                    "Check accessible resources."
                )
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during token exchange: {e}", exc_info=True)
            return False
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to decode JSON response from token endpoint: {e}",
                exc_info=True,
            )
            logger.error(
                f"Response text that failed to parse: "
                f"{response.text if 'response' in locals() else 'Response object not available'}"
            )
            return False
        except Exception as e:
            logger.error(f"Failed to exchange code for tokens: {e}")
            return False

    def refresh_access_token(self) -> bool:
        """Refresh the access token using the refresh token.

        Returns:
            True if the token was successfully refreshed, False otherwise.
        """
        if not self.refresh_token:
            logger.error("No refresh token available")
            return False

        try:
            payload = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }

            logger.debug(f"Refreshing access token at {self.token_url}...")
            response = requests.post(self.token_url, data=payload, timeout=HTTP_TIMEOUT)
            response.raise_for_status()

            # Parse the response
            token_data = response.json()
            self.access_token = token_data["access_token"]
            # Refresh token might also be rotated
            if "refresh_token" in token_data:
                self.refresh_token = token_data["refresh_token"]
            self.expires_at = time.time() + token_data.get("expires_in", 3600)

            # Save the tokens
            self._save_tokens()

            return True
        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            return False

    def ensure_valid_token(self) -> bool:
        """Ensure the access token is valid, refreshing if necessary.

        Returns:
            True if the token is valid (or was refreshed successfully), False otherwise.
        """
        if not self.is_token_expired:
            return True
        return self.refresh_access_token()

    def _get_cloud_id(self) -> None:
        """Get the cloud ID for the Atlassian instance.

        This method queries the accessible resources endpoint to get the cloud ID.
        The cloud ID is needed for API calls with Cloud OAuth.
        Data Center does not use cloud IDs.
        """
        if self.is_data_center:
            return

        if not self.access_token:
            logger.debug("No access token available to get cloud ID")
            return

        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = requests.get(CLOUD_ID_URL, headers=headers, timeout=HTTP_TIMEOUT)
            response.raise_for_status()

            resources = response.json()
            if resources and len(resources) > 0:
                # Use the first cloud site (most users have only one)
                self.cloud_id = resources[0]["id"]
                logger.debug(f"Found cloud ID: {self.cloud_id}")
            else:
                logger.warning("No Atlassian sites found in the response")
        except Exception as e:
            logger.error(f"Failed to get cloud ID: {e}")

    @staticmethod
    def _canonical_scopes(scope: str) -> tuple[str, ...]:
        """Return a stable, case-sensitive OAuth scope set."""
        return tuple(sorted(set(scope.replace(",", " ").split())))

    @staticmethod
    def _canonical_base_url(base_url: str) -> str:
        """Canonicalize a Data Center base URL without collapsing its path."""
        parsed = urllib.parse.urlsplit(base_url.strip())
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        if scheme not in {"http", "https"} or not hostname:
            raise ValueError("Data Center OAuth requires an HTTP(S) base URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "Data Center OAuth base URL cannot contain credentials, "
                "query, or fragment"
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Data Center OAuth base URL has an invalid port") from exc

        host_for_url = f"[{hostname}]" if ":" in hostname else hostname
        default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        netloc = (
            host_for_url if port is None or default_port else f"{host_for_url}:{port}"
        )
        path = parsed.path.rstrip("/")
        return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))

    @classmethod
    def _storage_identity(
        cls,
        client_id: str,
        scope: str,
        *,
        cloud_id: str | None = None,
        base_url: str | None = None,
        token_profile: str = DEFAULT_TOKEN_PROFILE,
    ) -> dict[str, Any]:
        """Build the complete identity for one persisted OAuth credential."""
        normalized_client_id = client_id
        scopes = cls._canonical_scopes(scope)
        profile = token_profile.strip() or DEFAULT_TOKEN_PROFILE
        if not normalized_client_id.strip():
            raise ValueError("OAuth token persistence requires a client ID")
        if not scopes:
            raise ValueError("OAuth token persistence requires at least one scope")
        if cloud_id and base_url:
            raise ValueError("OAuth token persistence requires one resource context")

        if base_url:
            resource = cls._canonical_base_url(base_url)
            issuer = resource
        elif cloud_id and cloud_id.strip():
            resource = cloud_id
            issuer = CLOUD_ISSUER
        else:
            raise ValueError(
                "OAuth token persistence requires a Cloud ID or Data Center base URL"
            )

        return {
            "version": OAUTH_STORAGE_VERSION,
            "issuer": issuer,
            "client_id": normalized_client_id,
            "resource": resource,
            "scopes": list(scopes),
            "profile": profile,
        }

    @staticmethod
    def _storage_username(identity: dict[str, Any]) -> str:
        """Return a fixed-length keyring and file identifier for an identity."""
        identity_json = json.dumps(
            identity, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        digest = hashlib.sha256(identity_json.encode()).hexdigest()
        return f"oauth-v{OAUTH_STORAGE_VERSION}-{digest}"

    def _get_keyring_username(self) -> str:
        """Get the versioned keyring username for this OAuth configuration."""
        identity = self._storage_identity(
            self.client_id,
            self.scope,
            cloud_id=self.cloud_id,
            base_url=self.base_url,
            token_profile=self.token_profile,
        )
        return self._storage_username(identity)

    def _token_data(self, identity: dict[str, Any]) -> dict[str, Any]:
        """Return versioned token data bound to its complete storage identity."""
        return {
            "storage_identity": identity,
            "refresh_token": self.refresh_token,
            "access_token": self.access_token,
            "expires_at": self.expires_at,
            "cloud_id": self.cloud_id,
            "base_url": self.base_url,
        }

    def _save_tokens(self) -> None:
        """Save the tokens securely using keyring for later use.

        This allows the tokens to be reused between runs without requiring
        the user to go through the authorization flow again.
        """
        try:
            identity = self._storage_identity(
                self.client_id,
                self.scope,
                cloud_id=self.cloud_id,
                base_url=self.base_url,
                token_profile=self.token_profile,
            )
        except ValueError as exc:
            logger.warning("OAuth tokens were not persisted: %s", exc)
            return

        username = self._storage_username(identity)
        token_data = self._token_data(identity)
        try:
            token_json = json.dumps(token_data)
            keyring.set_password(KEYRING_SERVICE_NAME, username, token_json)
            logger.debug(f"Saved OAuth tokens to keyring for {username}")
            self._save_tokens_to_file(token_data)
        except Exception as e:
            logger.error(f"Failed to save tokens to keyring: {e}")
            self._save_tokens_to_file(token_data)

    def _save_tokens_to_file(self, token_data: dict | None = None) -> None:
        """Save the tokens to a file as fallback storage.

        Args:
            token_data: Optional dict with token data. If not provided,
                        will use the current object attributes.
        """
        try:
            # Create the directory if it doesn't exist (owner-only)
            token_dir = Path.home() / ".mcp-atlassian"
            token_dir.mkdir(exist_ok=True)
            os.chmod(token_dir, 0o700)

            if token_data is None:
                identity = self._storage_identity(
                    self.client_id,
                    self.scope,
                    cloud_id=self.cloud_id,
                    base_url=self.base_url,
                    token_profile=self.token_profile,
                )
                token_data = self._token_data(identity)
            else:
                stored_identity = token_data.get("storage_identity")
                if not isinstance(stored_identity, dict):
                    raise ValueError("OAuth token data is missing its storage identity")
                identity = stored_identity

            token_path = token_dir / f"{self._storage_username(identity)}.json"

            # Persisted tokens are secrets: create/truncate owner-only so they are
            # never group/world-readable, independent of the process umask.
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(token_data, f)
            os.chmod(token_path, 0o600)

            logger.debug(f"Saved OAuth tokens to file {token_path} (fallback storage)")
        except Exception as e:
            logger.error(f"Failed to save tokens to file: {e}")

    @classmethod
    def load_tokens(
        cls,
        client_id: str,
        scope: str = "",
        *,
        cloud_id: str | None = None,
        base_url: str | None = None,
        token_profile: str = DEFAULT_TOKEN_PROFILE,
    ) -> dict[str, Any]:
        """Load tokens securely from keyring.

        Args:
            client_id: The OAuth client ID.
            scope: Requested OAuth scopes.
            cloud_id: Atlassian Cloud resource ID.
            base_url: Data Center issuer/resource URL.
            token_profile: Local principal/token-slot selector.

        Returns:
            Dict with the token data or empty dict if no tokens found
        """
        try:
            identity = cls._storage_identity(
                client_id,
                scope,
                cloud_id=cloud_id,
                base_url=base_url,
                token_profile=token_profile,
            )
        except ValueError as exc:
            logger.warning("OAuth tokens were not loaded: %s", exc)
            cls._warn_if_legacy_tokens_exist(client_id, cloud_id, base_url)
            return {}

        username = cls._storage_username(identity)

        try:
            token_json = keyring.get_password(KEYRING_SERVICE_NAME, username)
            if token_json:
                token_data = json.loads(token_json)
                if cls._stored_identity_matches(token_data, identity):
                    logger.debug(f"Loaded OAuth tokens from keyring for {username}")
                    return cast(dict[str, Any], token_data)
                logger.warning(
                    "Ignored persisted OAuth tokens with mismatched identity metadata"
                )
        except Exception as e:
            logger.warning(
                f"Failed to load tokens from keyring: {e}. Trying file fallback."
            )

        token_data = cls._load_tokens_from_file(identity)
        if token_data:
            return token_data
        cls._warn_if_legacy_tokens_exist(client_id, cloud_id, base_url)
        return {}

    @staticmethod
    def _stored_identity_matches(
        token_data: Any, expected_identity: dict[str, Any]
    ) -> bool:
        """Return whether persisted token metadata exactly matches the request."""
        if not isinstance(token_data, dict):
            return False
        stored_identity = token_data.get("storage_identity")
        return (
            isinstance(stored_identity, dict)
            and stored_identity == expected_identity
            and type(stored_identity.get("version")) is int
            and isinstance(stored_identity.get("issuer"), str)
            and isinstance(stored_identity.get("client_id"), str)
            and isinstance(stored_identity.get("resource"), str)
            and isinstance(stored_identity.get("profile"), str)
            and isinstance(stored_identity.get("scopes"), list)
            and all(isinstance(scope, str) for scope in stored_identity["scopes"])
        )

    @classmethod
    def _load_tokens_from_file(cls, identity: dict[str, Any]) -> dict[str, Any]:
        """Load tokens from a file as fallback.

        Args:
            identity: Complete expected OAuth storage identity.

        Returns:
            Dict with the token data or empty dict if no tokens found
        """
        token_path = (
            Path.home() / ".mcp-atlassian" / f"{cls._storage_username(identity)}.json"
        )

        if not token_path.exists():
            return {}

        try:
            with open(token_path) as f:
                token_data = json.load(f)
                if not cls._stored_identity_matches(token_data, identity):
                    logger.warning(
                        "Ignored OAuth token file with mismatched identity metadata"
                    )
                    return {}
                logger.debug(
                    f"Loaded OAuth tokens from file {token_path} (fallback storage)"
                )
                return cast(dict[str, Any], token_data)
        except Exception as e:
            logger.error(f"Failed to load tokens from file: {e}")
            return {}

    @classmethod
    def _warn_if_legacy_tokens_exist(
        cls, client_id: str, cloud_id: str | None, base_url: str | None
    ) -> None:
        """Warn about old ambiguous records without loading or modifying them."""
        legacy_usernames = {f"oauth-{client_id}"}
        if cloud_id:
            legacy_usernames.add(f"oauth-{client_id}-cloud-{cloud_id}")
        if base_url:
            url_hash = hashlib.sha256(base_url.encode()).hexdigest()[:8]
            legacy_usernames.add(f"oauth-{client_id}-dc-{url_hash}")

        legacy_found = False
        for username in legacy_usernames:
            try:
                if keyring.get_password(KEYRING_SERVICE_NAME, username):
                    legacy_found = True
                    break
            except Exception:  # noqa: BLE001 - keyring backends vary
                break

        legacy_filename = f"oauth-{client_id}.json"
        legacy_file_found = False
        if Path(legacy_filename).name == legacy_filename:
            legacy_path = Path.home() / ".mcp-atlassian" / legacy_filename
            legacy_file_found = legacy_path.exists()
        if legacy_found or legacy_file_found:
            logger.warning(
                "Legacy OAuth tokens were detected but cannot be safely matched to "
                "the current scope and token profile. Re-run "
                "`mcp-atlassian --oauth-setup` to authorize scoped storage."
            )

    @classmethod
    def from_env(
        cls,
        service_url: str | None = None,
        service_type: str | None = None,
    ) -> Optional["OAuthConfig"]:
        """Create an OAuth configuration from environment variables.

        Args:
            service_url: The service URL (e.g., JIRA_URL value) for DC detection.
            service_type: Service type ('jira' or 'confluence') for service-specific
                env vars.

        Returns:
            OAuthConfig instance or None if OAuth is not enabled
        """
        # Check if OAuth is explicitly enabled (allows minimal config)
        oauth_enabled = os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in (
            "true",
            "1",
            "yes",
        )

        # Service-specific env vars take precedence over shared ones
        prefix = service_type.upper() if service_type else None
        client_id = (
            os.getenv(f"{prefix}_OAUTH_CLIENT_ID") if prefix else None
        ) or os.getenv("ATLASSIAN_OAUTH_CLIENT_ID")
        client_secret = (
            os.getenv(f"{prefix}_OAUTH_CLIENT_SECRET") if prefix else None
        ) or os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET")
        redirect_uri = (
            os.getenv(f"{prefix}_OAUTH_REDIRECT_URI") if prefix else None
        ) or os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI")
        scope = (os.getenv(f"{prefix}_OAUTH_SCOPE") if prefix else None) or os.getenv(
            "ATLASSIAN_OAUTH_SCOPE"
        )
        token_profile = (
            (os.getenv(f"{prefix}_OAUTH_TOKEN_PROFILE") if prefix else None)
            or os.getenv("ATLASSIAN_OAUTH_TOKEN_PROFILE", DEFAULT_TOKEN_PROFILE)
            or DEFAULT_TOKEN_PROFILE
        )

        # Determine if this is a DC instance
        is_dc = bool(service_url) and not is_atlassian_cloud_url(service_url)

        # For DC, redirect_uri and scope can have defaults
        if is_dc:
            if not redirect_uri:
                redirect_uri = "http://localhost:8080/callback"
            if not scope:
                scope = "WRITE"

        # Full OAuth configuration (traditional mode)
        if all([client_id, client_secret]):
            # Need redirect_uri + scope for Cloud, but DC has defaults above
            if not all([redirect_uri, scope]) and not is_dc:
                return None

            cloud_id = os.getenv("ATLASSIAN_OAUTH_CLOUD_ID") if not is_dc else None
            base_url = service_url if is_dc else None

            config = cls(
                client_id=client_id or "",
                client_secret=client_secret or "",
                redirect_uri=redirect_uri or "",
                scope=scope or "",
                cloud_id=cloud_id,
                base_url=base_url,
                token_profile=token_profile,
            )

            # Try to load existing tokens
            token_data = cls.load_tokens(
                client_id or "",
                scope or "",
                cloud_id=cloud_id,
                base_url=base_url,
                token_profile=token_profile,
            )
            if token_data:
                config.refresh_token = token_data.get("refresh_token")
                config.access_token = token_data.get("access_token")
                config.expires_at = token_data.get("expires_at")

            return config

        # Minimal OAuth configuration (user-provided tokens mode)
        elif oauth_enabled:
            # Create minimal config that works with user-provided tokens
            logger.info(
                "Creating minimal OAuth config for user-provided tokens "
                "(ATLASSIAN_OAUTH_ENABLE=true)"
            )
            cloud_id = os.getenv("ATLASSIAN_OAUTH_CLOUD_ID") if not is_dc else None
            base_url = service_url if is_dc else None

            return cls(
                client_id="",  # Will be provided by user tokens
                client_secret="",  # Not needed for user tokens
                redirect_uri="",  # Not needed for user tokens
                scope="",  # Will be determined by user token permissions
                cloud_id=cloud_id,
                base_url=base_url,
            )

        # No OAuth configuration
        return None


@dataclass
class BYOAccessTokenOAuthConfig:
    """OAuth configuration when providing a pre-existing access token.

    This class is used when the user provides their own access token directly,
    bypassing the full OAuth 2.0 (3LO) flow. Works for both Cloud (with cloud_id)
    and Data Center (with base_url).

    This configuration does not support token refreshing.
    """

    access_token: str
    cloud_id: str | None = None
    base_url: str | None = None
    refresh_token: None = field(default=None, repr=False)
    expires_at: None = field(default=None, repr=False)

    @property
    def is_data_center(self) -> bool:
        """Check if this is a Data Center configuration."""
        if not self.base_url:
            return False
        return not is_atlassian_cloud_url(self.base_url)

    @classmethod
    def from_env(
        cls,
        service_url: str | None = None,
        service_type: str | None = None,
    ) -> Optional["BYOAccessTokenOAuthConfig"]:
        """Create a BYOAccessTokenOAuthConfig from environment variables.

        Args:
            service_url: The service URL for DC detection.
            service_type: Service type ('jira' or 'confluence') for service-specific
                env vars.

        Returns:
            BYOAccessTokenOAuthConfig instance or None if required
            environment variables are missing.
        """
        cloud_id = os.getenv("ATLASSIAN_OAUTH_CLOUD_ID")

        # Service-specific access token takes precedence
        prefix = service_type.upper() if service_type else None
        access_token = (
            os.getenv(f"{prefix}_OAUTH_ACCESS_TOKEN") if prefix else None
        ) or os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN")

        if not access_token:
            return None

        # Determine if DC
        is_dc = bool(service_url) and not is_atlassian_cloud_url(service_url)
        base_url = service_url if is_dc else None

        # Need either cloud_id (Cloud) or base_url (DC) to be useful
        if not cloud_id and not base_url:
            return None

        return cls(
            access_token=access_token,
            cloud_id=cloud_id if not is_dc else None,
            base_url=base_url,
        )


def get_oauth_config_from_env(
    service_url: str | None = None,
    service_type: str | None = None,
) -> OAuthConfig | BYOAccessTokenOAuthConfig | None:
    """Get the appropriate OAuth configuration from environment variables.

    This function attempts to load standard OAuth configuration first (OAuthConfig).
    If that's not available, it tries to load a "Bring Your Own Access Token"
    configuration (BYOAccessTokenOAuthConfig).

    Args:
        service_url: The service URL for DC detection.
        service_type: Service type ('jira' or 'confluence') for service-specific
            env vars.

    Returns:
        An instance of OAuthConfig or BYOAccessTokenOAuthConfig if environment
        variables are set for either, otherwise None.
    """
    return BYOAccessTokenOAuthConfig.from_env(
        service_url=service_url, service_type=service_type
    ) or OAuthConfig.from_env(service_url=service_url, service_type=service_type)


def configure_oauth_session(
    session: requests.Session, oauth_config: OAuthConfig | BYOAccessTokenOAuthConfig
) -> bool:
    """Configure a requests session with OAuth 2.0 authentication.

    This function ensures the access token is valid and adds it to the session headers.

    Args:
        session: The requests session to configure
        oauth_config: The OAuth configuration to use

    Returns:
        True if the session was successfully configured, False otherwise
    """
    logger.debug(
        f"configure_oauth_session: Received OAuthConfig with "
        f"access_token_present={bool(oauth_config.access_token)}, "
        f"refresh_token_present={bool(oauth_config.refresh_token)}, "
        f"cloud_id='{oauth_config.cloud_id}'"
    )

    # Early return when no tokens are available at all (#858)
    if not oauth_config.access_token and not oauth_config.refresh_token:
        logger.warning(
            "configure_oauth_session: No access_token or refresh_token available. "
            "Cannot configure OAuth session. If using per-request auth, "
            "the token should come from the request header."
        )
        return False

    # If user provided only an access token (no refresh_token), use it directly
    if oauth_config.access_token and not oauth_config.refresh_token:
        logger.info(
            "configure_oauth_session: Using provided OAuth access token directly "
            "(no refresh_token)."
        )
        session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
        return True
    logger.debug("configure_oauth_session: Proceeding to ensure_valid_token.")
    # Otherwise, ensure we have a valid token (refresh if needed)
    if isinstance(oauth_config, BYOAccessTokenOAuthConfig):
        logger.error(
            "configure_oauth_session: oauth access token configuration "
            "provided as empty string."
        )
        return False
    if not oauth_config.ensure_valid_token():
        logger.error(
            f"configure_oauth_session: ensure_valid_token returned False. "
            f"Token was expired: {oauth_config.is_token_expired}, "
            f"Refresh token present for attempt: {bool(oauth_config.refresh_token)}"
        )
        return False
    session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
    logger.info("Successfully configured OAuth session for Atlassian API")
    return True
