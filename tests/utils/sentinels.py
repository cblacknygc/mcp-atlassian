"""Portable helpers for asserting that inert secrets do not reach output sinks."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

DEFAULT_SECRET_NAMES = (
    "client_secret",
    "access_token",
    "refresh_token",
    "authorization_code",
    "expected_state",
    "received_state",
    "authorization_header",
    "cookie_header",
    "set_cookie_header",
    "proxy_authorization_header",
    "mcp_session_id",
)


@dataclass(frozen=True)
class SecretSentinels:
    """Deterministic inert values used to detect complete-secret disclosure."""

    values: Mapping[str, str]

    @classmethod
    def create(
        cls,
        namespace: str,
        names: Iterable[str] = DEFAULT_SECRET_NAMES,
    ) -> SecretSentinels:
        """Create unique, reproducible sentinel values for one test case.

        Args:
            namespace: Test-specific namespace used to keep sentinels distinct.
            names: Logical secret names to allocate.

        Returns:
            A set of deterministic inert secret values.
        """
        values = {}
        for name in names:
            digest = hashlib.sha256(f"{namespace}\0{name}".encode()).hexdigest()[:12]
            values[name] = f"INERT_{name.upper()}_{digest}"
        return cls(values=values)

    def __getitem__(self, name: str) -> str:
        """Return the sentinel allocated to a logical secret name."""
        return self.values[name]

    def present_names(self, *outputs: object) -> list[str]:
        """Return logical names whose complete sentinels appear in outputs.

        Args:
            outputs: Text-like output values to inspect.

        Returns:
            Sorted logical names found in complete form.
        """
        combined = "\n".join(str(output) for output in outputs)
        return sorted(name for name, value in self.values.items() if value in combined)

    def assert_absent(self, *outputs: object, context: str = "captured output") -> None:
        """Assert that no complete sentinel appears in the supplied outputs.

        Args:
            outputs: Text-like output values to inspect.
            context: Human-readable sink description for assertion failures.
        """
        present = self.present_names(*outputs)
        assert not present, f"Complete secret sentinels found in {context}: {present}"


def format_log_records(records: Iterable[logging.LogRecord]) -> str:
    """Format log records, including traceback text, as an output sink.

    Args:
        records: Log records captured by a test.

    Returns:
        Fully formatted records joined with newlines.
    """
    formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
    return "\n".join(formatter.format(record) for record in records)
