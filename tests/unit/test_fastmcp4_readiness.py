"""Regression tests for the FastMCP 4 advisory report runner."""

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import fastmcp4_readiness as readiness


def _case(classname: str, name: str, outcome: str) -> dict[str, str]:
    return {"classname": classname, "name": name, "outcome": outcome, "detail": ""}


def test_blocker_matching_requires_the_recorded_test_module() -> None:
    blockers: dict[str, dict[str, Any]] = {
        "POL-001": {"tests": ["tests/fastmcp4/test_policy.py::test_hidden"]}
    }
    assert (
        readiness._matching_blocker(
            _case("tests.fastmcp4.test_policy", "test_hidden[asyncio]", "failed"),
            blockers,
        )
        == "POL-001"
    )
    assert (
        readiness._matching_blocker(
            _case("tests.other.test_policy", "test_hidden", "failed"), blockers
        )
        is None
    )


@pytest.mark.parametrize(
    ("exit_code", "cases", "expected"),
    [
        (0, [], "not-run"),
        (5, [], "not-run"),
        (2, [], "regression"),
        (0, [_case("test_module", "test_one", "skipped")], "incomplete"),
        (
            0,
            [
                _case("test_module", "test_one", "passed"),
                _case("test_module", "test_two", "skipped"),
            ],
            "incomplete",
        ),
        (0, [_case("test_module", "test_one", "passed")], "passed"),
    ],
)
def test_summary_does_not_report_unrun_or_skipped_tests_as_passed(
    exit_code: int, cases: list[dict[str, str]], expected: str
) -> None:
    summary = readiness._build_summary("published", "policy", exit_code, cases, {})
    assert summary["status"] == expected


def test_collection_failure_is_not_hidden_by_a_known_failure() -> None:
    blockers: dict[str, dict[str, Any]] = {
        "POL-001": {"tests": ["tests/fastmcp4/test_policy.py::test_hidden"]}
    }
    cases = [_case("tests.fastmcp4.test_policy", "test_hidden", "failed")]
    summary = readiness._build_summary("published", "policy", 2, cases, blockers)
    assert summary["status"] == "regression"
    assert summary["known_failures"] == ["POL-001"]


def test_all_report_does_not_mislabel_policy_checks_as_compat_only() -> None:
    summary = readiness._build_summary(
        "published", "all", 0, [_case("test_module", "test_one", "passed")], {}
    )
    provenance = {
        "packages": {
            name: {"version": "test"} for name in ("fastmcp", "fastmcp-slim", "mcp")
        },
        "mcp_atlassian_git_sha": "test",
        "fastmcp_git_sha": None,
        "executable": "test-python",
    }
    report = readiness._markdown(summary, provenance, {})
    assert "includes policy checks" in report
    assert "Compat-only result" not in report
    assert "G4 remains a release blocker" in report


def test_default_reports_do_not_overwrite_other_suites(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(readiness, "ROOT", tmp_path)
    monkeypatch.setattr(readiness, "_provenance", lambda target: {})
    monkeypatch.setattr(readiness, "_load_blockers", lambda: {})
    monkeypatch.setattr(readiness, "_markdown", lambda *args: "report\n")
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=5),
    )
    for suite in ("policy", "auth"):
        args = argparse.Namespace(
            output_dir=None, target="published", suite=suite, advisory=True
        )
        assert readiness.run(args) == 0
    for suite in ("policy", "auth"):
        assert (tmp_path / ".readiness" / "published" / suite / "summary.json").exists()


@pytest.mark.parametrize(
    "suite",
    ["all", "auth", "policy", "broad-compat", "integration", "protocol", "compat-only"],
)
def test_run_selects_policy_separately_and_discards_stale_junit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, suite: str
) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "junit.xml").write_text(
        '<testsuite><testcase classname="old" name="old"/></testsuite>'
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        assert not (output / "junit.xml").exists()
        return SimpleNamespace(returncode=5)

    monkeypatch.setattr(readiness.subprocess, "run", fake_run)
    monkeypatch.setattr(readiness, "_load_blockers", lambda: {})
    monkeypatch.setattr(
        readiness,
        "_provenance",
        lambda target: {
            "target": target,
            "packages": {
                name: {"version": "test"} for name in ("fastmcp", "fastmcp-slim", "mcp")
            },
            "mcp_atlassian_git_sha": "test",
            "fastmcp_git_sha": None,
            "executable": "test-python",
        },
    )
    args = argparse.Namespace(
        output_dir=output, target="published", suite=suite, advisory=True
    )
    assert readiness.run(args) == 0
    assert json.loads((output / "summary.json").read_text())["status"] == "not-run"
    command = calls[0]
    if suite in {"all", "policy"}:
        assert str(readiness.POLICY_CONTRACT) in command
        if suite == "policy":
            assert "fastmcp4_policy or fastmcp4_smoke" in command
    elif suite == "broad-compat":
        assert str(readiness.POLICY_CONTRACT) not in command
        assert str(readiness.PROVENANCE_CONTRACT) in command
        assert "not fastmcp4_policy" in command
        for path in readiness.AUTH_CONTRACTS:
            assert str(path) in command
    elif suite == "auth":
        assert str(readiness.POLICY_CONTRACT) not in command
        assert str(readiness.PROVENANCE_CONTRACT) in command
        for path in readiness.AUTH_CONTRACTS:
            assert str(path) in command
    else:
        assert f"{readiness.SUITE_MARKERS[suite]} or fastmcp4_smoke" in command
