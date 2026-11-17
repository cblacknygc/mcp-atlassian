#!/usr/bin/env python3
"""Run and summarize the advisory FastMCP 4 readiness suites."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from importlib import metadata
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlparse

import tomli

ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "tests" / "fastmcp4"
PROVENANCE_CONTRACT = TEST_ROOT / "test_dependency_provenance.py"
POLICY_CONTRACT = ROOT / "tests" / "unit" / "servers" / "test_tool_policy_contract.py"
AUTH_CONTRACTS = (
    ROOT / "tests" / "unit" / "servers" / "test_oauth_proxy_build.py",
    ROOT / "tests" / "unit" / "servers" / "test_oauth_proxy_dcr_e2e.py",
)
BLOCKER_FILE = TEST_ROOT / "blockers.toml"
SUITE_MARKERS = {
    "smoke": "fastmcp4_smoke",
    "compat-only": "fastmcp4_compat",
    "policy": "fastmcp4_policy",
    "protocol": "fastmcp4_protocol",
    "integration": "fastmcp4_integration",
}
PROVENANCE_PACKAGES = (
    "mcp-atlassian",
    "fastmcp",
    "fastmcp-slim",
    "mcp",
    "mcp-types",
    "pydantic",
    "starlette",
)


def _git_output(*args: str) -> str | None:
    """Return one line of Git output, or None outside a Git checkout."""
    completed = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or None


def _fastmcp_git_sha() -> str | None:
    """Resolve the overlaid editable FastMCP checkout to an exact Git SHA."""
    try:
        direct_url = metadata.distribution("fastmcp").read_text("direct_url.json")
    except metadata.PackageNotFoundError:
        return None
    if not direct_url:
        return None
    source_url = json.loads(direct_url).get("url", "")
    if not source_url.startswith("file:"):
        return None
    source = Path(unquote(urlparse(source_url).path)).resolve()
    completed = subprocess.run(  # noqa: S603
        ["git", "-C", str(source), "rev-parse", "HEAD"],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or None


def _provenance(target: str) -> dict[str, Any]:
    """Collect dependency and source provenance without importing FastMCP."""
    packages: dict[str, dict[str, str]] = {}
    for name in PROVENANCE_PACKAGES:
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            packages[name] = {"version": "not-installed", "location": ""}
            continue
        direct_url = distribution.read_text("direct_url.json")
        source = ""
        if direct_url:
            details = json.loads(direct_url)
            parsed = urlparse(details.get("url", ""))
            if (
                details.get("dir_info", {}).get("editable") is True
                and parsed.scheme == "file"
                and parsed.netloc in {"", "localhost"}
            ):
                source = str(Path(unquote(parsed.path)).resolve())
        packages[name] = {
            "version": distribution.version,
            "location": str(distribution.locate_file("")),
            "editable_source": source,
        }

    lock_path = ROOT / "uv.lock"
    actual_fastmcp_sha = _fastmcp_git_sha()
    return {
        "target": target,
        "python": sys.version,
        "executable": sys.executable,
        "mcp_atlassian_git_sha": _git_output("rev-parse", "HEAD"),
        "mcp_atlassian_git_status": _git_output("status", "--short"),
        "fastmcp_git_sha": actual_fastmcp_sha,
        "expected_fastmcp_git_sha": (
            os.getenv("FASTMCP_GIT_SHA") or actual_fastmcp_sha
        ),
        "uv_lock_sha256": (
            hashlib.sha256(lock_path.read_bytes()).hexdigest()
            if lock_path.exists()
            else None
        ),
        "fastmcp_mcp_camelcase_compat": os.getenv("FASTMCP_MCP_CAMELCASE_COMPAT"),
        "packages": packages,
    }


def _load_blockers() -> dict[str, dict[str, Any]]:
    """Load the stable blocker ledger."""
    with BLOCKER_FILE.open("rb") as handle:
        data = tomli.load(handle)
    return cast(dict[str, dict[str, Any]], data["blockers"])


def _junit_cases(path: Path) -> list[dict[str, str]]:
    """Parse compact testcase outcomes from pytest JUnit XML."""
    root = ET.parse(path).getroot()  # noqa: S314
    cases: list[dict[str, str]] = []
    for testcase in root.iter("testcase"):
        outcome = "passed"
        detail = ""
        for child in testcase:
            if child.tag in {"failure", "error", "skipped"}:
                outcome = "failed" if child.tag in {"failure", "error"} else "skipped"
                detail = child.get("message", "")
                break
        cases.append(
            {
                "classname": testcase.get("classname", ""),
                "name": testcase.get("name", ""),
                "outcome": outcome,
                "detail": detail,
            }
        )
    return cases


def _matching_blocker(
    testcase: dict[str, str], blockers: dict[str, dict[str, Any]]
) -> str | None:
    """Match a JUnit testcase to a stable blocker ID."""
    for blocker_id, blocker in blockers.items():
        base_name = testcase["name"].split("[", maxsplit=1)[0]
        for node_id in blocker.get("tests", []):
            file_name, _, test_name = str(node_id).partition("::")
            module_name = file_name.removesuffix(".py").replace("/", ".")
            if base_name == test_name.rsplit("::", maxsplit=1)[-1] and (
                testcase["classname"] == module_name
                or testcase["classname"].startswith(f"{module_name}.")
            ):
                return blocker_id
    return None


def _build_summary(
    target: str,
    suite: str,
    exit_code: int,
    cases: list[dict[str, str]],
    blockers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Classify known blockers, resolution candidates, and regressions."""
    known_failures: list[str] = []
    resolution_candidates: list[str] = []
    regressions: list[str] = []
    skipped: list[str] = []
    for testcase in cases:
        blocker_id = _matching_blocker(testcase, blockers)
        if testcase["outcome"] == "failed":
            if blocker_id:
                known_failures.append(blocker_id)
            else:
                regressions.append(f"{testcase['classname']}::{testcase['name']}")
        elif testcase["outcome"] == "passed" and blocker_id:
            resolution_candidates.append(blocker_id)
        elif testcase["outcome"] == "skipped":
            skipped.append(f"{testcase['classname']}::{testcase['name']}")

    if not cases and exit_code in {0, 5}:
        status = "not-run"
    elif regressions or exit_code not in {0, 1} or (exit_code and not known_failures):
        status = "regression"
    elif known_failures:
        status = "known-blocked"
    elif skipped:
        status = "incomplete"
    else:
        status = "passed"

    return {
        "target": target,
        "suite": suite,
        "status": status,
        "pytest_exit_code": exit_code,
        "counts": {
            "passed": sum(case["outcome"] == "passed" for case in cases),
            "failed": sum(case["outcome"] == "failed" for case in cases),
            "skipped": sum(case["outcome"] == "skipped" for case in cases),
        },
        "known_failures": sorted(set(known_failures)),
        "resolution_candidates": sorted(set(resolution_candidates)),
        "regressions": regressions,
        "skipped": skipped,
    }


def _markdown(
    summary: dict[str, Any],
    provenance: dict[str, Any],
    blockers: dict[str, dict[str, Any]],
) -> str:
    """Render the human-readable one-page readiness summary."""
    packages = provenance["packages"]
    lines = [
        f"# FastMCP 4 readiness: {summary['target']}",
        "",
        f"**Status:** `{summary['status']}`  ",
        f"**Suite:** `{summary['suite']}`  ",
        (
            "**Versions:** "
            f"FastMCP `{packages['fastmcp']['version']}`, "
            f"fastmcp-slim `{packages['fastmcp-slim']['version']}`, "
            f"MCP `{packages['mcp']['version']}`"
        ),
        "",
        "## Results",
        "",
        (
            f"- Passed: {summary['counts']['passed']}; "
            f"failed: {summary['counts']['failed']}; "
            f"skipped: {summary['counts']['skipped']}."
        ),
    ]
    for blocker_id in summary["known_failures"]:
        blocker = blockers[blocker_id]
        lines.append(
            f"- **{blocker_id} / {blocker['gate']}:** {blocker['description']}"
        )
    for blocker_id in summary["resolution_candidates"]:
        lines.append(f"- **Resolution candidate:** {blocker_id} now passes.")
    for regression in summary["regressions"]:
        lines.append(f"- **Unclassified regression:** `{regression}`")
    if summary["skipped"]:
        lines.append(f"- Skipped contracts: {len(summary['skipped'])}.")

    if summary["suite"] in {"compat-only", "broad-compat"}:
        lines.extend(
            [
                "",
                "> Compat-only result. Tool-policy security parity was not "
                "exercised by compatibility tests. G4 remains a release blocker.",
            ]
        )
    elif summary["suite"] == "all":
        lines.extend(
            [
                "",
                "> This advisory suite includes policy checks, but does not establish "
                "all release-readiness gates. G4 remains a release blocker until "
                "the full gate is assessed.",
            ]
        )
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- mcp-atlassian SHA: `{provenance['mcp_atlassian_git_sha']}`",
            f"- FastMCP upstream SHA: `{provenance['fastmcp_git_sha'] or 'n/a'}`",
            "- Expected FastMCP SHA: "
            f"`{provenance.get('expected_fastmcp_git_sha') or 'n/a'}`",
            f"- Python executable: `{provenance['executable']}`",
            f"- uv.lock SHA-256: `{provenance.get('uv_lock_sha256') or 'n/a'}`",
        ]
    )
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> int:
    """Run pytest, classify results, and write durable evidence."""
    output_dir = (
        args.output_dir or ROOT / ".readiness" / args.target / args.suite
    ).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    junit_path = output_dir / "junit.xml"
    junit_path.unlink(missing_ok=True)
    provenance = _provenance(args.target)
    (output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.suite == "auth":
        test_paths = [PROVENANCE_CONTRACT, *AUTH_CONTRACTS]
    elif args.suite == "broad-compat":
        test_paths = [PROVENANCE_CONTRACT, ROOT / "tests" / "unit" / "servers"]
    else:
        test_paths = [TEST_ROOT]
    if args.suite in {"all", "policy"}:
        test_paths.append(POLICY_CONTRACT)
    if args.suite == "all":
        test_paths.extend(AUTH_CONTRACTS)
    command = [
        sys.executable,
        "-m",
        "pytest",
        *(str(path) for path in test_paths),
        f"--junitxml={junit_path}",
    ]
    if args.suite not in {"all", "auth", "broad-compat"}:
        marker = SUITE_MARKERS[args.suite]
        expression = marker if args.suite == "smoke" else f"{marker} or fastmcp4_smoke"
        command.extend(["-m", expression])
    elif args.suite == "broad-compat":
        command.extend(["-m", "not fastmcp4_policy"])
        for path in AUTH_CONTRACTS:
            command.extend(["--ignore", str(path)])

    env = os.environ.copy()
    env["FASTMCP4_TARGET"] = args.target
    env["FASTMCP_HOME"] = str(output_dir / "fastmcp-home")
    fastmcp_git_sha = provenance.get("expected_fastmcp_git_sha")
    if fastmcp_git_sha:
        env["FASTMCP_GIT_SHA"] = fastmcp_git_sha
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        check=False,
        env=env,
    )
    cases = _junit_cases(junit_path) if junit_path.exists() else []
    blockers = _load_blockers()
    summary = _build_summary(
        args.target,
        args.suite,
        completed.returncode,
        cases,
        blockers,
    )
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown = _markdown(summary, provenance, blockers)
    (output_dir / "summary.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0 if args.advisory else completed.returncode


def _parser() -> argparse.ArgumentParser:
    """Build the readiness command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument(
        "--target",
        choices=("published", "upstream-main"),
        required=True,
    )
    run_parser.add_argument(
        "--suite",
        choices=("all", "auth", "broad-compat", *SUITE_MARKERS),
        default="all",
    )
    run_parser.add_argument("--output-dir", type=Path)
    run_parser.add_argument("--advisory", action="store_true")
    run_parser.set_defaults(handler=run)
    return parser


def main() -> int:
    """Run the selected command."""
    args = _parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
