# FastMCP 4 readiness

This directory is an advisory, public-API readiness suite for the FastMCP 4
transition. It deliberately keeps compatibility testing separate from the tool
policy security gate.

## Targets

- `published`: FastMCP 4.2.0 and MCP SDK 2.3.0, as locked by the root project.
- `upstream-main`: the same project environment with both `fastmcp` and
  `fastmcp-slim` overlaid from one exact PrefectHQ checkout.

## Suites

- `smoke`: dependency provenance and production import/startup.
- `compat-only`: public FastMCP client, mounted tool, and schema behavior. A
  green result does **not** exercise mcp-atlassian policy parity.
- `policy`: the public-protocol policy-bypass canary, the current unit policy
  contracts, and the HTTP policy checks.
- `auth`: hermetic OAuth proxy construction and DCR/PKCE integration tests.
- `protocol`: public MCP schema serialization behavior.
- `integration`: stateful and stateless HTTP against the production app, with
  the MCP SDK and a mocked Jira fetcher, including successive requests with
  different placeholder service headers.
- `broad-compat`: the existing server unit suite excluding the policy and auth
  contracts, classified against the same blocker ledger.

Run the advisory report:

```bash
uv run python scripts/fastmcp4_readiness.py run \
  --target published --suite all --advisory
```

Run the policy canary directly:

```bash
uv run pytest tests/fastmcp4/test_tool_policy_contract.py
```

`blockers.toml` is the machine-readable ledger. A known blocker that starts
passing is reported as a resolution candidate instead of silently disappearing.
Advisory mode returns zero even if the report is not green. Inspect
`summary.json` or `summary.md`; a passing suite does not establish that all
release-readiness gates have passed. Skipped contracts are reported as
incomplete and an empty selection as not run. Every suite includes dependency
provenance so results cannot silently use the wrong target. By default each
target and suite writes to its own `.readiness/<target>/<suite>/` directory.

The feature-branch workflow runs the published target on Python 3.11 and 3.13
on pushes to `feat/fastmcp-4`. It produces separate all, policy, and auth
reports and uploads JUnit, provenance, and summary artifacts. It has no live
staging profile or schedule. Existing runs can be rerun in GitHub Actions; manual
dispatch requires a workflow on the default branch and is not configured here.

For `upstream-main`, install `fastmcp` and `fastmcp-slim` as editables from the
same clean checkout, install MCP SDK 2, and set `FASTMCP_GIT_SHA` to that
checkout's exact commit. The smoke test checks the installed source paths,
checkout cleanliness, and commit identity; this overlay is advisory and is
not the production lock.

## Live staging

`scripts/mcp_wire_probe.py --staging-dc-pat` uses only the MCP SDK as its
client, starts the server as a subprocess, and performs bounded read probes
against pre-existing Jira DC and Confluence DC objects. It enforces
`READ_ONLY_MODE=true`, one concurrent Atlassian request, retries disabled, and
at most 30 requests per minute (two seconds between probe calls). It never
records credentials or Atlassian response bodies.

The staging lane is opt-in and is not run by the public CI workflow.
Until G4 passes, the staging PATs must also be read-only at the Atlassian
permission layer.

The wire probe and its safety preflight are intentionally compatible with both
FastMCP 3/MCP SDK 1 and FastMCP 4/MCP SDK 2.
