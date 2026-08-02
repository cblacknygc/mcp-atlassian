# FastMCP 4 readiness

This directory is an advisory, public-API readiness suite for the FastMCP 4
transition. It deliberately keeps compatibility testing separate from the tool
policy security gate.

## Targets

- `published`: the exact FastMCP prerelease and paired MCP SDK prerelease locked
  by the root project.
- `upstream-main`: the same project environment with both `fastmcp` and
  `fastmcp-slim` overlaid from one exact PrefectHQ checkout.

## Suites

- `smoke`: dependency provenance and production import/startup.
- `compat-only`: public FastMCP client, mounted tool, and schema behavior. A
  green result does **not** exercise mcp-atlassian policy parity.
- `policy`: the public-protocol policy-bypass canary.
- `protocol`: public MCP schema serialization behavior.
- `broad-compat`: the existing server unit suite, classified against the same
  blocker ledger.

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

## Live staging

`scripts/mcp_wire_probe.py --staging-stdio-pat` uses only the MCP SDK as its
client, starts the server as a subprocess, and performs bounded read probes
against pre-existing Jira DC and Confluence DC objects. It enforces
`READ_ONLY_MODE=true`, one concurrent Atlassian request, retries disabled, and
at most 30 requests per minute (two seconds between probe calls). It never
records credentials or Atlassian response bodies.

The staging lane is opt-in and is not run by the public CI workflow.
Until G4 passes, the staging PATs must also be read-only at the Atlassian
permission layer.

The wire probe and its safety preflight are intentionally compatible with both
the FastMCP 3.4.4/MCP SDK 1 baseline and the FastMCP 4/MCP SDK 2 target.
