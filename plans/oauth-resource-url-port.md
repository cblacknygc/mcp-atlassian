# Port the exact OAuth resource URL override

## Goal and scope

Port `fix-oauth-resource-url` to current `cblacknygc/mcp-atlassian:main`
and open a fork-local PR targeting `main`. Do not deploy or modify Wiki Beta,
Confluence, tunnel configuration, or the separate CIMD audience overlay.

## Evaluation

- Original fix: commit `3311df9`, five files, 34 added lines; runtime code is
  11 added lines in `servers/main.py` and `servers/oauth_proxy.py`.
- Base: `66d49099188fd1cf2b204434f08be308964b7423` (Nov 16 upstream sync).
- The exact tunnel MCP resource differs from PUBLIC_BASE_URL, which must
  continue hosting authorization metadata and the upstream OAuth callback.
- Upstream PR #1839 disables forwarding `resource` to Atlassian but retains
  local resource matching. It does not replace this override.
- FastMCP 3.4.11 still derives the resource from the public base plus MCP path
  unless configured otherwise. Its resource_base_url API also appends the MCP
  path, so it is not a drop-in exact-URL replacement for this topology.
- Offline baseline reproduction: metadata and authorization fail for the
  configured tunnel resource; applying the original runtime patch fixes them.
- The Oct 22 and Oct 28 jira-dc-mcp-shim deployment reports distinguish this
  resource fix from a separate client-scoped CIMD token-endpoint audience patch.

## Implementation sequence

1. Confirm clean checkout and fetch current fork main.
2. Switch to `fix-oauth-resource-url` and merge current main without rewriting
   the published branch. Confirm the PR diff contains only the intended fix.
3. Preserve the exact-resource override, optional environment variable, and
   existing fallback when the override is absent. Preserve newer upstream
   resource-forwarding, scope, DCR, and request-hardening changes.
4. Strengthen the existing resource test with HTTP discovery metadata checks.
   Add only two tests (maximum three additional tests allowed):
   - tunnel resource accepted with the public DC callback and no resource
     forwarded to the DC authorization endpoint;
   - unrelated resource rejected even with the tunnel override configured.
   Extend the existing public-base test to pin no-override fallback behavior.
5. Run focused OAuth provider and DCR suites, excluding only the three tests
   already demonstrated to fail due to missing socksio. Run lint/typing checks
   before committing; report unrelated or environmental failures accurately.
6. Commit the regression coverage and this plan, push the branch to the fork,
   and open a PR to `cblacknygc/main` using the existing project PR template.
   Preserve checklist sections and disclose test exclusions and live-test limits.
7. Inspect initial GitHub check status. Do not merge the PR or deploy.

## Validation limits

No fresh ChatGPT consent/login or live token exchange is part of this port.
Do not claim the separate CIMD audience overlay is obsolete. Missing-socksio
failures are explicitly excluded at the user's request, not counted as passes.

## Results

- Current fork main merged cleanly; the runtime patch remains 11 added lines.
- Two additional test functions were added; existing metadata and fallback
  tests were strengthened without adding further test functions.
- Focused OAuth construction and DCR suites: 37 passed, 3 deselected for
  previously confirmed missing-socksio failures.
- Pre-commit checks on changed files passed, including Ruff and mypy.
- Initial testing without FASTMCP_HOME hit sandbox restrictions on FastMCP's
  default home storage; rerunning with disposable /private/tmp storage passed.
- Full repository and live deployment suites were not run.
