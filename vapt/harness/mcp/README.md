# Harness MCP Wrapper

Status: foundation wrapper metadata, 2026-05-25.

The harness CLI remains the stable interface. This directory provides an
MCP-facing manifest that lets an adapter expose selected harness commands as
tools without changing the core implementation.

The wrapper is intentionally conservative:

- it exposes only deterministic, artifact-first commands;
- it avoids raw shell execution entrypoints;
- it keeps network-touching commands explicit;
- it delegates execution to `.venv-vapt/bin/python vapt/harness/harness.py`.

Primary manifest:

```text
vapt/harness/mcp/mcp_manifest.json
```

Recommended adapter behavior:

1. Load the manifest.
2. Validate arguments against each tool's JSON schema.
3. Execute the configured argv from the workspace root.
4. Return stdout, stderr, exit code, and any generated artifact path.
5. Do not expose `prove --shell`, arbitrary scanner flags, or destructive
   commands without a separate rules-of-engagement gate.

