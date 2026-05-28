# Mythos Substrate Phase 4 Foundation

Date: 2026-05-25
Harness version: `0.4.1-phase4-hardening`

## Status

Phase 4 foundation and hardening are implemented. The harness now has the
watch/queue substrate, live remote polling validation, advisory cross-reference,
patch-window enrichment, bounded daemon soak checks, and an MCP-facing manifest.
The only item that cannot be compressed into an instant check is the empirical
twenty-four-hour wall-clock daemon soak; the command support exists and can be
run with `--require-24h`.

## Delivered

- Watch profiles under `vapt/harness/watches/<target_id>.yaml`.
- Watch state under `vapt/harness/watches/state/<target_id>.json`.
- Queue entries under `vapt/harness/queue/<target_id>/*.yaml`.
- `watch-add` for `github_commits`, `github_releases`, `ghsa_advisories`, and
  `osv_advisories` source kinds.
- `watch-list` for profile and queue-depth visibility.
- `watch-tick` for one polling pass.
- `watch-daemon` for repeated polling with heartbeat logging and SIGTERM/SIGINT
  handling.
- `queue` for pending queue listing.
- `queue claim` for claiming a generated seed and binding it to a run.
- Offline local-git polling for commit and release sources through `repo_path`.
- Offline advisory polling through JSON/YAML fixtures.
- Opt-in remote polling for GitHub commits, GitHub releases, GHSA advisories,
  and OSV advisories when a source is explicitly marked `allow_network`.
- `phase4-check` acceptance test.
- `phase4-remote-check` live validation against GitHub and OSV/GHSA endpoints.
- `phase4-soak-check` bounded daemon soak check, with optional
  `--require-24h`.
- Advisory matching by package, package alias, ecosystem, CWE, and trigger-text
  overlap.
- Advisory affected-version metadata extraction from OSV-style records.
- Patch-window enrichment from local git repos when advisories include
  `fixed_commit` or `patch_range`.
- MCP-facing manifest under `vapt/harness/mcp/mcp_manifest.json`.

## Acceptance Evidence

Latest acceptance artifact:

```text
vapt/harness/tests/results/phase4_check_20260525_021530.md
vapt/harness/tests/results/phase4_remote_check_20260525_021345.md
vapt/harness/tests/results/phase4_soak_check_20260525_021532.md
```

The check verified:

- watch profile creation
- commit-diff queue entry creation from a fresh local git commit
- advisory queue entry creation from an OSV-style fixture
- patch-window enrichment from a fixed commit
- required Phase 4 commands present in the CLI
- live remote GitHub commit and release polling
- live OSV/GHSA advisory polling
- bounded daemon heartbeat operation

## Operating Model

Watch profiles surface candidate seeds. They do not create reportable findings.
The operator or model must still claim a queue item, create or attach a normal
run, and pass the standard harness workflow:

```text
candidate -> deduped -> promoted -> proved -> root_cause_recorded
-> variant_searched -> patch_diffed -> report_ready -> submitted
```

## Remaining Empirical Work

- Run a literal twenty-four-hour daemon soak:

```sh
.venv-vapt/bin/python vapt/harness/harness.py phase4-soak-check \
  --target phase4_fixture \
  --seconds 86400 \
  --iterations 0 \
  --interval-seconds 1800 \
  --require-24h
```

This is not marked as passed until 24 real hours elapse.
