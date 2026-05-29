# Harness Campaign Start Advisory Refresh

`campaign-start --refresh-advisories` now performs a bounded advisory refresh
before it writes the campaign plan. This is generic harness behavior, not a
target-specific adapter.

## Purpose

- Pull fresh OSV/GHSA-style advisory context into the existing watch queue.
- Write `advisory_refresh.md` and `advisory_refresh.json` inside the campaign
  workspace.
- Add executable `queue claim ... --run-dir ...` commands to
  `NEXT_COMMANDS.md` for newly created queue entries.
- Feed `patch-first-plan` with fresh queue seeds before broad scanning starts.

## Inputs

The command uses target profile metadata when present:

- `osv_ecosystem`
- `osv_package`
- `repo_url`
- `source_path` or `repo_path`
- `package_aliases`
- `trigger_patterns` or `category`

If explicit metadata is missing, the harness makes conservative package-source
inferences from language and repository URL:

- Go repositories become `Go` / `github.com/<owner>/<repo>` for OSV.
- Python targets use `PyPI` and target `name` or `id`.
- JavaScript/TypeScript targets use `npm` and target `name` or `id`.

Operators can override inference:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start <target> \
  --refresh-advisories \
  --refresh-source both \
  --refresh-ecosystem PyPI \
  --refresh-package demo-pyml
```

## Network And State

- Live polling is enabled only when `--refresh-advisories` is passed.
- `--refresh-fixture <path>` switches the refresh to a local fixture and disables
  network for that source.
- `--refresh-seed` defaults to enabled so a campaign start captures current
  advisories as seeds. Use `--no-refresh-seed` for state-only initialization.
- Watch state is persisted by default. Use `--refresh-ephemeral-state` for smoke
  tests or one-off checks that should not update watch state.

GHSA ecosystem names are normalized separately from OSV ecosystem names. For
example, OSV uses `PyPI`; GHSA expects `pip`.

## Artifacts

Inside the campaign workspace:

- `advisory_refresh.json`: source list, poll results, new queue entries, pending
  queue depth, warnings, and state persistence status.
- `advisory_refresh.md`: operator-readable summary.
- `campaign_start.json`: embeds the advisory refresh summary.
- `NEXT_COMMANDS.md`: includes queue-claim commands when fresh queue entries
  were created.

Queue entries remain in the generic watch queue:

```text
vapt/harness/queue/<target_id>/*.yaml
```

The queue entries are candidate seeds only. They are not reportable findings
until claimed, deduplicated, proven, scored, and report-gated.

## Verification

Syntax:

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py
```

Offline fixture acceptance:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start \
  vapt/harness/tests/fixtures/targets/advisory_refresh_target.yaml \
  --out-dir vapt/harness/tests/results/campaign-start-refresh-fixture \
  --refresh-advisories \
  --refresh-fixture vapt/harness/tests/fixtures/advisories/osv_phase4_sample.json \
  --refresh-ephemeral-state \
  --json
```

Expected result:

- `advisory_refresh.status=completed`
- two fixture advisories queued
- one fixture advisory has patch enrichment
- `NEXT_COMMANDS.md` contains two queue-claim commands

Live GHSA smoke:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start demo-pyml \
  --out-dir vapt/harness/tests/results/campaign-start-demo-pyml-ghsa-smoke \
  --refresh-advisories \
  --refresh-source ghsa \
  --refresh-ephemeral-state \
  --json
```

Expected result:

- GHSA source uses `ecosystem=pip`
- polling completes without GitHub API 422
- zero or more queue entries are valid; no finding is implied by queue depth
