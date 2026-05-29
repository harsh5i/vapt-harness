# Harness Generic Campaign Runner - 2026-05-26

## Purpose

The harness must not depend on a specific BB target. `campaign-run` is the
generic execution layer: it reads an adapter manifest, renders module command
templates, executes them with bounded argv-mode subprocess calls, checks
declared artifacts, and optionally validates runtime mutation coverage.

Targets remain outside the core harness. A target adapter supplies commands and
result file locations; the core runner only understands the manifest contract.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-run \
  --target <target-id> \
  --module <generic-module-id> \
  --out-dir <campaign-output-dir> \
  --validate-mutation \
  --fail
```

For harness-only smoke tests:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-run \
  --adapter vapt/harness/tests/fixtures/adapters/fixture_adapter.yaml \
  --out-dir vapt/harness/tests/results/campaign-run-fixture/orchestrator \
  --validate-mutation \
  --fail
```

## Template Variables

Adapter command argv entries may use:

- `{target_id}`
- `{adapter_id}`
- `{module_id}`
- `{local_name}`
- `{out_dir}`
- `{module_out_dir}`
- `{runtime_root}`
- `{default_target}`
- `{workspace_root}`

Unknown variables fail before execution.

## Evidence

The runner writes:

- `campaign_run.json`
- `campaign_run.md`
- `modules/<local_name>/campaign_run_execution.json`

If `--validate-mutation` is set, the runner invokes the same generic
mutation-coverage validation logic used by `mutation-coverage-check`.

## Validation Performed

The harness fixture adapter was executed with mutation validation enabled:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-run \
  --adapter vapt/harness/tests/fixtures/adapters/fixture_adapter.yaml \
  --out-dir vapt/harness/tests/results/campaign-run-fixture/orchestrator \
  --validate-mutation \
  --fail
```

Result:

- adapter check: pass
- module execution: pass
- declared artifacts: present
- mutation coverage: pass
- variants planned: `5`
- variants executed: `5`
- variants skipped: `0`

This validates the core harness execution path without relying on a BB target.
