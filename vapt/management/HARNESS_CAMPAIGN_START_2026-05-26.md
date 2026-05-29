# Harness Campaign Start - 2026-05-26

## Purpose

`campaign-start` is the standard entry point for a new BB/VAPT campaign. It
creates the campaign workspace and generates the first required planning
artifacts before any runtime testing or candidate promotion.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start <target-id> --name <campaign-id>
```

Default output:

```text
vapt/bug_bounties/<target>/campaigns/<campaign-id>/
```

## Artifacts

Always created:

- `campaign_start.json`
- `campaign_start.md`
- `NEXT_COMMANDS.md`
- `target_snapshot.json`
- `candidates.yaml`
- `patch_first_plan.md`
- `campaign_plan.md`

Created when a target adapter exists:

- `adapter_check.md`
- `mutation_plan.md`

## Next Commands

When an adapter exists, `NEXT_COMMANDS.md` starts with:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-run --target <target> --out-dir <campaign-dir>/run --validate-mutation --fail
.venv-vapt/bin/python vapt/harness/harness.py campaign-gate <campaign-dir>/run --revalidate-mutation --fail
```

When no adapter exists, `NEXT_COMMANDS.md` tells the operator to create or
validate an adapter before runtime campaign execution.

## Validation

Adapter-missing path validated with:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start demo-pyml --name harness-start-smoke --json
```

Adapter-present path validated with:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start grafana-oss --name harness-start-smoke --json
```

Both commands produced machine-readable JSON and target-local campaign
workspaces under `vapt/bug_bounties/<target>/campaigns/`.
