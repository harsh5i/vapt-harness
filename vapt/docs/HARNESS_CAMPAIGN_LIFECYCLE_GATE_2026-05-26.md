# Harness Campaign Lifecycle Gate - 2026-05-26

## Purpose

The harness now has planners, runners, mutation validators, and dashboards.
`campaign-gate` makes that workflow enforceable. It validates the output of
`campaign-run` before a campaign is treated as acceptable evidence.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-gate <campaign-run-dir> --revalidate-mutation --fail
```

## Checks

`campaign-gate` currently enforces:

- `campaign_run.json` exists.
- campaign was not a dry run.
- `campaign-run` marked the campaign passed.
- adapter validation passed.
- all module executions passed.
- declared artifacts exist.
- declared artifacts stay inside the campaign directory.
- mutation coverage passed in `campaign-run`.
- optional `--revalidate-mutation` independently re-runs generic mutation
  coverage validation.
- evidence location respects boundaries:
  - harness fixtures stay under `vapt/harness/tests/`;
  - real target evidence stays under `vapt/bug_bounties/`;
  - non-fixture target evidence is not written into core harness folders.

## Harness Fixture Validation

Executed:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-gate \
  vapt/harness/tests/results/campaign-run-fixture/orchestrator \
  --revalidate-mutation \
  --fail
```

Result:

- gate passed
- adapter check passed
- module execution passed
- artifact containment passed
- mutation coverage passed
- evidence boundary passed

Artifacts:

- `vapt/harness/tests/results/campaign-run-fixture/orchestrator/campaign_gate.json`
- `vapt/harness/tests/results/campaign-run-fixture/orchestrator/campaign_gate.md`
