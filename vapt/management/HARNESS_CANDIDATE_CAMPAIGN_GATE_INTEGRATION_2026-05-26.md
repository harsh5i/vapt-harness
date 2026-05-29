# Harness Candidate Campaign Gate Integration - 2026-05-26

## Purpose

Runtime campaign evidence should not be treated as report-ready unless it came
through the controlled campaign lifecycle. This integration links candidates to
`campaign-run` / `campaign-gate` artifacts and makes promotion/report gates
aware of that link.

## New Candidate Fields

Runtime campaign candidates may now carry:

- `evidence_kind: runtime_campaign`
- `campaign_run`
- `campaign_gate`
- `campaign_module`
- `campaign_evidence`

`campaign_evidence` records the linked campaign directory, campaign run JSON,
campaign gate JSON, module name, gate result, module status, and link time.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-link-campaign \
  <run-dir> <candidate-id> \
  --campaign-dir <campaign-run-dir> \
  --module <generic-module-id-or-local-name> \
  --fail
```

By default, the command requires:

- `campaign_run.json` exists.
- `campaign_gate.json` exists.
- campaign gate passed.
- selected module exists in `campaign_run.json`.
- selected module passed.

## Gate Behavior

For candidates marked as runtime campaign evidence, `gate` and `report-gate`
now require:

- campaign run artifact is linked and readable.
- campaign gate artifact is linked and readable.
- campaign gate passed.
- linked module is present in the campaign run.
- linked module passed.
- campaign gate directory matches the campaign run directory.

Candidates that are not runtime campaign evidence are not forced through this
path.

## Fixture Validation

Created a harness-only fixture candidate under:

- `vapt/harness/tests/results/candidate-campaign-gate-fixture/`

Linked it to the harness fixture campaign:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-link-campaign \
  vapt/harness/tests/results/candidate-campaign-gate-fixture \
  CAND-001 \
  --campaign-dir vapt/harness/tests/results/campaign-run-fixture/orchestrator \
  --module authz_matrix \
  --json \
  --fail
```

Result:

- campaign link passed.
- candidate ledger now records `evidence_kind: runtime_campaign`.
- `report-gate` emits no campaign blockers for the linked fixture candidate.
- `report-gate` still blocks on unrelated proof/dedup requirements, as
  expected.
