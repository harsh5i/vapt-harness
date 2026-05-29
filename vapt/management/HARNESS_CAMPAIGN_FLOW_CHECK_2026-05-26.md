# Harness Campaign Flow Check

`campaign-flow-check` is the bundled regression path for the generic harness
campaign flow. It exists so we can test the whole discovery scaffold in one
command instead of validating each piece manually.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-flow-check --json --fail
```

Optional:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-flow-check \
  --out-dir vapt/harness/tests/results/campaign-flow-check \
  --json \
  --fail
```

## Covered Flow

The check runs a local fixture through:

1. `campaign-start`
2. advisory refresh from an offline OSV fixture
3. queue seed creation
4. `candidate-from-queue --claim`
5. generic adapter `campaign-run`
6. `campaign-gate`
7. `candidate-link-campaign`
8. queue provenance validation
9. campaign provenance validation

## Expected Artifacts

```text
vapt/harness/tests/results/campaign-flow-check/campaign/campaign_start.json
vapt/harness/tests/results/campaign-flow-check/campaign/advisory_refresh.json
vapt/harness/tests/results/campaign-flow-check/campaign/run/candidates.yaml
vapt/harness/tests/results/campaign-flow-check/campaign/run/campaign_run.json
vapt/harness/tests/results/campaign-flow-check/campaign/run/campaign_gate.json
vapt/harness/tests/results/campaign-flow-check/campaign_flow_check.json
vapt/harness/tests/results/campaign-flow-check/campaign_flow_check.md
```

## Passing Criteria

- campaign start creates advisory queue entries
- queue entry converts into a candidate
- candidate has queue provenance
- candidate has campaign provenance
- campaign run and gate pass
- `candidate-link-campaign` passes
- queue and campaign provenance gates have no blockers

The fixture does not claim a real vulnerability. It validates harness mechanics.
