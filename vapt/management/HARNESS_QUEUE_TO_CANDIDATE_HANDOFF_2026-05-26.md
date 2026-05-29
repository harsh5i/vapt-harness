# Harness Queue To Candidate Handoff

Watch/advisory queue entries can now be converted directly into candidates.
This closes the manual drift between `campaign-start --refresh-advisories`,
watch queue seeds, and the candidate ledger.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-from-queue \
  <run-dir> \
  <target-id>/<queue-entry-id> \
  --claim \
  --campaign-module <module>
```

The command accepts the same refinement-style overrides as `candidate-add`:

- `--title`
- `--surface`
- `--weakness`
- `--impact`
- `--attacker-control`
- `--sink`
- `--entrypoint`
- `--trust-boundary`
- `--latest-affected`
- `--cwe`
- `--cvss`
- `--reference-sources`
- `--campaign-dir`
- `--campaign-run`
- `--campaign-gate`

Use `--seed-index` when a queue entry has more than one candidate seed.

## Behavior

`candidate-from-queue`:

- requires a claimed queue entry, unless `--claim` is provided
- creates a candidate from `candidate_seeds[seed_index]`
- extracts CWE/advisory references when present
- records `queue_id`, `queue_entry`, and `queue_evidence`
- marks the queue entry `converted`
- writes `candidate_id`, `run_dir`, and `converted_at` back into the queue entry
- auto-attaches `campaign_start` context when the run is inside a campaign
  workspace

`campaign-start --refresh-advisories` now writes `candidate-from-queue ... --claim`
commands directly into `NEXT_COMMANDS.md` for new advisory queue entries.

## Enforcement

Promotion and report gates now validate queue provenance when a candidate has
queue evidence:

- queue id must exist
- queue entry artifact must exist
- queue id must match the artifact
- queue entry must be `status: converted`
- queue entry candidate id must match the candidate when present

Queue-derived candidates still need normal proof, latest-version confirmation,
negative controls, campaign run/gate linkage, and report readiness. Queue
conversion creates a triage candidate, not a reportable vulnerability.

## Verification

Syntax:

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py
```

Fixture flow:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start \
  vapt/harness/tests/fixtures/targets/advisory_refresh_target.yaml \
  --out-dir vapt/harness/tests/results/queue-to-candidate-fixture \
  --refresh-advisories \
  --refresh-fixture vapt/harness/tests/fixtures/advisories/osv_phase4_sample.json \
  --refresh-ephemeral-state \
  --json

.venv-vapt/bin/python vapt/harness/harness.py candidate-from-queue \
  vapt/harness/tests/results/queue-to-candidate-fixture/run \
  advisory-refresh-fixture/<queue-id> \
  --claim \
  --campaign-module authz_matrix \
  --json
```

Expected:

- queue entry status becomes `converted`
- queue entry records `candidate_id`
- candidate has `evidence_kind: queue_campaign_seed`
- candidate has `queue_evidence.created_from_queue: true`
- candidate has `campaign_evidence.campaign_start`
- `gate` has no queue provenance blocker, but still blocks missing proof/runtime
  evidence
