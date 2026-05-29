# Harness Outcome Driven Tuning

The harness now records BB/VAPT outcomes as learning signals and uses them to
adjust future campaign planning and candidate scoring.

This does not guarantee critical vulnerabilities. It makes the harness less
static: accepted, paid, duplicate, rejected, and not-applicable results now
change future priority.

## Commands

Record an outcome:

```sh
.venv-vapt/bin/python vapt/harness/harness.py outcome-record \
  --run-dir vapt/bug_bounties/<target>/campaigns/<campaign-id>/run \
  --candidate-id CAND-001 \
  --submission-id <platform-report-id> \
  --status accepted \
  --severity high \
  --payout 1500 \
  --currency USD \
  --lesson "accepted because authz boundary had clear two-account proof"
```

Build tuning weights:

```sh
.venv-vapt/bin/python vapt/harness/harness.py outcome-tune --json
```

Run the fixture acceptance check:

```sh
.venv-vapt/bin/python vapt/harness/harness.py outcome-tune-check --json --fail
```

## Stored Signals

Each outcome records:

- platform/program
- candidate run and candidate id
- final status
- severity and payout
- target id/category/language
- weakness/CWE
- surface/sink
- campaign module
- evidence kind
- queue type
- lessons

The shared ledger remains:

```text
vapt/bug_bounties/_shared/corpus/submissions.jsonl
```

The active tuning file is:

```text
vapt/harness/corpus/outcome_tuning.yaml
```

## How Tuning Is Used

`outcome-tune` calculates adjustments by:

- campaign module
- evidence kind
- weakness/CWE
- target id

Positive outcomes increase priority. Duplicate and negative outcomes reduce it.
The adjustment is confidence-weighted down when there are fewer than two terminal
samples.

Currently used by:

- `campaign-plan`: module ranking receives module-level outcome adjustment.
- `score`: candidate quality receives bounded adjustment from weakness,
  evidence-kind, and campaign-module history.

## Verification

`outcome-tune-check` creates temporary fixture outcomes:

- accepted `authz_matrix` / `CWE-863`
- duplicate `xss_render` / `CWE-79`

Expected:

- `authz_matrix` gets a positive adjustment
- duplicate module gets a lower adjustment than accepted module
- fixture records are restored out of the shared submissions ledger after the
  check

Last verified command:

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py
.venv-vapt/bin/python vapt/harness/harness.py outcome-tune-check --json --fail
```
