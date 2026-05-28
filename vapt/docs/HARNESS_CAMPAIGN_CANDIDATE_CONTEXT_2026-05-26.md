# Harness Campaign Candidate Context

Candidate creation now preserves campaign provenance automatically.

## Behavior

When `candidate-add` is run inside a campaign workspace, the harness walks up
from `run_dir` until it finds `campaign_start.json`. If found, the candidate is
created with:

- `evidence_kind: campaign_seed`
- `campaign_evidence.created_in_campaign: true`
- `campaign_evidence.campaign_dir`
- `campaign_evidence.campaign_start`
- optional `campaign_module`, `campaign_run`, and `campaign_gate` when provided
  or already present

This keeps candidate provenance attached at creation time. The candidate still
needs `candidate-link-campaign` after a real `campaign-run` and `campaign-gate`
pass.

## Commands

Auto-detect campaign context:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-add \
  vapt/bug_bounties/<target>/campaigns/<campaign-id>/run \
  --title "..." \
  --surface "..." \
  --weakness "CWE-863" \
  --impact "..." \
  --attacker-control "..." \
  --sink "..." \
  --campaign-module authz_matrix
```

Explicit campaign context:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-add <run-dir> \
  --campaign-dir vapt/bug_bounties/<target>/campaigns/<campaign-id> \
  --campaign-module authz_matrix \
  ...
```

Opt out only for non-campaign fixture work:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-add <run-dir> \
  --no-campaign-context \
  ...
```

## Enforcement

Once campaign evidence is present, existing promotion and report gates require:

- valid `campaign_start.json`
- valid `campaign_run.json`
- valid `campaign_gate.json`
- a campaign module name
- passed campaign gate
- passed module status in the campaign run

Until those are linked, `gate` blocks promotion with campaign blockers such as:

```text
campaign:run_missing
campaign:gate_missing
campaign:module_missing
```

## Verification

Syntax:

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py
```

Fixture acceptance:

```sh
.venv-vapt/bin/python vapt/harness/harness.py campaign-start \
  vapt/harness/tests/fixtures/targets/advisory_refresh_target.yaml \
  --out-dir vapt/harness/tests/results/campaign-candidate-linkage \
  --json

mkdir -p vapt/harness/tests/results/campaign-candidate-linkage/run

.venv-vapt/bin/python vapt/harness/harness.py candidate-add \
  vapt/harness/tests/results/campaign-candidate-linkage/run \
  --title "Campaign linkage fixture" \
  --surface "fixture" \
  --weakness "CWE-863" \
  --impact "Unauthorized access across campaign-controlled boundary" \
  --attacker-control "attacker controls fixture request" \
  --sink "fixture_sink" \
  --entrypoint "fixture_entry" \
  --trust-boundary "attacker request to protected resource" \
  --latest-affected yes \
  --cwe CWE-863 \
  --cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N" \
  --campaign-module authz_matrix
```

Expected:

- candidate has `evidence_kind: campaign_seed`
- candidate has `campaign_evidence.campaign_start`
- promotion gate blocks until campaign run/gate linkage exists
