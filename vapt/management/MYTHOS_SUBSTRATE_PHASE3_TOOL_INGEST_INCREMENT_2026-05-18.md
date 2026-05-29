# Mythos Substrate Phase 3 Tool-Ingest Increment - 2026-05-18

Status: implemented and fixture-tested.

## Delivered

- Harness version: `0.3.4-phase3-tool-ingest`.
- Added `ingest-tool-scan` command.
- Supported scanner parsers:
  - `bandit`
  - `semgrep`
  - `nuclei`
  - `nuclei-jsonl`
  - `pip-audit`
  - `osv`
  - `trufflehog`
- Added fixture scanner outputs under
  `vapt/harness/tests/fixtures/tool_scans/`.
- Added optional `--create-candidates` mode that creates `auto-candidate`
  ledger entries.

## Safety Model

- Scanner output is normalized first; candidate creation is opt-in.
- `auto-candidate` status means triage seed, not vulnerability.
- Auto-created candidates use exploitability `L0 scanner signal`.
- Auto-created candidates include safety notes warning that submission requires
  manual validation, deduplication, latest-version confirmation, root cause,
  proof, and negative controls.

## Verification

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py vapt/harness/probes/*.py
.venv-vapt/bin/python vapt/harness/harness.py commands --json
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/runs/demo-pyml/smoke vapt/harness/tests/fixtures/tool_scans/bandit_sample.json --tool bandit
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/runs/demo-pyml/smoke vapt/harness/tests/fixtures/tool_scans/nuclei_sample.jsonl --tool nuclei
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/runs/demo-pyml/smoke vapt/harness/tests/fixtures/tool_scans/pip_audit_sample.json --tool pip-audit
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/runs/demo-pyml/smoke vapt/harness/tests/fixtures/tool_scans/trufflehog_sample.jsonl --tool trufflehog
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/tests/results/tool_ingest_run vapt/harness/tests/fixtures/tool_scans/pip_audit_sample.json --tool pip-audit --create-candidates
```

Representative artifacts:

- `vapt/harness/runs/demo-pyml/smoke/tool_scans/ingest/tool_ingest_bandit_20260518_104455.json`
- `vapt/harness/tests/results/tool_ingest_run/candidates.yaml`

## Remaining Work

- Add parser fixtures for Semgrep and OSV scanner once those tool outputs are
  available locally. Done on 2026-05-18 with synthetic fixtures.
- Add dedup hints and package ecosystem inference for dependency findings.
- Add optional scanner-ingest summary into dashboards.
