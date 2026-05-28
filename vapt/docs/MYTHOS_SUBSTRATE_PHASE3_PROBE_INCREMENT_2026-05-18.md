# Mythos Substrate Phase 3 Probe Increment - 2026-05-18

Status: implemented and smoke-tested.

## Delivered

- Expanded the reusable probe library to eight probe classes:
  - `websocket_authz_drift`
  - `idor_diff`
  - `serialization_rce`
  - `ssrf_outbound`
  - `parser_canonicalization`
  - `prompt_injection_to_tool`
  - `rag_poisoning_durability`
  - `model_card_local_file_read`
- Added `probes-test` to run probes against captive fixture candidates.
- Added `vapt/harness/tests/fixtures/probe_candidates.yaml`.
- Added doctrine stubs for:
  - `idor_diff`
  - `rag_poisoning_durability`
  - `model_card_local_file_read`
- Added `vapt/harness/probes/README.md`.
- Updated PoC scaffolds to run cleanly without modification while clearly
  marking themselves as `scaffold_only` and `ready_for_submission: false`.

## Verification

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py vapt/harness/probes/*.py
.venv-vapt/bin/python vapt/harness/harness.py probes
.venv-vapt/bin/python vapt/harness/harness.py probes-test
.venv-vapt/bin/python vapt/harness/harness.py scaffold-poc idor_diff demo-target
.venv-vapt/bin/python vapt/pocs/demo-target/2026-05-18/poc_idor_diff.py
```

`probes-test` wrote:

- `vapt/harness/tests/results/probe_smoke_20260518_100851.json`

All fixture probes passed.

## Remaining Phase 3 Work

- Add full tool wrappers for CodeQL, Bandit, pip-audit, OSV package scans,
  TruffleHog/detect-secrets, TLS, and bounded nuclei.
- Add captive lab fixtures that exercise actual local vulnerable services, not
  only candidate-shape fixtures.
- Make `refine` support model/operator-supplied field updates between
  iterations rather than only recording probe gaps.
