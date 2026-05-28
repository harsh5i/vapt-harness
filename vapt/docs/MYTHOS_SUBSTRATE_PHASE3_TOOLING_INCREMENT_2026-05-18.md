# Mythos Substrate Phase 3 Tooling Increment - 2026-05-18

Status: implemented and parser-smoke-tested.

## Delivered

- Harness version: `0.3.3-phase3-tools`.
- Added streamed tool-scan evidence helper:
  - raw stdout/stderr
  - capped stdout/stderr views
  - status file
  - command JSON
  - summary JSON
- Added missing-tool refusal artifacts as `.missing.json`.
- Added scanner wrappers:
  - `scan-bandit`
  - `scan-codeql`
  - `scan-pip-audit`
  - `scan-osv`
  - `scan-trufflehog`
  - `scan-tls`
  - `scan-nuclei`
- Added `tool-health` for no-scan local tool availability checks.
- Updated `scan-semgrep` to use the same streamed evidence helper.
- Installed pip-based scanner tools into `.venv-vapt` where possible:
  - `bandit==1.9.4`
  - `pip-audit==2.10.0`
  - `sslyze==6.3.1`
  - `semgrep==1.163.0`
- Updated `vapt/env/requirements-vapt.txt` and regenerated
  `vapt/env/requirements-vapt.lock`.

## Safety Defaults

- Scanner output is streamed to disk rather than buffered fully in memory.
- Long-running tools are killed by process group on timeout.
- Missing tools write explicit refusal artifacts and exit non-zero.
- `scan-nuclei` refuses to run without explicit templates unless
  `--allow-default-templates` is supplied.
- No external scan was run during implementation verification.
- 2026-05-25 status: Semgrep is operational through harness-managed
  workspace-local `HOME` and certificate-bundle environment settings.

## Verification

```sh
.venv-vapt/bin/python -m py_compile vapt/harness/harness.py vapt/harness/probes/*.py
.venv-vapt/bin/python vapt/harness/harness.py commands --json
.venv-vapt/bin/python vapt/harness/harness.py scan-bandit --help
.venv-vapt/bin/python vapt/harness/harness.py scan-pip-audit --help
.venv-vapt/bin/python vapt/harness/harness.py scan-osv --help
.venv-vapt/bin/python vapt/harness/harness.py scan-trufflehog --help
.venv-vapt/bin/python vapt/harness/harness.py scan-tls --help
.venv-vapt/bin/python vapt/harness/harness.py scan-nuclei --help
.venv-vapt/bin/python vapt/harness/harness.py tool-health --json --versions
.venv-vapt/bin/python vapt/harness/harness.py scan-nuclei vapt/harness/runs/demo-pyml/smoke --url http://127.0.0.1
```

The final command intentionally refused execution because no explicit nuclei
template was provided and wrote:

- `vapt/harness/runs/demo-pyml/smoke/tool_scans/nuclei/nuclei_20260518_103732.policy.json`

## Remaining Work After Phase 3 Gate

- Install optional local binaries `codeql` and `osv-scanner` if live wrapper
  execution is required on this machine.
- Fix the local Semgrep trust-store startup issue or run Semgrep in a container.
- Add dashboard summaries for scanner-ingest artifacts.
