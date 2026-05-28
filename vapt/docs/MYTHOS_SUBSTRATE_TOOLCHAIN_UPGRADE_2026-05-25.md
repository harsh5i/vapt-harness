# Mythos Substrate Toolchain Upgrade - 2026-05-25

## Purpose

Close the practical Phase 3 source-review tooling gap for dependency advisory
checks and CodeQL-assisted source analysis.

## Changes

- Installed `osv-scanner 2.3.8` through Homebrew.
- Installed CodeQL CLI `2.25.5` workspace-locally under `.vapt-tools/codeql`.
- Exposed CodeQL as `.vapt-bin/codeql` so the VAPT activation helper and
  harness can resolve it consistently.
- Verified the CodeQL archive SHA-256 before installation:
  `1b3f785a8c8746668c5575bf6ffab4ec46e9207519e8aab82babb2a21beaf538`.
- Updated `find_tool()` and `tool_env()` so harness wrappers prefer
  workspace-local `.vapt-bin` and `.venv-vapt/bin` tools before global PATH
  tools.
- Made `phase3-check` report CodeQL/OSV gaps dynamically instead of carrying
  stale static warnings.

## Verified State

- `.vapt-bin/codeql version`: CodeQL CLI `2.25.5`.
- `osv-scanner --version`: `2.3.8`.
- `harness.py tool-health --json --versions`: CodeQL and OSV scanner available.
- `harness.py phase3-check`: passed with CodeQL and OSV scanner available.
- `harness.py phase4-check`: passed.
- `python -m py_compile vapt/harness/harness.py`: passed.

## Remaining Caveats

- Docker/Podman remain unavailable, so container-backed sandbox execution is not
  available.
- The literal 24-hour daemon soak remains an empirical wall-clock validation
  item.

## Follow-up Hardening Completed

- Semgrep is operational through harness-managed `HOME`, certificate-bundle,
  metrics, and version-check environment settings.
- Scanner wrappers now pass the required evidence base path to `run_tool_scan`,
  so scanner executions produce durable `.summary.json`, `.out`, `.err`, and
  `.status` files.
- `sandbox-exec` now supports a macOS `/usr/bin/sandbox-exec` fallback when
  Docker/Podman are absent. The fallback denies network access and denies writes
  outside the evidence directory unless an explicit `:rw` mount is supplied.
