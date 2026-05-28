# Mythos Substrate BB Quality Upgrade - 2026-05-25

## Purpose

Move the harness from "artifact organizer" toward repeatable bug-bounty
research discipline with stricter novelty, proof, and report-readiness gates.

## Implemented

- Added target-class playbooks through `playbook`.
  - Python ML / deserialization
  - Go API / server
  - JS/TS web / Electron
  - Local AI runtime
  - MLOps / experiment orchestration
- Added repeatable CodeQL workflow generation through `codeql-workflow`.
  - Python, Go, JS/TS, and C/C++ style workflows.
  - Each workflow records focus areas and exact `scan-codeql` commands.
- Added strict final report gate through `report-gate`.
  - Requires exact affected version or commit, not only `yes`.
  - Requires passed proof plus durable proof artifacts.
  - Requires substantive attacker control, trust boundary, impact, root cause,
    negative controls, variant analysis, and patch/advisory state.
  - Requires OSV duplicate evidence and CVE/GHSA/GitHub-style reference
    coverage; Huntr coverage is currently a warning rather than a blocker.
- Strengthened quality scoring.
  - Shallow placeholder strings no longer earn full credit.
  - Scoring now rewards proof artifacts, exact affected versions, multi-source
    dedup/advisory coverage, and strict report-gate cleanliness.
- Strengthened dedup metadata.
  - `dedup --reference` records manual Huntr/GitHub/GHSA/CVE checks.
  - Suggested queries now include Huntr, GitHub advisories, and GitHub issue
    search shapes.
- Improved PoC scaffolding.
  - `scaffold-poc` now emits class-aware templates for path traversal, SSRF,
    command injection, unsafe deserialization, IDOR/authz, and template
    injection.

## Verification

- `python -m py_compile vapt/harness/harness.py`
- `harness.py commands --json`
- `harness.py phase3-check`
- `harness.py phase4-check`
- `harness.py codeql-workflow vapt/harness/runs/demo-pyml/smoke --json`
- `harness.py playbook vapt/harness/runs/demo-pyml/smoke`
- `harness.py scaffold-poc path_traversal demo-pyml`
- `python -m py_compile vapt/pocs/demo-pyml/2026-05-25/poc_path_traversal.py`
- `harness.py report-gate vapt/harness/runs/demo-pyml/smoke --fail` correctly
  blocked the shallow smoke candidate.

## Remaining

- Literal 24-hour wall-clock soak remains intentionally deferred.
- CodeQL workflows are generated and executable, but deep target-specific custom
  QL packs are future work.
- Huntr/GitHub duplicate checks are recorded as manual references unless a
  future authenticated/API-backed search integration is added.
