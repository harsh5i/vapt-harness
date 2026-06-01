# STATUS — VAPT Harness Capability Truth

Last verified: 2026-05-30 (against the working tree, not the roadmaps).

This file is the **single source of truth** for what is actually implemented.
Rules:

- `README.md` must not claim a capability as working unless it is `implemented`
  here.
- Roadmap / management docs are **strategic intent**, not operational truth.
- A capability is `implemented` only with reproducible acceptance evidence.

Status values: `implemented` · `partial` · `designed` · `not_started` · `deprecated`

All validation commands assume repo root and system `python3` (the `.venv-vapt`
intentionally lacks PyYAML; it exists only so the campaign adapter can spawn its
subprocess).

---

## Core lifecycle & gates

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| Candidate ledger | implemented | `candidate-add`, `candidate-set`, `candidate-from-queue` in harness.py | `python3 vapt/harness/harness.py candidate-add --help` | No unit tests around state transitions (see T3). |
| Dedup gate | implemented | `dedup`, `dedup --check-osv` | `python3 vapt/harness/harness.py dedup --help` | Offline-cache false-novelty path untested. |
| Promotion / report gate | implemented | `gate`, `report-gate` | `python3 vapt/harness/harness.py report-gate --help` | No unit test asserting report-ready requires reproducer + negative controls. |
| Orchestration spine (orient/submit/advance) | implemented | commit 714bce6; `orient`, `submit`, `loop-integrity-check` (3 fixtures) | `python3 vapt/harness/harness.py loop-integrity-check` | — |
| Intent layer | implemented | `intent-set`, `intent-show`, `intent-ordering-check` | `python3 vapt/harness/harness.py intent-ordering-check` | — |
| Phase checks (2/3/4) | implemented | `phase2-check`, `phase3-check`, `phase4-check`, `campaign-flow-check` | `python3 vapt/harness/harness.py phase4-check` | Integration-style only; no unit layer. |

## Learning loop

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| Outcome-tuning loop | implemented | `outcome-tune` computes `weakness_adjustments` from terminal submission outcomes + triage verdicts (false_positive / defended / needs_proof). Wired through `_score_candidate`, bounded [-6, 6]. Synthetic rows excluded by default. | `python3 vapt/harness/harness.py weights show --json` ; `python3 vapt/harness/harness.py outcome-tune --out /tmp/t.yaml` | A fresh clone has no real outcomes (`weights show` reports `STARVED`). Synthetic seeding (`submissions seed-synthetic`) lets you exercise the loop without operational data. |
| Synthetic outcome seeding | implemented | `submissions seed-synthetic`; rows tagged `synthetic:true` | `python3 vapt/harness/harness.py submissions seed-synthetic --help` | — |
| Synthetic excluded from tuning by default | implemented | harness.py:7046 `include_synthetic=False`; `--include-synthetic` flag :12117 | `python3 vapt/harness/harness.py outcome-tune --out /tmp/t.yaml` (reports `synthetic_excluded`) | — |
| Sanctioned real-outcome write path | implemented | `outcome-record` is the non-synthetic terminal write path (rows carry no `synthetic` key); `outcome-tune` excludes synthetic by default; `weights show` reports effective weights + last meaningful update + STARVED/stale-source diagnostics | `python3 vapt/harness/harness.py weights show --json` | `outcome-record` and `submission add/update` coexist by design; no CLI rename (migration non-negotiable). |
| OSV cache (offline dedup) | implemented | OSV cache + `dedup --check-osv` | `python3 vapt/harness/harness.py dedup --check-osv --help` | Needs a test proving offline failure ≠ false novelty. |

## Discovery & source-reading

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| GHSA discovery sweep | implemented | `discovery-sweep`, `discovery-list` (needs internet) | `python3 vapt/harness/harness.py discovery-list` | — |
| Discovery claim flow | implemented | `discovery-claim`; proposals require claim before campaign | `python3 vapt/harness/harness.py discovery-claim --help` | — |
| Source acquisition | partial | source acquire/index in harness.py | `python3 vapt/harness/harness.py source-probe --help` | Validated on synthetic fixture only. |
| AST walker | partial | source-reading AST classifier with intra-function, same-file inter-procedural, and same-class self.method/self.attr taint flow (T4.3 + T4.6 + T4.7); 5/5 seeded fixtures + 24 unit tests under `tests/test_ast_taint_flow.py` (12 intra-function, 6 cross-function, 6 self/class) | `python3 vapt/harness/harness.py source-probe --local-path vapt/harness/fixtures/seeded_bugs_repo` (expects `finding_count=5`) | Taint propagates through Assign / AnnAssign / AugAssign / tuple-unpack within a function, across same-file calls (positional-by-index + keyword-by-name + tainted-return propagation, fixed-point bounded by max 6 iterations), and across methods of the same class (`self.method(...)` dispatch with self-skip; `self.X = tainted` lifted flow-insensitively to the whole class so any method using `self.X` flags). Still does **not** cross file boundaries, resolve attribute taint on objects other than `self`, model container aliasing, or follow chained-attribute calls (`self.helper().bar()`). Real-target validation (≥1 small OSS Python project with a known logic flaw) still pending. |
| Reference probe: patch_variant_hunter | implemented | catches 4/5 seeded patterns | source-probe on seeded_bugs_repo | — |
| Reference probe: auth_chain_audit | implemented | `vapt/harness/probes/auth_chain_audit.py` | source-probe | — |

## Tooling wrappers

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| ZAP wrapper | partial | `cmd_scan_zap_baseline`, `cmd_scan_zap_full` in `tools/commands.py`; ROE-gated via `_authorize_scan` (`gates/authorization.py`) — requires `active_scan_allowed: true` for full-scan and rejects out-of-scope targets fail-closed before any subprocess | `python3 vapt/harness/harness.py tools-capability --json` ; `scope-check <run_dir> <url> --scanner zap-full` | Docker-gated; real-target validation pending. |
| sqlmap wrapper | partial | `cmd_scan_sqlmap` in `tools/commands.py`; ROE-gated via `_authorize_scan` | `tools-capability --json` ; `scope-check <run_dir> <url> --scanner sqlmap` | Docker-gated; real-target validation pending. |
| JWT tooling | partial | `cmd_scan_jwt` in `tools/commands.py`; ROE-gated via `_authorize_scan` | `tools-capability --json` ; `scope-check <run_dir> <url> --scanner jwt` | Docker-gated; real-target validation pending. |
| Playwright screenshot | partial | `cmd_scan_screenshot` in `tools/commands.py`; ROE-gated via `_authorize_scan` | `tools-capability --json` ; `scope-check <run_dir> <url> --scanner screenshot` | Container-first; binary fallback. |
| Static scanners (semgrep/bandit/pip-audit/osv/codeql) | implemented | `cmd_scan_*` :10128–10224 | `tools-capability --json` | Read-only; lower ROE risk. |
| Capability/health reporting | implemented | `tools-capability`, `tool-health` | `python3 vapt/harness/harness.py tools-capability --json` | Make Docker-vs-binary fallback state clearer (T4). |

## Safety, structure, quality

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| Authorization / ROE machine-enforcement | implemented | `gates/authorization.py`; `cmd_scan_zap/sqlmap/screenshot` gated via `_authorize_scan`; `scope-check` dry-run cmd; 13 unit tests | `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_authorization_scope.py` ; `python3 vapt/harness/harness.py scope-check <run_dir> <url> --scanner zap-full` | Target profile must declare `scope_hosts` (+ optional `out_of_scope_hosts`, `active_scan_allowed`). Fail-closed: undeclared scope = refuse. |
| Package decomposition | implemented | strangler-fig batches 1-21 landed; every module under 1500 LOC; harness.py is a 1,459-line entrypoint that re-imports cmd_* + helpers from the per-domain packages | `wc -l vapt/harness/*.py vapt/harness/*/*.py \| sort -rn \| head` (max < 1500) | T3.2 acceptance met. harness.py shrank 13,001 -> 1,459 lines across 21 batches. |
| Unit tests | implemented | 109 tests green across 9 suites: `test_ast_taint_flow.py` (24, incl. cross-function + self/class), `test_authorization_scope.py` (13), `test_cold_start_commands.py` (16), `test_dedup_novelty.py` (6), `test_gates_promotion.py` (17), `test_imports.py` (4), `test_io_atomic.py` (10), `test_outcome_tuning.py` (9), `test_validators.py` (10) | `./.venv-vapt/bin/python -m pytest vapt/harness/tests/` | T3.1 acceptance met (≥50 tests covering ledger/gates/transitions/taint). Per-engagement integration tests still future. |
| Sensitive-data pre-commit | implemented | `.pre-commit-config.yaml` + `scripts/check_engagement_paths.py` + `.secrets.baseline` (detect-secrets) | `pre-commit install && pre-commit run --all-files` | Opt-in install per clone. Engagement-path guard is fail-closed on any staged file under `vapt/engagements/<id>/`. |
| Cross-platform support | partial | `atomic_io.py` dispatches `fcntl` on Unix/macOS and `msvcrt.locking` on Windows for the same `file_lock` / `candidate_ledger_lock` surface; `vapt/requirements-dev.txt` added | `python3 -c "import sys; sys.path.insert(0,'vapt/harness'); import atomic_io"` | Lock abstraction landed; full Windows CI still pending. |

## Honest capability framing (supersedes README until T4.2)

- **Implemented:** evidence-gated candidate lifecycle, authorized-target workflow,
  candidate ledger, dedup gate, report-readiness gate, orchestration spine, intent
  ordering, GHSA discovery + claim, synthetic seeding.
- **Partial:** outcome-tuned prioritization (no real data yet), source-reading
  probes (single-statement, synthetic-validated), tool wrappers (wired, ungated).
- **Future (not started):** logic-flaw 0day generation, protocol-state analysis,
  memory-corruption fuzzing, cryptographic-flaw discovery.

Avoid "autonomous 0day engine" framing. Accurate label:
**evidence-gated vulnerability research harness for authorized assessment.**
