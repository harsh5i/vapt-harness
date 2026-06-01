# STATUS — VAPT Harness Capability Truth

Last verified: 2026-06-01 (against the working tree, not the roadmaps).

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
| Candidate ledger | implemented | `candidate-add`, `candidate-set`, `candidate-from-queue` in harness.py; state-transition + workflow-blocker coverage in `tests/test_gates_promotion.py` (17 tests) | `python3 vapt/harness/harness.py candidate-add --help` ; `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_gates_promotion.py` | — |
| Dedup gate | implemented | `dedup`, `dedup --check-osv`; offline / cache-only / cache-only-miss novelty paths covered by `tests/test_dedup_novelty.py` (6 tests, incl. `test_offline_osv_cache_only_does_not_fake_novelty` and `test_dedup_incomplete_blocks_promotion`) | `python3 vapt/harness/harness.py dedup --help` ; `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_dedup_novelty.py` | — |
| Promotion / report gate | implemented | `gate`, `report-gate`; `tests/test_gates_promotion.py` covers report-ready preconditions: proof passed, root cause, variant analysis, patch advisory, negative controls, exploitability threshold | `python3 vapt/harness/harness.py report-gate --help` ; `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_gates_promotion.py -k report_ready` | — |
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
| OSV cache (offline dedup) | implemented | OSV cache + `dedup --check-osv`; covered by `tests/test_dedup_novelty.py::test_offline_osv_cache_only_does_not_fake_novelty` (asserts cache-only miss downgrades to `dedup-incomplete`, not `no-known-duplicate`) | `python3 vapt/harness/harness.py dedup --check-osv --help` ; `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_dedup_novelty.py::test_offline_osv_cache_only_does_not_fake_novelty` | — |

## Discovery & source-reading

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| GHSA discovery sweep | implemented | `discovery-sweep`, `discovery-list` (needs internet) | `python3 vapt/harness/harness.py discovery-list` | — |
| Discovery claim flow | implemented | `discovery-claim`; proposals require claim before campaign | `python3 vapt/harness/harness.py discovery-claim --help` | — |
| Source acquisition | implemented | `source-probe --local-path <repo>` consumed three real OSS targets end-to-end on 2026-06-01: bottle (30 files, 3 findings), flask (83 files, 1 finding), werkzeug (138 files, 13 findings incl. the historically CVE'd `send_file` open path). No parse errors, no crashes, sub-2s per target. | `python3 vapt/harness/harness.py source-probe --local-path vapt/harness/fixtures/seeded_bugs_repo` ; for real-target: `VAPT_REALWORLD=1 ./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_realworld_smoke.py` | Real-target acceptance evidence captured under `tests/test_realworld_smoke.py` (opt-in via env var so default unit runs stay deterministic and offline). |
| AST walker | implemented | source-reading AST classifier with intra-function, same-file inter-procedural, same-class self.method/self.attr, cross-file, **non-self attribute taint, and container aliasing** (T4.3 + T4.6 + T4.7 + T4.8 + T4.9); 5/5 seeded fixtures + 36 unit tests under `tests/test_ast_taint_flow.py` (12 intra-function, 6 cross-function, 6 self/class, 6 cross-file, 6 non-self attr + container) + 3 real-world smoke tests (`test_realworld_smoke.py`, opt-in) validating against bottle / flask / werkzeug | `python3 vapt/harness/harness.py source-probe --local-path vapt/harness/fixtures/seeded_bugs_repo` (expects `finding_count=5`) ; `VAPT_REALWORLD=1 ./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_realworld_smoke.py` | Taint propagates through Assign / AnnAssign / AugAssign / tuple-unpack within a function, across same-file calls, across methods of the same class, across files in the same package via import-resolved callee lookup, across non-self attribute writes (`cfg.path = tainted` taints `cfg.path` for downstream reads in the function), and across container mutations (`lst.append/extend/insert/add/update`, `d[k] = ...`, `for x in tainted_container`). Walker runs at package granularity over an opt-in module set; stdlib / third-party imports never resolve so taint cannot leak through them. Remaining out-of-scope: chained-attribute call resolution (`self.helper().bar()`), cross-module class hierarchies. |
| Reference probe: patch_variant_hunter | implemented | catches 4/5 seeded patterns | source-probe on seeded_bugs_repo | — |
| Reference probe: auth_chain_audit | implemented | `vapt/harness/probes/auth_chain_audit.py` | source-probe | — |

## Tooling wrappers

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| ZAP wrapper | implemented | `cmd_scan_zap_baseline`, `cmd_scan_zap_full` in `tools/commands.py`; ROE-gated via `_authorize_scan` (`gates/authorization.py`); validated end-to-end on 2026-06-01 against OWASP Juice Shop (`bkimminich/juice-shop:latest`), 600s timeout, 10 alerts surfaced (CSP missing, cross-domain misconfig, dangerous JS, header-policy gaps) | `python3 vapt/harness/harness.py scan-zap-baseline <run_dir> http://<in-scope-host>/ --network host --timeout 600` | Container-first via `ghcr.io/zaproxy/zaproxy:stable`. Active-scan variant requires `active_scan_allowed: true`. |
| sqlmap wrapper | implemented | `cmd_scan_sqlmap` in `tools/commands.py`; ROE-gated; validated end-to-end on 2026-06-01 against OWASP Juice Shop's `/rest/products/search?q=` endpoint (no SQLi surfaced -> no false positive); `--prefer-local` flag added to bypass the docker runtime when the venv carries a working `sqlmap` (the deprecated `paoloo/sqlmap` manifest-v1 image is now rejected by Docker 29 / containerd v2.1 -- binary fallback is the supported path on those hosts) | `python3 vapt/harness/harness.py scan-sqlmap <run_dir> --target-url <url> --prefer-local --timeout 120` | Container path remains for hosts with a working modern sqlmap image; `--prefer-local` is the recommended path until the configured image is upgraded. |
| JWT tooling | implemented | `cmd_scan_jwt` in `tools/commands.py`; ROE-gated; validated on 2026-06-01 (local decode + `ticarpi/jwt_tool` container both succeeded against a synthetic juice-shop-shaped token, decode JSON written) | `python3 vapt/harness/harness.py scan-jwt <run_dir> --token <jwt> --container --timeout 60` | Local decode always works; container path optional via `--container`. |
| Playwright screenshot | implemented | `cmd_scan_screenshot` in `tools/commands.py`; ROE-gated; validated end-to-end on 2026-06-01 against OWASP Juice Shop (233KB PNG, rc=0); `--prefer-local` flag added (the published `mcr.microsoft.com/playwright/python:v1.45.0-jammy` image bundles browsers but not the Python `playwright` module, so the local venv install is the supported path until that gap is closed upstream). Local fallback now correctly resolves the venv interpreter that owns the playwright CLI. | `python3 vapt/harness/harness.py scan-screenshot <run_dir> <url> --prefer-local --timeout 60` | Container path remains for hosts with a self-built image that pre-installs the python module. |
| Static scanners (semgrep/bandit/pip-audit/osv/codeql) | implemented | `cmd_scan_*` :10128–10224 | `tools-capability --json` | Read-only; lower ROE risk. |
| Capability/health reporting | implemented | `tools-capability`, `tool-health`; `scan-sqlmap` and `scan-screenshot` expose `--prefer-local` so operators can explicitly route around a missing or broken container image without losing the wrapper's evidence-capture contract | `python3 vapt/harness/harness.py tools-capability --json` | — |

## Safety, structure, quality

| Capability | Status | Evidence | Validation command | Known gaps / next |
|---|---|---|---|---|
| Authorization / ROE machine-enforcement | implemented | `gates/authorization.py`; `cmd_scan_zap/sqlmap/screenshot` gated via `_authorize_scan`; `scope-check` dry-run cmd; 13 unit tests | `./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_authorization_scope.py` ; `python3 vapt/harness/harness.py scope-check <run_dir> <url> --scanner zap-full` | Target profile must declare `scope_hosts` (+ optional `out_of_scope_hosts`, `active_scan_allowed`). Fail-closed: undeclared scope = refuse. |
| Package decomposition | implemented | strangler-fig batches 1-21 landed; every module under 1500 LOC; harness.py is a 1,459-line entrypoint that re-imports cmd_* + helpers from the per-domain packages | `wc -l vapt/harness/*.py vapt/harness/*/*.py \| sort -rn \| head` (max < 1500) | T3.2 acceptance met. harness.py shrank 13,001 -> 1,459 lines across 21 batches. |
| Unit tests | implemented | 121 tests green across 10 suites (+3 opt-in real-world smoke tests skipped by default): `test_ast_taint_flow.py` (36, incl. cross-function + self/class + cross-file + non-self attr/container), `test_authorization_scope.py` (13), `test_cold_start_commands.py` (16), `test_dedup_novelty.py` (6), `test_gates_promotion.py` (17), `test_imports.py` (4), `test_io_atomic.py` (10), `test_outcome_tuning.py` (9), `test_realworld_smoke.py` (3, opt-in), `test_validators.py` (10) | `./.venv-vapt/bin/python -m pytest vapt/harness/tests/` ; `VAPT_REALWORLD=1 ./.venv-vapt/bin/python -m pytest vapt/harness/tests/test_realworld_smoke.py` | T3.1 acceptance met. Per-engagement integration tests still future. |
| Sensitive-data pre-commit | implemented | `.pre-commit-config.yaml` + `scripts/check_engagement_paths.py` + `.secrets.baseline` (detect-secrets) | `pre-commit install && pre-commit run --all-files` | Opt-in install per clone. Engagement-path guard is fail-closed on any staged file under `vapt/engagements/<id>/`. |
| Cross-platform support | implemented | `atomic_io.py` dispatches `fcntl` on Unix/macOS and `msvcrt.locking` on Windows for the same `file_lock` / `candidate_ledger_lock` surface; `.github/workflows/ci.yml` exercises both lock branches via a 3-OS x 2-Python matrix (ubuntu-latest, macos-latest, windows-latest; Python 3.11 + 3.12) running the full unit suite plus an import-surface smoke check per platform | `python3 -c "import sys; sys.path.insert(0,'vapt/harness'); import atomic_io"` ; CI run history under `.github/workflows/ci.yml` on every push / pull request to `main` | Real-target smoke tests stay opt-in (`VAPT_REALWORLD=1`) so CI does not depend on network availability of upstream OSS repos. |

## Honest capability framing (supersedes README until T4.2)

- **Implemented:** evidence-gated candidate lifecycle, authorized-target workflow,
  candidate ledger, dedup gate, report-readiness gate, orchestration spine, intent
  ordering, GHSA discovery + claim, synthetic seeding, source acquisition,
  AST walker (intra-function + same-file inter-procedural + same-class
  self.method/self.attr + cross-file + non-self attribute + container aliasing,
  validated against bottle / flask / werkzeug), ROE-gated tool wrappers
  (ZAP, sqlmap, JWT, Playwright -- end-to-end against OWASP Juice Shop).
- **Partial:** outcome-tuned prioritization (loop wired; terminal-submission
  channel awaits real bounty rows -- the loop runs as soon as outcomes are
  recorded). This is operational, not engineering: every other capability
  on the path is `implemented`, and the loop activates as soon as real
  submission outcomes are written to the corpus.
- **Future (not started):** logic-flaw 0day generation, protocol-state analysis,
  memory-corruption fuzzing, cryptographic-flaw discovery.

Avoid "autonomous 0day engine" framing. Accurate label:
**evidence-gated vulnerability research harness for authorized assessment.**

## Stress evidence (2026-06-01)

Run alongside the partial -> implemented push to verify the harness holds
under load.

| Dimension | Workload | Result |
|---|---|---|
| AST walker scale | Django HEAD, 2,911 .py files, ~520K LOC | 31.5s, 234 findings, 1 graceful parse_error on an intentional syntax-error fixture (no crash) |
| AST walker extreme | CPython HEAD, 2,275 .py files, ~1.1M LOC | 70s, 514 findings + structured parse_error degradation for files using 3.15-dev syntax beyond the local interpreter |
| ROE gate matrix | 4 URLs (in-scope localhost, out_of_scope 127.0.0.1, two undeclared hosts) x 4 scanners | 16/16 correct decisions: 4 allow, 12 deny with structured reasons |
| Orchestration spine | `loop-integrity-check`, `intent-ordering-check`, `phase3-check`, `phase4-check` | all green; 3/3 loop fixtures + intent-distinct-top + advisory + commit_diff queue parity |
| Concurrent wrappers | 4 wrappers (jwt + screenshot + 2 scope-checks) running in parallel | 3.67s wall, no file-lock contention, all artifacts written |
| Cross-platform CI | ubuntu-latest + macos-latest + windows-latest x Python 3.11 + 3.12 | 6/6 jobs green in 1m42s on push of `e1ef4aa` |
| Full unit suite | `pytest vapt/harness/tests/` (default + `VAPT_REALWORLD=1`) | 124/124 green in 7.7s (121 default + 3 opt-in real-world against bottle/flask/werkzeug) |
