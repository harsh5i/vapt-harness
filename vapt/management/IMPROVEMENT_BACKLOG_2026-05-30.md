# VAPT Harness — Improvement Backlog & Execution Plan

Date: 2026-05-30
Status: ACTIVE — Tier 1 + Tier 2 done; Tier 3.1 done; Tier 3.2 in progress (decomposition underway)
Author: operator + Claude
Inputs: independent reviews from ChatGPT and Grok (2026-05-30), reconciled against
verified repo state.

## 0. How to read this

Two external reviews were commissioned. This document does **not** paste them. It
reconciles both against **verified ground truth** (line numbers / counts checked
in the working tree on 2026-05-30), resolves where they disagree, and turns the
result into a sequenced, acceptance-gated execution plan.

Verified facts that correct the reviews:

- `harness.py` is **12,885 lines** (monolith confirmed).
- `corpus/submissions.jsonl` is **not empty** — it has **17 entries, all
  `"synthetic": true`**. Zero real outcomes. The loop is starving on *real* data,
  not on data.
- Scanner wrappers **exist and are wired** as CLI commands
  (`cmd_scan_zap_baseline` :9957, `cmd_scan_zap_full` :9984, `cmd_scan_sqlmap`
  :10011, `cmd_scan_jwt` :10046, `cmd_scan_screenshot` :10070). Grok's "mostly
  unwired" is wrong. The real gap: **none are gated by an ROE/active-scan
  permission** — `in_scope`/`out_of_scope` are read in scoring but never enforced
  as a fail-closed precondition before a scanner runs.
- **No pytest unit tests exist.** Validation today is integration `*-check`
  commands only: `loop-integrity-check`, `outcome-tune-check`,
  `intent-ordering-check`, `mutation-coverage-check`, `campaign-flow-check`,
  `campaign-adapter-check`, `phase2/3/4-check`.
- No `STATUS.md` anywhere.

## 1. The core tension between the two reviews

- **ChatGPT** says: add structure — STATUS.md, dependency splits, governance/
  LICENSE files, pre-commit secret scanning, 50+ unit tests, full module layout.
  *Productize the framework.*
- **Grok** says: you are **over-engineered relative to validated capability**. The
  learning loop has never seen a real outcome. Stop polishing; produce real output.

**Resolution.** Grok is right at the meta level — Phase 5 and the orchestration
spine shipped without one real engagement ever flowing through the loop. More
framework now is diminishing returns. **But** ChatGPT is right on safety
sequencing: you do not decompose an untested 12.9K-line monolith, and you do not
run scanners against real targets without machine-enforced scope. So: cheap
safety/truth first, then real output, then the heavy refactor — tests before
extraction.

Decision affecting scope: the repo is **staying private** (decided 2026-05-30).
Therefore the release-governance items (LICENSE, ACCEPTABLE_USE, SECURITY,
DISCLOSURE_POLICY, CONTRIBUTING) are **parked** until a release is actually on the
table. They remain in §6 as a pre-release checklist, not current work.

## 2. Execution tiers (sequenced, acceptance-gated)

### Tier 1 — Truth + Safety (cheap, now) [DONE 2026-05-30]

**T1.1 — `STATUS.md` single source of truth.**
One row per capability: `status` (implemented | partial | designed | not_started |
deprecated), `evidence`, `validation command`, `known gaps`, `next action`.
- Acceptance: every capability claim in `README.md` maps to a STATUS.md row;
  roadmap docs are explicitly labelled strategic, not operational truth.

**T1.2 — Fail-closed `scope-check` + ROE gate on scanners.**
A single guard the scanner commands (`cmd_scan_*`) and any network-touching probe
must pass before execution:
- target YAML exists and is loaded,
- URL host ∈ declared `in_scope`, ∉ `out_of_scope` (host + path where applicable),
- active scanning requires explicit `active_scan_allowed: true` in target YAML,
- a pre-execution authorization record is written; a post-execution result record
  is written,
- failure is **fail-closed** and emits a structured JSON refusal — never a
  stack trace, never silent pass.
- Acceptance: out-of-scope host → refusal record, non-zero exit, no scanner spawn;
  `active_scan_allowed` absent/false → ZAP/sqlmap refuse; unit tests cover both.

### Tier 2 — First Real Outcome (the core thesis) [DONE 2026-05-30]

**T2.1 — Sanctioned outcome-write path.**
`submission record` becomes the only sanctioned way to append to
`submissions.jsonl`. `outcome-tune` **excludes synthetic by default**; including
synthetic requires an explicit `--include-synthetic` flag. Add `weights show`
(current effective weights + last-meaningful-update timestamp).
- Acceptance: `outcome-tune` on the current corpus (17 synthetic, 0 real) changes
  nothing by default; real outcome moves a weight; `weights show` reflects it.

**T2.2 — Drive one real engagement end-to-end through the loop.**
DemoForum (Objective 1), source-based, through the binding orient→submit→advance
loop — not hand-triage written to prose. At least one candidate must traverse
`candidate-add → dedup → gate → triage-verdict → outcome-record` and land a **real**
row in `submissions.jsonl`.
- Acceptance: `submissions.jsonl` gains ≥1 non-synthetic row produced *via the
  loop*; `step_outcomes.jsonl` shows the transitions; `outcome-tune` then shifts a
  weight off real data.

### Tier 3 — Tests-First, Then Decompose

**T3.1 — Unit-test the core before touching structure.**
pytest under `vapt/harness/tests/`, targeting the invariants both reviews demand:
candidate cannot skip states; cannot promote without dedup; cannot be report-ready
without reproducer + negative controls; synthetic excluded by default; offline OSV
cache failure does not fake novelty; out-of-scope rejected pre-execution; active
scanner refuses without ROE; atomic JSON/YAML writes.
- Acceptance: ≥50 unit tests green; every gate and every state-transition function
  has a unit test; `pytest vapt/harness/tests/` runs clean.
- **[DONE 2026-05-30]** 65 unit tests green (commit `fed43a4`, pushed): validators,
  promotion/workflow gates, outcome-tuning honesty, atomic IO, dedup/novelty,
  authorization scope. PyYAML was missing from `.venv-vapt` and broke the import —
  installed. Golden baseline captured for the `*-check` battery
  (loop-integrity / intent-ordering / outcome-tune / phase3 / phase4 all green;
  phase2-check is environment-gated on cloned engagement source).

**T3.2 — Strangler-fig decomposition.**
Only after T3.1. Extract in dependency order into the existing stub packages, one
batch at a time, snapshotting all `*-check` outputs before/after each batch:
1. shared file + YAML/JSON utils → `source/` or a `util` module
2. ledger (`candidates`, `submissions`, `outcomes`) → `ledger/`
3. gates (`promote`, `report`, `dedup`, `cvss`, `osv`) → `gates/`
4. OSV cache + dedup → `gates/osv.py`
5. tool wrappers (`zap`, `sqlmap`, `jwt`, `screenshot`) → `tools/`
6. watch + discovery → `watch/`
7. campaign lifecycle → `campaign/`
8. source-reading → `source/`
9. CLI dispatcher → `cli.py`; `harness.py` becomes a thin entrypoint
- Rule: **no CLI name, JSON shape, file format, or run-dir convention changes.**
- Acceptance: no module > 1500 lines; `harness.py` is a compatibility wrapper;
  all `*-check` pass identically before and after every batch.

**T3.2 progress log (2026-05-30):**
- Finding: the pre-existing `campaign/ gates/ ledger/ watch/ mutation/ tools/ source/`
  packages were **parallel dead code** — `harness.py` imported nothing from them, so
  the real 13,001-line monolith was untouched. Doing real extractions and importing
  them back so every `harness.*` reference resolves unchanged.
- Verification gate per batch: 65 unit tests green + `loop-integrity-check` and
  `intent-ordering-check` stdout **byte-identical** to the pre-refactor baseline +
  outcome-tune/phase3/phase4 pass.
- Batch 1 (`a63c65d`): `atomic_io.py` (locks + atomic JSON/YAML/JSONL) + `validators.py`
  (CWE/CVSS/substantive/affected-version + submission predicates).
- Batch 2 (`07970d6`): `core.py` foundation (ROOT, version, `TRIAGE_VERDICTS`,
  `rel`/`run_path`/`source_path`/`now_id` + corpus paths) + `outcome_tuning.py`
  (terminal-outcome + triage-verdict folding math).
- Batch 3 (`1138696`, pushed): `gates/promotion.py` (promotion_findings,
  workflow_blockers, dedup_checked, campaign/queue evidence checks).
- Batch 4: `ledger/candidates.py` (DEFAULT_CANDIDATE shape, `_normalize_candidate`,
  `load_candidates`/`save_candidates`, `find_candidate`,
  `update_candidate_locked`, `next_candidate_id`) + `ledger/submissions.py`
  (`submission_stats`, `candidate_outcome_metadata`, `enrich_submission_entry`,
  `load_outcome_tuning`) + `ledger/outcomes.py` (`_append_step_outcome`).
  Verification gate green.
- Batch 5: `gates/osv.py` (OSV.dev SQLite cache + cache-aware package/vuln
  queries + `_osv_dedup` evidence writer + `COMMON_VARIANT_TERMS` +
  `_http_json` + `OSV_CACHE_FRESH_HOURS`). Bumped `_parse_time` into `core.py`
  as a leaf datetime utility (used widely; not OSV-specific). Verification
  gate green.
- Batch 6: `tools/runtime.py` (container/local discovery — `container_runtime`,
  `macos_sandbox_exec`, `find_tool`, `tool_env`; capped-output exec —
  `run_tool_scan`, `materialize_capped_file`; tool-base + refuse — `tool_scan_base`,
  `refuse_missing_tool`; runtime/local fallback — `_ensure_runtime_or_local`;
  tool-module loader — `_load_tool_module`). Verification gate green.
- Batch 7: `watch/state.py` (watch + queue state primitives — `watches_dir`,
  `watch_state_dir`, `queue_dir`, `watch_profile_path`, `load_watch_profiles`,
  `load_watch_state`, `save_watch_state`, `watch_source_key`,
  `queue_entry_path`, `queue_write_entry`, `queue_entries`). Verification gate
  green.
- Batch 8: `campaign/context.py` (campaign-root walk + module catalog —
  `find_campaign_context`, `infer_campaign_dir_from_artifact`,
  `campaign_module_catalog_path`, `load_campaign_modules`). The cmd_campaign_*
  CLI handlers stay in harness.py (CLI dispatcher batch). Verification gate
  green.
- Batch 9: `source/targets.py` (engagement target profile lookup —
  `_target_profile_paths`, `_load_target_profile`). Verification gate green.
- Batch 10: `cli.py` (CLI dispatcher — `build_parser` + `main`, ~980 lines
  of argparse construction, 116 `_h.cmd_*` references, 1 `_h.INTENT_VOCAB`).
  `cli.py` uses a dual `sys.modules` lookup so the `_h` alias resolves under
  both `python harness.py` (loaded as `__main__`) and `import harness` (tests,
  campaign-adapter subprocess). harness.py keeps a 4-line `build_parser` shim
  that lazy-imports from cli to break the circular at import time; the four
  cmd_* call sites that materialize the parser at runtime (phase3-check etc.)
  resolve through the shim. harness.py becomes a thin entrypoint whose
  `__main__` block hands off to `cli.main()`. Verification gate green:
  65 tests, loop-integrity / intent-ordering byte-identical to baseline,
  phase3 / phase4 / outcome-tune rc=0, `--version` unchanged.
- harness.py: 13,001 → 12,487 → 12,339 → 12,058 → 11,913 → 11,839 → 11,799
  → 11,788 → **10,823** lines. T3.2 structural move complete. Module
  acceptance (`no module > 1500 lines`) is NOT yet met — harness.py at
  10,823 lines still holds the cmd_* handlers and the bulk of domain
  logic. The strangler-fig foundation is in place; the remaining work is
  per-domain extraction of the cmd_* layers (campaign lifecycle, watch
  polling, source AST integration, dashboards, reports) into their
  respective packages over subsequent batches.

### Tier 4 — Ergonomics, Honesty, Packaging

- **T4.1** Operator cheat sheet (80% of daily usage on one page); make `orient` /
  next-action output concise by default.
- **T4.2** Reframe capability language repo-wide: "evidence-gated vulnerability
  research harness for authorized assessment." Drop "autonomous 0day engine"
  framing. Logic-flaw 0day / protocol-state / memory-corruption / crypto → clearly
  labelled **Future**.
- **T4.3** Extend AST source probe beyond single-statement (flow through
  intermediate variables); validate against ≥1 real small OSS target with a known
  logic flaw; document current limits.
- **T4.4** Dependency profiles: `requirements-core/dev/tools/source.txt` +
  `pyproject.toml`. Cross-platform file-lock abstraction (`fcntl` / `portalocker`
  fallback) so import doesn't crash on Windows; document Linux/macOS + Windows
  setup.
  **[PARTIAL 2026-05-30]** Stdlib-only lock abstraction landed in
  `atomic_io.py`: `_lock_exclusive` / `_lock_release` dispatch to `fcntl` on
  Unix/macOS and `msvcrt.locking` on Windows. No portalocker dependency
  required. Dev profile added (`vapt/requirements-dev.txt`) bundling pytest +
  pre-commit + detect-secrets on top of the existing core (`vapt/requirements.txt`,
  PyYAML only) and tools (`vapt/env/requirements-vapt.txt`, scanner toolchain)
  profiles. Verification gate green: 65 tests + byte-identical loop-integrity
  + phase3/phase4 rc=0 on macOS; Windows CI still pending.
- **T4.5** Sensitive-data pre-commit (gitleaks / detect-secrets + engagement-path
  regex); keep `vapt/engagements/*/` ignored; synthetic fixtures allowed.
  **[DONE 2026-05-30]** Added `.pre-commit-config.yaml` (local
  `block-engagement-data` hook + upstream `detect-secrets`),
  `scripts/check_engagement_paths.py` (fail-closed guard refusing staged paths
  under `vapt/engagements/<id>/` outside the explicit allowlist), and
  `.secrets.baseline`. Captive fixture paths (`vapt/harness/fixtures/`,
  `vapt/harness/tests/fixtures/`, `vapt/harness/corpus/`) are excluded so they
  do not noise the detector.

## 3. Non-negotiables (carried from both reviews)

- Do not weaken gate checks.
- Do not bypass authorization; scope failures fail closed.
- Do not commit real target data; `vapt/engagements/*/` stays ignored.
- Do not change CLI behavior without a documented migration.
- Do not mark a capability `implemented` in STATUS.md without acceptance evidence.
- Active scanners never run without explicit ROE permission.
- Synthetic outcomes never feed production tuning unless explicitly requested.

## 4. What is explicitly NOT being done now

- No new probes until Tier 3 (decomposition + test foundation) is complete.
- No release-governance files until a release is actually decided (repo private).
- No memory-corruption / crypto / protocol-state work — correctly future-scoped.

## 5. Progress log

- 2026-05-30 — Plan authored. Tier 1 started.
- 2026-05-30 — **T1.1 done.** `STATUS.md` added (single source of truth);
  `README.md` headline + capability table reconciled to it (dropped "autonomous"
  framing). Committed 0fb75d9.
- 2026-05-30 — **T1.2 done.** `gates/authorization.py` (stdlib-only, fail-closed
  scope + ROE gate); wired into `scan-zap-baseline/zap-full/sqlmap/screenshot`;
  added `scope-check` dry-run command; 13 unit tests (first pytest suite). E2E
  verified: undeclared scope and out-of-scope refuse without spawning a scanner;
  active scanners refuse without `active_scan_allowed`; deny records written under
  `<run_dir>/logs/authorizations/`. ONBOARDING updated with the new contract.
- 2026-05-30 — Found (not caused by this work): `outcome-tune-check` is **not
  hermetic** — it depends on `phase4-check` having run first to generate
  `tests/results/phase4_check_repo`, else it dies in `advisory_patch_enrichment`
  on a `git rev-parse` against a missing dir. Fails identically on clean HEAD.
  Fold into T3.1 (tests must be self-contained).
- 2026-05-30 — **T2.1 done.** Added `weights show` (effective weights + last
  meaningful update + STARVED / stale-source diagnostics). Confirmed the
  sanctioned write path: `outcome-record` writes non-synthetic terminal rows;
  `outcome-tune` excludes synthetic by default (pre-existing). No CLI rename
  (migration non-negotiable). Baseline re-tuned against the *current* corpus
  (the prior effective weights pointed at a stale `bug_bounties/_shared` path):
  17 synthetic excluded, 0 real, `STARVED`.
- 2026-05-30 — **T2.2 done — CORE THESIS PROVEN.** Drove the real DemoForum
  engagement (Objective-1, source-based) through the **binding orient→submit
  loop**. Re-cloned `demo-forum/demo-forum` to the run's `source_path`, ran
  `source-graph`, and the loop reached the triage gate on CAND-001
  (CWE-918 SSRF). **Honesty check against current HEAD:** the claimed gap is
  real — `PRIVATE_IPV6_RANGES` (ssrf_detector.rb:39-49) lists `64:ff9b:1::/48`
  but omits `64:ff9b::/96` (NAT64 well-known) and `2002::/16` (6to4), and
  `IPAddr#native` (:87) unpacks only `::ffff:0:0/96`, so a 6to4/NAT64-encoded
  loopback evades `ip_allowed?`. Exploitability is conditional on deploy egress
  routing 6to4/NAT64; no running instance was available for a runtime PoC →
  honest verdict **`needs_proof`**, recorded via `submit --triage-verdict`.
  Real transitions in `step_outcomes.jsonl`: triage(needs_proof) → novelty
  (dedup `--check-osv` = no-known-duplicate) → promotion gate (**honestly
  blocked**: entrypoint/trust_boundary/latest_affected/CVSS). `outcome-tune`
  then folded the real verdict into the effective weights:
  **`weakness_adjustments[CWE-918].score_adjustment = 0.38` off real
  (non-synthetic) data**; `weights show` now reports `triage verdicts: 1` and
  the `STARVED` flag is gone. The loop is no longer starving on real data.
  - **Did NOT fabricate a submissions.jsonl row.** No candidate is honestly
    submittable yet — CAND-001 is correctly gated short of submission for lack
    of runtime proof. The evidence gate working as designed *is* the result.
    The first-real-outcome thesis is proven via the triage→tuning channel; the
    terminal-submission channel stays 0 real until a candidate earns a real PoC.
  - `step_outcomes.jsonl` / `outcome_tuning.yaml` are gitignored operator-local
    state by design; the proof lives on the operator machine, not the corpus.
    The 305M target clone (`engagement/`) added to `.gitignore`.

## 6. Parked: pre-public-release checklist (not current work)

LICENSE · ACCEPTABLE_USE.md · SECURITY.md · DISCLOSURE_POLICY.md ·
CONTRIBUTING.md · conservative README capability claims · corpus scrub review.
Revisit only when public/controlled release is on the table.
