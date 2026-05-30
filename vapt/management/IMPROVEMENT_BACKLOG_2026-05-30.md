# VAPT Harness — Improvement Backlog & Execution Plan

Date: 2026-05-30
Status: ACTIVE — Tier 1 in progress
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

### Tier 1 — Truth + Safety (cheap, now) [IN PROGRESS]

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

### Tier 2 — First Real Outcome (the core thesis)

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
- **T4.5** Sensitive-data pre-commit (gitleaks / detect-secrets + engagement-path
  regex); keep `vapt/engagements/*/` ignored; synthetic fixtures allowed.

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

## 6. Parked: pre-public-release checklist (not current work)

LICENSE · ACCEPTABLE_USE.md · SECURITY.md · DISCLOSURE_POLICY.md ·
CONTRIBUTING.md · conservative README capability claims · corpus scrub review.
Revisit only when public/controlled release is on the table.
