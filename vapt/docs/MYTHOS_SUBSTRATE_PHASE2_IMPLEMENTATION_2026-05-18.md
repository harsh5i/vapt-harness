# Mythos Substrate Phase 2 Implementation - 2026-05-18

Status: complete against the Phase 2 roadmap acceptance criteria as of
2026-05-18. Live score tuning still depends on real terminal submission
outcomes.

## Delivered

- Submission ledger:
  - `submissions add`
  - `submissions update`
  - `submissions list`
  - `submissions stats`
  - Ledger path: `vapt/harness/corpus/submissions.jsonl`
- Retrospectives:
  - `retro <run_dir>` writes `<run_dir>/retro.md`
  - `retro <run_dir>` writes `<run_dir>/retro.patch`
- Cross-engagement reuse:
  - `corpus suggest <target_id>`
  - Uses `vapt/harness/corpus/candidates.jsonl`
- Target selection:
  - `pick-target`
  - Scores target profiles using in-scope breadth, local corpus signal, duplicate
    pressure, and submission outcomes when available.
- Score tuning:
  - `score-tune`
  - Produces a report under `vapt/harness/corpus/`
  - Reports `insufficient-data` until enough terminal outcomes exist.
- Acceptance gate:
  - `phase2-check`
  - Writes `vapt/harness/tests/results/phase2_check_<stamp>.md`
  - Runs fixture submission stats, corpus suggestion, retro artifact,
    target ranking, and pattern coverage checks.

## Smoke Checks

- `python -m py_compile vapt/harness/harness.py`: passed.
- `submissions stats --json`: passed on empty ledger.
- `corpus suggest demo-target --limit 3 --json`: returned ranked suggestions.
- `pick-target --json`: returned ranked registered targets.
- `retro vapt/harness/runs/demo-target/2026-05-16-initial`: wrote
  `retro.md` and `retro.patch`.
- `score-tune`: wrote an insufficient-data report, as expected with no terminal
  submission outcomes.
- `submissions add --help` and `submissions update --help`: parsed successfully.
- `phase2-check`: passed on 2026-05-18 and wrote
  `vapt/harness/tests/results/phase2_check_20260518_110039.md`.

## Operational Notes

- Do not log fake external submissions. Help and stats were smoke-tested without
  contaminating `submissions.jsonl`.
- Outcome quality depends on disciplined `submissions update` use after triage,
  duplicate, paid, rejected, or resolved outcomes.
- `score-tune` needs terminal positive and negative outcomes before it can make
  meaningful weight recommendations.
- `phase2-check` uses in-memory fixture submissions to validate the stats math;
  it does not contaminate the real submission ledger.

## Phase 2 Completion Check - 2026-05-18

- `phase2-check` passed.
- Fixture submission stats produced five terminal outcomes with acceptance,
  duplicate, average value, and days-to-final rollups.
- Pattern coverage regression passed for all configured fixture categories.
- `corpus suggest demo-target` produced non-trivial suggestions from prior
  engagements.
- Registered target ranking is available through `pick-target`.
- DemoTarget retro artifacts exist.
- Actual `submissions.jsonl` remains empty because no fake external submissions
  were logged.

## Remaining Roadmap Phases

- Phase 3: partially implemented; remaining work is tool depth, real captive
  fixtures, CodeQL/OSV scanner onboarding, dashboard integration, and refine
  automation.
- Phase 4: watch profiles, queue, daemon, commit/release/advisory polling, and
  optional MCP wrapper.
