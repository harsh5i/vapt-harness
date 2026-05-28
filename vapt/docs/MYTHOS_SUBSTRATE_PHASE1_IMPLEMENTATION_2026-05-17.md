# Mythos Substrate Phase 1 Implementation - 2026-05-17

Status: complete against the Phase 1 roadmap acceptance criteria as of
2026-05-18.

## Delivered

- Knowledge tree:
  - `vapt/harness/knowledge/INDEX.md`
  - `vapt/harness/knowledge/principles.md`
  - `vapt/harness/knowledge/workflow.md`
  - `vapt/harness/knowledge/patterns.yaml`
  - `vapt/harness/knowledge/scoring.yaml`
  - `vapt/harness/knowledge/programs/`
  - `vapt/harness/knowledge/vuln_classes/`
  - `vapt/harness/knowledge/lessons/`
- Cold-start/session commands:
  - `session-start`
  - `next-action`
  - `explain`
  - `knowledge`
  - `commands --json`
- Decision-director commands:
  - `budget`
  - stronger `status --json`
  - canonical workflow checks in `candidate-set`
  - stricter report-ready checks in `gate --report-ready`
- Corpus command:
  - `corpus-rebuild`
- Target profile budget/scoring schema added to all registered target profiles:
  `demo-mlops`, `llama_index`, `demo-target`, `ollama`, and `demo-pyml`.

## Important Behavior

- `session-start <run_dir>` is now the cold-start entrypoint for any fresh model
  session. It emits run state, target scope, candidate summaries, budget status,
  latest artifacts, knowledge pointers, and a recommended next action.
- `candidate-set --status <canonical_state>` refuses illegal roadmap workflow
  transitions unless `--force` is supplied with an explicit reason.
- `gate` now treats formal deduplication as a promotion precondition, not just a
  free-form novelty label.
- `budget` exits non-zero when the run is over total budget.
- `knowledge <query>` searches local docs, agents, knowledge files, and corpus
  without embeddings or external services.

## Smoke Checks

- `python -m py_compile vapt/harness/harness.py`: passed.
- `session-start` on DemoTarget run: passed.
- `next-action` on DemoTarget run: passed.
- `knowledge "websocket authz negative control"`: returned relevant doctrine.
- `explain gate`: returned command help and knowledge references.
- `commands --json`: emitted a machine-readable command manifest.
- `corpus-rebuild`: wrote `vapt/harness/corpus/candidates.jsonl`.
- `gate MM-CAND-001`: passed after formal dedup normalization.
- `budget` correctly flagged the historical DemoTarget run as over total budget.

## Phase 1 Completion Check - 2026-05-18

- `knowledge/INDEX.md` now points to the reviewer agent checklist directory.
- All registered target profiles include `budgets` and
  `scoring.report_ready_threshold`.
- `--version` returns the active harness version.
- `session-start` on the DemoTarget run emits target scope, candidate summary,
  budget state, knowledge pointers, latest artifacts, and recommended next
  action.
- `explain gate` returns command help and relevant knowledge pointers.
- `knowledge "workflow gate dedup"` returns local corpus/docs results.
- `next-action --json` returns a structured recommendation.

## Remaining Roadmap Phases

Phase 1 is complete. Later roadmap phases remain tracked separately:

- Phase 2: implemented as a feedback-loop foundation; usefulness depends on
  more terminal submission outcomes.
- Phase 3: partially implemented; remaining work is tool depth, real captive
  fixtures, CodeQL/OSV scanner onboarding, and refine automation.
- Phase 4: not started; watch profiles, queue, daemon, advisory/commit polling,
  and optional MCP remain pending.
