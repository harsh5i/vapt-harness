# Harness Roadmap: Autonomous Vulnerability Research Substrate

Status: design specification; Phase 1 complete on 2026-05-18,
Phase 2 complete on 2026-05-18, Phase 3 complete on 2026-05-18,
and Phase 4 foundation/hardening complete on 2026-05-25.
Phase 3 completion includes the foundation, probe regression,
tooling-wrapper, tool-ingest, and acceptance-gate increments.
Phase 4 includes watch profiles, local git commit/release polling,
fixture-backed advisory polling, queue entry creation/listing/claiming,
daemon heartbeat mode, advisory cross-reference, patch-window enrichment,
bounded soak checks, an MCP-facing manifest, and live remote GitHub/GHSA/OSV
polling validation. The remaining empirical item is only the literal
twenty-four-hour daemon soak, which cannot be time-compressed.
See `MYTHOS_SUBSTRATE_PHASE1_IMPLEMENTATION_2026-05-17.md` and
`MYTHOS_SUBSTRATE_PHASE2_IMPLEMENTATION_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE3_FOUNDATION_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE3_PROBE_INCREMENT_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE3_TOOLING_INCREMENT_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE3_TOOL_INGEST_INCREMENT_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE3_COMPLETION_2026-05-18.md` and
`MYTHOS_SUBSTRATE_PHASE4_FOUNDATION_2026-05-25.md`.
Audience: harness engineering team.
Project type: authorized vulnerability assessment and external program
research tooling.

This document specifies the next evolution of the vulnerability research
harness from an operator-driven ledger into a model-agnostic substrate
that any external language model can plug into and perform iterative,
knowledge-driven, self-improving vulnerability research within
authorization boundaries.

---

## 1. Overview

The harness today is a deterministic CLI that organizes manual research:
a candidate ledger, a promotion gate, a scoring function, reviewer
checklists, and source-pattern maps. It is artifact-first and works well
for single-target engagements driven by a human operator with optional
model assistance.

The objective of this roadmap is to extend the harness so that:

1. Knowledge, doctrine, and program intelligence are durable, queryable,
   and loadable by any external language model on cold start.
2. The workflow is enforced by the harness, not by operator discipline
   alone.
3. Reusable probe modules replace per-target ad-hoc proof scripts.
4. Known and novel security tools are first-class citizens with a
   sandboxed execution layer.
5. Submission and outcome data feed back into knowledge and scoring.
6. New code, releases, and advisories on watched targets surface
   automatically as a queue of candidate seeds.

The harness does not implement a model. It provides the substrate around
the model. The same harness must support multiple external models
without code changes — commercial APIs, locally hosted open weights, and
future entrants.

---

## 2. Goals and Non-Goals

### 2.1 Goals

- Model-agnostic substrate. Any external LLM with shell access (or a
  later MCP layer) can use it.
- Repeatable, auditable workflow with enforced state transitions.
- Cross-engagement learning via a flat, append-only corpus.
- Continuous operation: watch sources surface fresh candidate seeds.
- Knowledge-first design: doctrine, patterns, and program intelligence
  live in versioned files, not in code.
- Self-improvement: outcomes (triaged, duplicate, resolved, paid)
  flow back into knowledge and scoring weights.
- Safe execution of untrusted external research material via a sandboxed
  runner.
- Authorized testing only: rate limits, scope checks, and rules of
  engagement are first-class.

### 2.2 Non-Goals

- No model implementation, fine-tuning, or training.
- No autonomous exploitation outside locally captive lab environments.
- No destructive testing, denial-of-service, or credential attacks
  except where an explicit ROE permits them.
- No mass internet scanning.
- No telemetry, phone-home, or cloud dependencies for core operation.
- No integration with external in-house systems. The harness must be
  installable and runnable in isolation.
- No proprietary or platform-locked dependencies for core operation
  (Docker or Podman is acceptable for the sandbox layer; both are
  industry-standard).

---

## 3. Design Principles

1. **Artifact-first.** Every action produces a durable file on disk.
   State is reconstructible from the run directory alone.
2. **Deterministic.** Same input state plus same command equals same
   logical output. Timestamps appear in artifacts only.
3. **Atomic writes.** Write to a temporary file, then rename. Take
   advisory file locks on read-modify-write paths.
4. **Append-only history.** Every candidate carries a history list.
   Knowledge edits flow through a retrospective patch reviewed by a
   human before commit.
5. **Reference hygiene.** External repositories and payload libraries
   are untrusted data. Doctrine and workflow may be learned. Code,
   payloads, and installer scripts are never executed without
   sandboxing.
6. **Authorized testing only.** Targets carry rules of engagement;
   commands respect them. No bypasses for convenience.
7. **Model-agnostic.** No interface depends on a particular model's
   prompting style, context window, or tool-call schema.
8. **Composable, not monolithic.** Probes, scanners, knowledge entries,
   and program profiles are independent units that can be added,
   removed, or replaced without touching the core.

---

## 4. Architecture: The Six Capability Layers

### 4.1 Knowledge Layer

**Purpose.** Make doctrine, patterns, program intelligence, and prior
candidate outcomes loadable by any external model on cold start.

**Today.** Reviewer checklists exist as Markdown files. Pattern lists
are hard-coded in the CLI. Lessons learned live in narrative
documentation written for human readers. Knowledge is not queryable.

**Target state.** A versioned knowledge tree under `harness/knowledge/`:

```
harness/knowledge/
  INDEX.md              # cold-start entrypoint for any model session
  principles.md         # ~30 machine-consumable operating principles
  workflow.md           # explicit candidate state machine and transitions
  patterns.yaml         # unified pattern stack (categories, regex, fixed strings)
  scoring.yaml          # configurable score weights and band thresholds
  programs/             # per-program intelligence
    template.md
    <program_id>.md
  vuln_classes/         # per-vulnerability-class doctrine
    template/
    <class_id>/
      doctrine.md
      sinks.md
      exemplars.md      # sanitized references — no payloads
      cves.md           # cluster of historical CVEs and silent fixes
  lessons/              # dated learning events
    <YYYY-MM-DD>_<topic>.md
  semgrep/              # vendored static-analysis rulesets
  codeql/
```

**New commands.**

- `harness explain <command>` — prints command help, relevant agent
  prompts, and recent successful examples drawn from the corpus.
- `harness knowledge <query>` — local search across `knowledge/` and
  `corpus/candidates.jsonl`. Implementation: ripgrep plus a simple BM25
  ranker. No embedding dependency required.
- `harness session-start <run_dir>` — emits a JSON dump containing run
  state, candidate summaries, recent history, recommended next action,
  and pointers into the knowledge index. Any fresh model session can
  bootstrap from this output alone.

**Acceptance.**

- A fresh model session, given only `knowledge/INDEX.md` and the CLI,
  can initialize a run on any registered target, add a candidate, run
  deduplication, and exercise the promotion gate without operator
  intervention.
- `harness knowledge <query>` returns relevant doctrine plus prior
  corpus entries within two seconds on a workstation.

### 4.2 Decision-Director Layer

**Purpose.** Make the workflow that the documentation prescribes
enforceable. Today the reviewer checklists are advisory. The harness
must turn them into rails.

**Today.** Promotion gate checks field presence. Score function sums
weights for non-empty fields. Workflow transitions are implicit and not
checked.

**Target state.**

1. **`knowledge/principles.md`** — terse rules consumed by the model as
   system context. Example rule shapes:
   - Before promotion, deduplication status must be
     `no-known-duplicate`, `possible-regression`, or
     `low-public-footprint`.
   - If novelty equals `known-duplicate` and the working thesis is not
     `incomplete-fix`, `regression`, or `affected-version-correction`,
     abandon the candidate within the program's `commodity_class_minutes`
     budget.
   - Proof-of-concept output is not acceptable as report-ready unless a
     negative control has been recorded.
   - Exploitability level L2 or below cannot reach report-ready status.

2. **`knowledge/workflow.md`** — explicit candidate state machine:

   ```
   candidate
     -> deduped
     -> promoted
     -> proved
     -> root_cause_recorded
     -> variant_searched
     -> patch_diffed
     -> report_ready
     -> submitted
     -> { triaged, duplicate, n_a, resolved, paid }
   ```

   Each transition has machine-checkable preconditions.
   `harness gate` and `harness candidate-set` refuse illegal transitions
   with structured error output.

3. **Workflow enforcement upgrades to `harness gate`** (in addition to
   existing field-presence checks):
   - Gate fails if deduplication has not been run on this candidate.
   - `--promote` requires gate pass and non-blocking deduplication
     status.
   - `--report-ready` requires gate pass, `proof = passed`, a
     `variant_analysis` artifact path, and a non-empty `root_cause`.

4. **Per-target budgets** in the target profile:

   ```yaml
   budgets:
     novelty_gate_minutes: 30
     triage_minutes: 120
     deep_review_minutes: 240
     commodity_class_minutes: 30
     total_minutes: 480
   scoring:
     report_ready_threshold: 85
   ```

   New command: `harness budget <run_dir>` reads history, computes
   elapsed wall-clock per stage, flags overruns.

5. **`harness next-action <run_dir>`** — given current run state,
   returns a recommended next step with reasoning. The recommendation
   is grounded in current ledger state, target budgets, and program
   profile. It does not replace model judgement; it gives a model a
   default to either accept or override.

**Acceptance.**

- Promoting an undeduplicated candidate fails with a structured error
  identifying the missing precondition.
- A run that overruns `triage_minutes` flags clearly in `harness status`
  and the run dashboard.
- `harness next-action` produces a non-trivial recommendation grounded
  in the ledger.

### 4.3 Testing-Pattern Layer

**Purpose.** Reusable probe modules so the second engagement on a given
vulnerability class inherits work done on the first.

**Today.** Per-target proof scripts live ad-hoc under `pocs/<target>/`.
There is no shared probe library.

**Target state.**

```
harness/probes/
  __init__.py
  base.py                       # Probe abstract base class
  websocket_authz_drift.py
  parser_canonicalization.py
  idor_diff.py
  serialization_rce.py
  ssrf_outbound.py
  prompt_injection_to_tool.py
  rag_poisoning_durability.py
  model_card_local_file_read.py
  saml_audience_confusion.py
  ...
  README.md
```

Each probe:

- Implements a common interface: `prepare`, `run`, `evidence`,
  `cleanup`.
- Takes a `ProbeContext` containing target spec, run directory,
  candidate reference, and knobs.
- Runs a bounded local differential test.
- Emits structured evidence under
  `<run_dir>/evidence/<cand_id>_<probe>_<stamp>.{out,err,status,yaml}`.
- Updates the candidate's `proof` field through the ledger API rather
  than by direct file write.
- Records framework mappings, negative controls, and safety notes
  automatically when the probe can derive them.

**Iterative refinement command** (new).

```
harness refine <run_dir> <cand_id> [--max-iterations <n>] [--budget-minutes <m>]
```

Drives a single candidate through repeated probe-evidence-update cycles
until one of: the candidate reaches report-ready, the budget is
exhausted, or the model marks it abandoned. Each iteration:

1. Selects the most relevant probe based on the candidate's current
   surface, sink, and weakness.
2. Runs the probe with the candidate's current parameters.
3. Captures evidence.
4. Hands control back to the model with a structured prompt summarizing
   what changed.
5. The model updates the candidate (new attacker_control wording, new
   sink, new entrypoint, new negative control), and the loop continues.

This is the iterative refinement loop that distinguishes a substrate
from a static ledger.

**PoC scaffold command** (new).

```
harness scaffold-poc <vuln_class> <target_id>
```

Emits a runnable proof skeleton pre-wired with: imports for the target
environment, positive-proof boilerplate, a negative-control stub,
evidence-capture hooks, and headers that link the corresponding
vulnerability-class doctrine.

**Initial probe library.**

Priority for first delivery, weighted by current external program
demand for ML/AI library findings:

- `websocket_authz_drift`
- `serialization_rce`
- `prompt_injection_to_tool`
- `parser_canonicalization`
- `ssrf_outbound`
- `rag_poisoning_durability`
- `model_card_local_file_read`

**Acceptance.**

- Each delivered probe has an end-to-end test against a captive lab
  fixture in `tests/fixtures/`.
- `harness scaffold-poc <class> <target>` produces a script that runs
  without modification and emits structured evidence.
- `harness refine` completes at least one improvement iteration on a
  test candidate within the iteration budget.

### 4.4 Tooling Layer

**Purpose.** Make known security tools first-class harness citizens,
and provide a factory for novel tooling when an existing tool does not
cover a surface.

**Today.** Industry tools (`nuclei`, `semgrep`, `ffuf`, `trufflehog`,
`pip-audit`, `bandit`, and so on) are installed in the workspace but
not driven by the harness.

**Target state.**

**Tool wrappers** (each command runs the tool with safe defaults,
captures raw output as evidence, and emits records as
`auto-candidate` status — they do not count toward score or gate until
promoted by the operator or model):

```
harness scan-nuclei <run_dir> --url <url> [--templates <list>]
harness scan-semgrep <run_dir> [--ruleset <name>]
harness scan-codeql <run_dir> [--ql-pack <name>]
harness scan-trufflehog <run_dir>
harness scan-pip-audit <run_dir>
harness scan-bandit <run_dir>
harness scan-osv <run_dir>
harness scan-headers <url>
harness scan-tls <host>
```

**Sandboxed runner** (new).

```
harness sandbox-exec --cmd "<cmd>" --image <image> [--policy <policy>] [--mount <path>:<ro|rw>]
```

Executes an arbitrary command inside a sealed container. Default
policy:

- No network egress.
- Filesystem: only `<run_dir>/evidence/<cand_id>/` writable.
- CPU and memory limits enforced via cgroups.
- Timeout enforced by the container runtime, not by Python.
- Output captured to `<run_dir>/evidence/sandbox/<stamp>.{cmd,out,err,status,policy}`.

Policies:

- `none` — default. No egress.
- `egress-allowlist` — outbound to a configured allowlist only (used for
  OSV, GHSA, and similar advisory lookups).
- `internal-only` — outbound to RFC1918 ranges only (used for captive
  lab environments).

Backend: Docker if available, Podman as fallback. The harness refuses
sandboxed execution if neither is present. There is no raw-shell
fallback, by design.

**Novel-tool factory** (new).

```
harness new-probe <name> --vuln-class <class>
```

Scaffolds:

- `harness/probes/<name>.py` from `probes/base.py`.
- `knowledge/vuln_classes/<class>/` with template doctrine if the class
  is new.
- `tests/probes/test_<name>.py` with a scaffold-only smoke test.
- A new entry under `knowledge/INDEX.md` in the probes section.

The model fills the body. The harness grows itself across engagements.

**Tool-gap signal** (new).

When a probe is requested for a vulnerability class with no matching
probe, the harness logs an entry to
`corpus/tool_gaps.jsonl`:

```json
{
  "at": "<timestamp>",
  "run_dir": "<path>",
  "candidate_id": "<id>",
  "missing_class": "<class>",
  "context": "<short reason>"
}
```

`harness tool-gaps` lists open gaps ranked by frequency. The factory
consumes this list to decide what to build next.

**Acceptance.**

- Each tool wrapper produces at least one `auto-candidate` against a
  captive lab fixture.
- `harness sandbox-exec` blocks network egress by default and refuses to
  run without a container runtime present.
- `harness new-probe foo --vuln-class bar` produces a runnable skeleton
  whose scaffold test passes immediately.
- `harness tool-gaps` returns a ranked list after two engagements that
  exercise gap logging.

### 4.5 Self-Improvement Layer

**Purpose.** Outcomes flow back into knowledge and scoring. The harness
becomes more accurate over time without code changes.

**Today.** None of this exists. Each run is independent.

**Target state.**

**Submission ledger.**

```
harness/corpus/submissions.jsonl
```

Schema (one JSON object per line):

```json
{
  "submission_id": "<external_platform_id>",
  "platform": "<platform_name>",
  "program": "<program_id>",
  "candidate_run": "<run_dir>",
  "candidate_id": "<id>",
  "submitted_at": "<timestamp>",
  "title": "<title>",
  "severity_claimed": "<severity>",
  "cvss_claimed": "<vector>",
  "status_history": [
    {"at": "<timestamp>", "status": "submitted"},
    {"at": "<timestamp>", "status": "<later_status>", "note": "<text>"}
  ],
  "final_status": "<terminal_status>",
  "payout_value": <number_or_null>,
  "payout_currency": "<iso_code_or_null>",
  "days_to_final": <integer>,
  "lessons": ["<string>", "..."]
}
```

Commands:

```
harness submission-add <run_dir> <cand_id> --platform <p> --id <id> [--severity <s>] [--cvss <vec>]
harness submission-update <submission_id> --status <s> [--payout <value>] [--currency <iso>] [--note <text>]
harness submissions list [--program <p>] [--since <date>] [--final-only]
harness submissions stats
```

`harness submissions stats` produces per-program rollups: total
submissions, acceptance rate, duplicate rate, average value per accepted
submission, average days to final.

**Retrospective command** (new).

```
harness retro <run_dir>
```

Writes `<run_dir>/retro.md` answering:

- Which candidates passed the gate?
- Which patterns produced signal? Which produced noise?
- Which reviewer agents fired? Which went unused?
- What lesson should propagate?

Proposes edits as a git patch at `<run_dir>/retro.patch`. Operator
reviews and applies it. The harness never silently mutates knowledge —
every knowledge change goes through reviewable diff.

**Cross-engagement transfer** (new).

```
harness corpus suggest <target_id>
```

Queries `corpus/candidates.jsonl` for patterns, sinks, and surfaces
that produced positive outcomes (`triaged`, `resolved`, `paid`) on
targets in the same vulnerability-class neighborhood as the supplied
target. Returns ranked suggestions with rationale.

This is the cross-engagement learning lever: a paid pattern on one
target becomes a hypothesis seed on the next.

**Engagement selection** (new).

```
harness pick-target [--budget-minutes <m>] [--platform <p>]
```

Ranks open targets by expected value over the supplied time budget,
using:

- Program profile data (acceptance rate, average value, response time,
  duplicate density).
- Watch-queue depth (fresh candidates surfaced but not yet triaged).
- Past corpus performance on similar targets.
- Operator-supplied priors in `knowledge/programs/<id>.md`.

Returns the recommendation with full reasoning so the operator or model
can override.

**Pattern coverage tests.**

```
harness/tests/
  fixtures/
    known_vulnerable/
      ...
  test_patterns.py
  test_probes.py
  test_workflow.py
  test_ledger.py
```

CI runs on every commit. Pattern removals or regressions are caught
before merge.

**Score-weight tuning** (new).

Once `submissions.jsonl` has sufficient entries with terminal outcomes
(threshold to be tuned, target initial threshold of twenty
submissions):

```
harness score-tune --since <date>
```

Computes correlation between each candidate field and positive terminal
outcomes. Proposes weight adjustments and a confidence interval.
Operator reviews. Weights live in `knowledge/scoring.yaml` and are
hot-loaded by the score command.

**Acceptance.**

- `harness submissions stats` produces useful per-program rollups after
  five logged submissions.
- `harness retro` produces a retro.md and a retro.patch that a human
  reviewer would accept.
- `harness corpus suggest` returns non-trivial suggestions after the
  corpus contains entries from at least three engagements.
- `harness pick-target` produces a justified ranked recommendation.
- Pattern-coverage CI fails on a deliberate pattern removal.

### 4.6 Continuous-Operation Layer

**Purpose.** New commits, new releases, and new advisories on watched
targets surface automatically as queue entries the operator or model
picks from.

**Today.** None of this exists. Every engagement begins on operator
trigger.

**Target state.**

**Watch profiles.**

```
harness/watches/
  <target_id>.yaml
```

Example:

```yaml
target_id: <generic_id>
sources:
  - kind: github_releases
    repo: <owner>/<repo>
  - kind: github_commits
    repo: <owner>/<repo>
    branch: <branch>
    paths:
      - <path>
  - kind: ghsa_advisories
    ecosystem: <ecosystem>
    package: <package_name>
  - kind: osv_advisories
    package: <package_name>
poll_interval_minutes: 30
trigger_patterns:
  - <category_name>
  - <category_name>
```

**Commands.**

```
harness watch-add <target_id> --source <kind> [...]
harness watch-list
harness watch-tick [--target <id>]
harness watch-daemon
harness queue
harness queue claim <queue_id>
```

`harness watch-tick` runs one polling pass:

1. Poll each registered source. Persist state under
   `harness/watches/state/<target_id>.json` (last seen reference, last
   poll timestamp).
2. For new commits, run `patch-mine` automatically over the diff using
   the target's `trigger_patterns`.
3. If hits, create a queue entry under
   `harness/queue/<target_id>/<stamp>_<short_ref>.yaml` with prefilled
   candidate seeds, the diff hunks, and the matched patterns.
4. For new advisories, cross-reference all watch profiles. Any profile
   whose target shares the advisory's affected package or whose
   `trigger_patterns` overlap the advisory's CWE class produces a
   `possible-regression` queue entry.

**Patch-window race** (specific case of the above).

When a published advisory describes a silent fix, the harness
automatically queues `possible-regression` candidates against every
watched target that shares either the affected package or a sufficiently
similar pattern signature. This is the "ahead of adversaries" lever:
adversaries diff every published patch; the harness should diff them
first.

**Daemon mode.**

`harness watch-daemon` is a long-running loop that runs `watch-tick` on
each profile's configured interval, writes a heartbeat log, and handles
SIGTERM cleanly. The harness does not ship a system service file;
operators wire it into the host's service manager.

**Acceptance.**

- `harness watch-tick --target <id>` after a fresh commit in a watched
  path produces at least one queue entry with diff hunks attached.
- A newly published advisory against a watched package produces a
  `possible-regression` queue entry within one poll cycle.
- `harness watch-daemon` survives a twenty-four-hour soak test without
  leaking file handles or losing state.

---

## 5. Model Contract

The harness must be usable by any external language model. The contract
is intentionally narrow.

### 5.1 CLI is the universal interface

The CLI is the contract. Command names are stable across versions.
Argument schemas are versioned. Help output is parseable.

### 5.2 Self-describing

- `harness --version` returns semver.
- `harness --help` lists top-level commands.
- `harness explain <command>` returns long-form help, the relevant
  reviewer agent, and recent successful examples drawn from the corpus.
- `harness commands --json` returns a machine-readable manifest of all
  commands and their argument schemas, suitable for downstream MCP
  wrapping.

### 5.3 Session abstraction

- `harness session-start <run_dir>` emits a JSON blob with run state,
  candidate summaries, recent history, recommended next action, and
  pointers into the knowledge index.
- `harness session-end <run_dir>` writes a session-close summary and
  appends to the corpus.

A fresh model session uses these two commands to bootstrap and finalize.

### 5.4 Knowledge entrypoint

`knowledge/INDEX.md` is the single file a fresh model session reads
first. It must:

- Explain in under five hundred words what the harness is and how it
  works.
- List the principles file, the workflow file, and the reviewer agents.
- Point at `harness explain <command>` for command help.
- Point at `harness knowledge <query>` for in-context lookup.
- Point at `harness session-start` for resuming engagements.

### 5.5 Optional MCP wrapper

A thin Model Context Protocol shim exposing each CLI command as a tool
with JSON-schema arguments. Targeted for Phase 4. CLI remains primary.

```
harness/mcp/
  server.py
  schema.json
```

---

## 6. Phased Delivery Plan

### Phase 1 — Substrate Basics

Estimated effort: one to two engineer-weeks.

Deliverables:

1. `knowledge/` tree scaffolded. Existing reviewer agents migrated.
2. `knowledge/INDEX.md`, `knowledge/principles.md`, and
   `knowledge/workflow.md` authored.
3. `harness explain`, `harness knowledge`, and `harness session-start`
   commands implemented.
4. Workflow enforcement upgrades to `harness gate` and
   `harness candidate-set`.
5. Per-target budgets in target profile schema. `harness budget`
   command.
6. `harness next-action` minimal rule-based implementation.
7. Cross-run corpus rebuild script.

Acceptance: a fresh model session resumes any existing run from
`harness session-start` output alone, with no operator-provided
context.

### Phase 2 — Feedback Loop

Estimated effort: two to four engineer-weeks.

Deliverables:

8. Submission ledger with all four commands.
9. `harness retro` emitting `retro.md` and `retro.patch`.
10. `harness corpus suggest`.
11. `harness pick-target`.
12. Pattern-coverage CI with fixture corpus.

Acceptance: `harness submissions stats` produces meaningful per-program
rollups after five logged submissions. `harness retro` produces an
acceptable knowledge edit proposal. `harness corpus suggest` returns
non-trivial suggestions once the corpus reaches three engagements.

### Phase 3 — Tooling Leverage

Estimated effort: one to two engineer-months.

Deliverables:

13. Tool wrappers for `nuclei`, `semgrep`, `codeql`, `trufflehog`,
    `pip-audit`, `bandit`, `osv-scanner`, `scan-headers`, and
    `scan-tls`.
14. Sandboxed runner with Docker and Podman backends.
15. First five probe modules from the priority list.
16. `harness scaffold-poc` and `harness new-probe`.
17. `harness refine` iterative loop.
18. Tool-gap logging and `harness tool-gaps` query.

Acceptance: each tool wrapper produces at least one validated
`auto-candidate` on its fixture. Sandboxed runner blocks network egress
by default. At least one delivered probe reproduces an end-to-end
finding from start to evidence without operator help.

### Phase 4 — Autonomy

Estimated effort: two to three engineer-months.

Deliverables:

19. Watch layer with all source kinds: `github_commits`,
    `github_releases`, `ghsa_advisories`, `osv_advisories`.
20. Daemon mode with heartbeat logging.
21. Advisory cross-reference and patch-window race auto-queuing.
22. `harness score-tune` from accumulated submission data.
23. MCP wrapper (optional).

Acceptance: the watch layer produces at least one queue entry from a
real-world fresh commit on a watched target. Daemon mode survives a
twenty-four-hour soak. Score-tune produces non-trivial weight
recommendations after twenty terminal-outcome submissions.

---

## 7. Target Directory Structure

```
harness/
  harness.py                       # CLI entrypoint
  __init__.py
  core/
    ledger.py                      # candidate I/O, locking, schema
    state.py                       # run state machine
    schema.py                      # pydantic models
    runner.py                      # subprocess helpers
    sandbox.py                     # container-backed exec
    knowledge.py                   # knowledge tree loader and search
    corpus.py                      # cross-run aggregation
    scoring.py                     # configurable scorer
    workflow.py                    # state-machine enforcement
  agents/                          # reviewer prompts (existing)
  probes/                          # reusable test modules
    base.py
    <probe_name>.py
  knowledge/                       # model-loadable knowledge tree
    INDEX.md
    principles.md
    workflow.md
    patterns.yaml
    scoring.yaml
    programs/
    vuln_classes/
    lessons/
    semgrep/
    codeql/
  targets/                         # target profiles
  watches/
    <target_id>.yaml
    state/
  queue/
    <target_id>/
  corpus/
    candidates.jsonl
    submissions.jsonl
    patterns_coverage.jsonl
    tool_gaps.jsonl
    build_corpus.py
  runs/                            # generated per engagement
  templates/                       # report and candidate templates
  mcp/                             # optional, Phase 4
    server.py
    schema.json
  tests/
    fixtures/
    test_patterns.py
    test_probes.py
    test_workflow.py
    test_ledger.py
  README.md
  CHANGELOG.md
  docs/
    ROADMAP.md
    ARCHITECTURE.md
    CONTRIBUTING.md
    SECURITY.md
```

---

## 8. Engineering Requirements

### 8.1 Determinism

Every command produces deterministic logical output given the same
input state and arguments. Timestamps appear in artifacts only, not in
control flow. No reliance on iteration order of unordered structures.

### 8.2 Idempotency

Re-running a command with the same arguments on the same state must
either produce the same artifact or refuse with a clear error. The
`init` command refuses to re-initialize a populated run directory and
emits a precise error.

### 8.3 Atomicity

All writes follow the temp-then-rename pattern. Read-modify-write paths
acquire an advisory file lock on a sidecar lockfile. Locking is
mandatory for `candidates.yaml`, `state.json`, and any corpus file.

### 8.4 Audit trail

Every candidate mutation appends to `candidate.history[]`. Every
knowledge mutation flows through `harness retro` and produces a
reviewable diff. The harness never silently rewrites knowledge.

### 8.5 Schema validation

All persistent records use pydantic models with auto-migration for
older schema versions. Schema versions are tagged in the file header
and bumped on breaking changes.

### 8.6 Concurrency

Multiple `harness` invocations against the same run directory are safe
through advisory locking. Single-writer per mutator command. Read-only
queries do not block writers.

### 8.7 Cross-platform support

Primary support: macOS and Linux. Windows is out of scope for the core
runtime. The harness must run on x86_64 and arm64.

### 8.8 Performance budgets

- `harness session-start` returns within two seconds on a workstation
  with a one-hundred-megabyte run directory.
- `harness knowledge <query>` returns within two seconds on a fully
  populated knowledge tree of up to one hundred megabytes.
- `harness watch-tick` for a single source returns within sixty
  seconds.

### 8.9 Dependencies

Minimize transitive dependencies. Prefer the standard library and
already-installed tools. New runtime dependencies require justification
in `docs/ARCHITECTURE.md`.

### 8.10 Testing

- Unit tests for ledger, workflow, scoring, knowledge search, schema.
- Integration tests for each probe against a captive fixture.
- Pattern-coverage tests with a fixture corpus.
- CI gates on full suite plus linting.

---

## 9. Security and Compliance Requirements

### 9.1 Authorized testing only

Every target profile carries an `authorization` block describing the
ROE. Commands that interact with external systems verify the ROE
permits the action and refuse otherwise.

### 9.2 No autonomous exploitation

The harness performs reconnaissance, source review, and bounded local
proofs. It does not perform exploitation against systems the operator
has not explicitly authorized. The sandboxed runner exists specifically
to keep external research material isolated.

### 9.3 No destructive testing

Commands that perform mutating actions against any external system are
disabled by default. Operators must enable them per-target with an
explicit flag and a recorded justification.

### 9.4 Rate limits

Every external-facing command (watch polls, advisory fetches, scanner
runs) enforces a configurable rate limit. Defaults are conservative.

### 9.5 No mass scanning

The harness operates one target at a time. Bulk operations across
unrelated targets are not supported.

### 9.6 Reference hygiene

External repositories, payload libraries, prompt collections, and
third-party rulesets are treated as untrusted data. Doctrine and
workflow may be adopted in rewritten form. Code, payloads, and
installer scripts are not executed outside the sandboxed runner. Every
adopted reference is recorded in the engagement's `references.yaml`
with URL, access date, trust level, and the specific items adopted or
explicitly not adopted.

### 9.7 Data handling

The harness does not exfiltrate data. The corpus, submission ledger,
and run artifacts stay local. Operators are responsible for any
external storage they choose to use.

### 9.8 Secrets

The harness does not request, store, or forward authentication
secrets for external systems. Operators provide tokens for the watch
layer (GitHub, OSV) through environment variables, which are read at
runtime and never persisted in artifacts.

### 9.9 Logging

Operational logs are local. They do not contain target credentials,
session tokens, or other sensitive material. Log redaction rules
apply uniformly to all commands.

### 9.10 Sandbox guarantees

The sandboxed runner enforces:

- No network egress by default.
- A configured filesystem allowlist.
- CPU, memory, and PID limits via cgroups.
- A hard wall-clock timeout enforced by the runtime, not by Python.
- A separate user namespace.

A run with a missing or misconfigured container runtime exits with a
non-zero status and a structured error. There is no raw-shell fallback.

---

## 10. Open Design Questions

To resolve before Phase 1 implementation begins:

1. **Container runtime selection.** Docker or Podman as the primary
   sandbox backend, with auto-detection at startup. Both are
   acceptable; the team should pick one as primary based on
   distribution and licensing considerations.
2. **Initial vulnerability-class population.** Which five classes to
   author first in `knowledge/vuln_classes/`. Recommendation:
   `websocket_authz`, `serialization_rce`, `prompt_injection_chain`,
   `parser_canonicalization`, `ssrf_outbound`.
3. **Initial program-profile population.** Which three external program
   templates to author first in `knowledge/programs/`. Recommendation:
   the three most common open-source program platforms, authored
   generically.
4. **Submission ledger entry method.** Manual operator entry for Phase 2,
   thin API clients for Phase 4 once the schema stabilizes.
5. **Embedding-based search.** Phase 1 ships ripgrep plus BM25. A later
   phase may add optional embedding-based knowledge search if local
   embedding tooling is available; this is not a Phase 1 requirement.
6. **CI provider.** Self-hosted runners versus a hosted CI provider for
   pattern-coverage and integration tests.

---

## Appendix A: Glossary

- **Candidate.** A vulnerability hypothesis tracked in the ledger with
  attacker control, surface, sink, impact, and proof state.
- **Probe.** A reusable test module that takes a candidate and a target
  spec, runs a bounded local differential test, and produces evidence.
- **Run.** A single engagement against a single target, with a
  dedicated run directory holding state, ledger, evidence, and reports.
- **Corpus.** The append-only aggregation of past candidates,
  submissions, pattern coverage, and tool gaps across runs.
- **Watch.** A configured set of sources (commits, releases, advisories)
  for a given target that produce queue entries on change.
- **Queue.** Pending auto-candidate seeds surfaced by the watch layer,
  awaiting operator or model claim.
- **ROE.** Rules of engagement for a specific target, recorded in the
  target profile.
- **Substrate.** The set of harness capabilities that an external model
  uses to perform vulnerability research: knowledge, decision rails,
  probes, tools, feedback, and continuous operation.

---

## Appendix B: What This Specification Does Not Solve

The harness does not invent novel vulnerability classes on its own.
With a competent external model on top, the substrate enables finding
known-class variants in fresh code faster than manual review, applying
prior cross-engagement lessons automatically, and reacting to fresh
patches and advisories without operator nudging. That is the realistic
substrate outcome.

External-program submission value remains bounded by program scope,
duplicate density, and triage cycle. The harness raises the floor:
more attempts per unit time, faster rejection of dead ends, and better
submission quality. It does not guarantee acceptance rate or value.

Adversarial-group response time is shortened by the watch layer and
probe library reuse. Without those layers, the harness remains
operator-paced.
