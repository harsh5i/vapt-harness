# LLM Operator Guide

Audience: an external language model with shell access that is being
asked to perform authorized vulnerability research using this harness.

This document is the cold-start contract. Read it end-to-end before
running any command. If you are resuming a prior engagement, also read
the run directory's `prepare.json` and the most recent candidate
ledger before acting.

This guide unifies and points at three existing surfaces:

- `vapt/harness/knowledge/INDEX.md`, `principles.md`, `workflow.md`,
  `scoring.yaml` - doctrine and the candidate state machine.
- `vapt/harness/agents/*.md` - per-role checklists (you adopt one at a
  time depending on the lifecycle stage).
- `vapt/management/MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` and
  per-Move evidence docs - architecture context and current capability
  state.

If this guide and any of the above disagree, follow this guide for
operating norms and the existing docs for technical contracts. Report
the conflict in your session output so the maintainer can reconcile.

### Repository layout (Mandatory -> Management -> Records)

When you enter `vapt/` you will see exactly four things:

- `ONBOARDING.md` (this file) - the mandatory cold-start contract.
- `harness/` - the engine: `harness.py`, `knowledge/`, `agents/`,
  `config/`, `probes/`, `gates/`, captive `fixtures/`, and the
  cross-engagement learning `corpus/` (candidates + submissions).
  Everything needed to *run* the harness lives here.
- `engagements/` - the Records bucket. One subfolder per target,
  structured as the harness directs: `engagements/<target>/targets/`,
  `adapters/`, and `runs/<target>/<run-id>/`. This is gitignored
  per-target; bounty data never enters the public mirror.
- `management/` - roadmaps, plans, design notes, diagnostics. Context
  for *improving* the harness, not part of execution.

Records are written under `engagements/`; never write findings into
`management/` or as prose side-files. The ledger under each run dir is
the only sanctioned home for candidates.

---

## 1. Identity and authorization

You are an external operator. The harness is not a model and does not
make authorization decisions for you. The hard rules are:

1. **Only act on declared, authorized targets.** A target is declared
   when a `targets/<id>.yaml` profile exists under
   `vapt/engagements/<program>/` AND that program's scope explicitly
   permits the action you are about to take.
2. **Never run active scans, exploitation, denial-of-service, or
   credential attacks** unless the program's ROE explicitly permits
   them. Default assumption is read-only outside-in research.
3. **Never bypass the gate stack.** If `harness gate` blocks
   promotion, fix the missing artifact; do not edit `dedup.status`,
   `proof`, or `cvss` by hand to make the gate pass.
4. **Never submit a candidate without a working reproducer.** The
   substrate refuses to mark a candidate report-ready without one.
5. **Stay inside the harness.** If you want to deviate (e.g., touch a
   file outside the run dir, install a tool, change a hard rule),
   stop and ask the human operator. Do not improvise.

If at any point you find you have run a probe against an unauthorized
host, an unscoped path, or an out-of-program endpoint, **stop, record
what happened in the run's `notes`, and surface it to the operator**.
Do not delete evidence.

---

## 2. Cold-start orientation

At the start of any session, run this exact sequence and let the
output inform what to do next:

```bash
# 1. What tools can I actually reach?
python3 vapt/harness/harness.py tools-capability --json
python3 vapt/harness/harness.py tool-health --json

# 2. What targets exist and which are mine?
ls vapt/engagements/*/targets/*.yaml

# 3. What ongoing work is there?
ls -d vapt/engagements/*/runs/*/* 2>/dev/null
ls vapt/harness/queue/discovery/ 2>/dev/null

# 4. What does current doctrine say?
ls vapt/harness/knowledge/
head -40 vapt/harness/knowledge/principles.md
```

From the output you derive:

- which probe families are reachable today (Move 3 tools may refuse
  if Docker is not installed)
- which programs and targets you are authorized to touch
- whether there are abandoned runs to resume or new discovery
  proposals awaiting claim
- which doctrine constants apply (severity thresholds, dedup sources,
  scoring weights)

Never assume the toolchain or scope from prior sessions. Always
re-derive from the live filesystem.

---

## 3. The lifecycle and where you are in it

The canonical state machine lives in
`vapt/harness/knowledge/workflow.md`. Summary:

```
candidate -> deduped -> promoted -> proved -> root_cause_recorded
  -> variant_searched -> patch_diffed -> report_ready -> submitted
  -> triaged | duplicate | n_a | resolved | paid
```

Every CLI subcommand is associated with one or more transitions. Your
job is to push a candidate forward one transition at a time and never
to skip steps. If a stage cannot complete (e.g., no patch available),
record the reason in the candidate's `notes` and continue; do not
omit the artifact.

### 3.1 The binding loop: `orient` -> run -> `submit`

Do not choose commands by intuition. The harness decides the next step;
you execute it. The loop is:

```
orient <run>        # harness issues ONE step: a command, a gate, an expected result
<run the command>   # do exactly what the step says
submit <run> [...]  # record the outcome; the cursor advances only if the
                    # recommendation actually changed
```

- `orient` is idempotent: calling it again before you act re-emits the
  same step (`reissued: true`). It never skips ahead.
- `submit` will **not** advance the cursor if the step's required result
  is still missing - it returns `advanced: false` with a blocker. That is
  the harness refusing to let you fake progress.
- Triage is a hard gate. A flow with no `triage_verdict` blocks all proof
  work. `orient` will hand you a `candidate-set ... --triage-verdict
  <needs_proof|defended|false_positive>` step; classify the flow, then
  `submit --triage-verdict <verdict>`. Only `needs_proof` candidates
  proceed to dedup/gate/proof. `defended` and `false_positive` are
  retired with no further work.
- Every advance writes a row to `step_outcomes.jsonl` (the closed learning
  loop, separate from bounty `submissions.jsonl`) and appends to the run's
  `loop_cursor.history` with an `outcome_id`.
- `loop-integrity-check --run-dir <run>` audits the cursor: states must be
  reached in canonical order, no proof without a `needs_proof` verdict,
  every history step carries an `outcome_id`.

`next-action` still exists as a read-only advisory view, but the binding
contract is `orient`/`submit`. Drive the harness through them.

### 3.2 Intent: declare the threat model before you hypothesize

Set the run's threat model early so the harness orients itself, not just
you. `intent-set <run> --threat <token> [--threat <token> ...]` records a
prioritised threat model from this vocabulary:

```
realtime_authz_drift  route_authz_gap        parser_storage_boundary
ssrf_outbound_boundary  command_execution_boundary  native_memory_boundary
```

Effect:

- `hypothesize` floats hypotheses whose kind matches the intent to the top
  (and marks them `intent-priority`), so they survive the `--max-hypotheses`
  cap instead of being truncated away.
- `score` adds a bounded `+5` to candidates whose weakness/CWE/impact aligns
  with the intent (recorded as an `intent-aligned` strength).

Intent **never suppresses** off-intent findings - it only orders and nudges.
A real bug outside your stated threat model still scores and still reports.
`intent-show <run>` prints the current threat model.

---

## 4. Role files: pick the right hat per stage

`vapt/harness/agents/` holds 13 role files. Each describes a focused
mental model. Adopt one at a time; do not try to be all of them at
once. Mapping from lifecycle stage to role:

| Stage | Role file to read first |
|------|-------------------------|
| Initial surface mapping | `source_mapper.md` |
| Source-reading bug hunt | `root_cause_variant.md`, `patch_diff_advisory.md` |
| Web protocol research | `web_protocol_research.md`, `websocket_authz.md` |
| Deserialization audit | `deserialization.md`, `memory_safety_research.md` |
| Fuzz / property probing | `fuzz_prover.md` |
| Reproducer building | `atomic_validation.md`, `exploitability_ladder.md` |
| Dedup discipline | `dedup_skeptic.md`, `reference_hygiene.md` |
| AI-system specifics | `ai_security_reviewer.md` |

A role file is not a permission to expand scope. It is a checklist of
what evidence the next gate expects from you while you are in that
stage.

---

## 5. Commands grouped by lifecycle

Below are the harness's load-bearing subcommands. Run
`python3 vapt/harness/harness.py --help` for the full surface.

### 5.1 Setup and discovery

```bash
# Convert an authorized program into a fresh run dir
harness init <target_id> [--run-id <slug>]

# Fingerprint source, capture deps
harness prepare <run_dir> [--allow-non-git]

# Lightweight pattern map across source
harness map <run_dir> [--max-hits 40]

# Discover new authorized-program candidates (cross-target)
harness discovery-sweep --severity-floor high --since-days 7
harness discovery-list
harness discovery-claim <slug> --claimed-by you
```

Throughout this guide, `harness` is shorthand for
`python3 vapt/harness/harness.py`.

### 5.2 Candidate creation and proof

```bash
# Create a candidate in a run
harness candidate-add <run_dir> \
  --title "..." --surface "..." --weakness "CWE-..." \
  --impact "..." --attacker-control "..." --sink "..."

# Run a probe to substantiate the thesis
harness source-probe --local-path <repo_path>           # Move 5 substrate
harness scan-semgrep <run_dir> [--ruleset PATH]         # Phase 3 toolchain
harness scan-jwt <run_dir> --token "<jwt>"              # Move 3 JWT audit
harness scan-zap-baseline <run_dir> <url>               # Move 3 (needs Docker)
harness scan-sqlmap <run_dir> --target-url "<url>"      # Move 3 (needs Docker)
```

After producing evidence, attach it to the candidate via the
candidate ledger; the gates inspect candidate fields, not free-floating
files.

### 5.3 Dedup, promotion, and report

```bash
# Dedup with offline-safe OSV cache
harness dedup <run_dir> [<candidate_id>] --check-osv \
  --osv-ecosystem PyPI --osv-package <name> [--osv-cache-only]

# Promote (gate-enforced)
harness gate <run_dir> <candidate_id> --promote

# Strict report-readiness gate before any submission
harness report-gate <run_dir> [<candidate_id>] --mark-ready --fail

# Submission ledger
harness submissions add <run_dir> <candidate_id> --platform <h1|bugcrowd|huntr|...> --id <ext_id>
harness outcome-record --run-dir <run_dir> --candidate-id <id> --status triaged|duplicate|...
```

### 5.4 Learning and tuning

```bash
# Seed synthetic outcomes for development (auto-excluded in prod runs)
harness submissions seed-synthetic
harness submissions seed-synthetic --clear

# Build outcome-derived scoring weights
harness outcome-tune                       # production: synthetic excluded
harness outcome-tune --include-synthetic   # development: synthetic included
```

### 5.5 OSV cache

```bash
harness osv-cache stats --json
harness osv-cache prefetch <target_id> [<target_id> ...]
harness osv-cache clear
```

Use `--osv-cache-only` on `dedup` when you are offline. The substrate
refuses to claim `no-known-duplicate` without a real lookup; a
cache-only run with no cache entry surfaces as `dedup-incomplete`
rather than a silent false negative.

### 5.6 Acceptance checks

When in doubt, run an acceptance check against fixtures to confirm
your wiring is intact:

```bash
harness outcome-tune-check --fail --json
harness campaign-flow-check --fail --json
harness campaign-adapter-check --target <id> --fail
harness mutation-coverage-check --fail --json
harness phase2-check --fail --json
harness phase3-check --fail --json
harness phase4-check --fail --json
```

A green check is a precondition for trusting your code paths. A red
check is an instruction to fix before continuing.

---

## 6. Gates and what they reject

Three gates matter:

- **`gate` (promotion gate).** Fails if `dedup.status` is missing,
  `cvss` is invalid, the candidate has no `proof: passed`, or
  `latest_affected` is not set. Fixing means doing the missing work;
  not editing fields by hand.
- **`report-gate` (report-readiness gate).** Adds: variant search must
  exist or be explicitly scoped out; negative controls must be
  recorded; CWE/CVSS must be coherent; the dedup record must cite
  sources actually checked (not "I will check later"); a working
  reproducer must be referenced.
- **OSV `dedup`.** Will mark a candidate `dedup-incomplete` when the
  cache cannot answer offline and the network call failed. Do NOT
  promote a candidate in that state.

Gate failures are not bugs in the harness. They are the substrate
telling you what is missing. Treat them as a worklist.

---

## 7. Pitfalls and silent failure modes

These have bitten prior operators. Recognize them.

1. **Cache-only without warming the cache.** If you run dedup with
   `--osv-cache-only` and the cache is empty, every candidate degrades
   to `dedup-incomplete`. Run `harness osv-cache prefetch <target>`
   first.
2. **Synthetic data leaking into production tune.** Always confirm
   `outcome-tune` is invoked without `--include-synthetic` for any
   production weight update. The default is safe; explicit flags can
   bypass it.
3. **Scope drift.** If you observe yourself about to scan a host that
   is not in the target's `targets/<id>.yaml` scope block, stop. Do
   not run the command, do not rationalize it.
4. **Auto-discovered targets bypassing claim.** A proposal in
   `vapt/harness/queue/discovery/` is not authorization to act. It is
   a candidate target. The operator must claim it (`discovery-claim`)
   and convert it to a watch (`watch-add`) before any probe runs
   against it.
5. **Module heuristic gaps.** The synthetic seeder and some auto-
   labellers use coarse keyword maps. If you see almost everything
   tagged `manual_review`, refine the mapping in
   `harness.SYNTHETIC_OUTCOME_DISTRIBUTION` or related helpers - do
   not work around it by re-tagging rows.
6. **Source-probe taint blind spot.** The Python AST classifier is
   single-statement. It misses bugs where untrusted data flows
   through one intermediate variable. For known-class hunts, also
   read the call sites by hand. Do not over-trust empty results.
7. **Container-tool refusals.** ZAP / sqlmap / jwt_tool will write a
   `*.missing.json` refusal record when no container runtime is
   available. That is not a bug; it is the capability gap surfacing.
   Either install Docker or use a local binary.

---

## 8. End-to-end worked example

Goal: take a hypothetical authorized PyPI package `widgety` from
"interesting" to a submittable candidate using only the harness.

```bash
# 1. Make sure the program/target is declared and authorized.
ls vapt/engagements/widgety/targets/widgety.yaml  # must exist

# 2. Initialize a run.
RUN_ID=2026-05-29-initial
harness init widgety --run-id $RUN_ID
RUN_DIR=vapt/engagements/widgety/runs/widgety/$RUN_ID

# 3. Prepare and map the source.
harness prepare $RUN_DIR
harness map $RUN_DIR

# 4. Surface source-reading hypotheses (Move 5).
harness source-probe \
  --local-path $RUN_DIR/source \
  --bug-classes cmd_injection_shell_true sql_injection_string_format \
  --json > $RUN_DIR/evidence/source_probe.json

# 5. Pick the most promising hypothesis and create a candidate.
harness candidate-add $RUN_DIR \
  --title "widgety subprocess shell=True on user input in cli.py" \
  --surface "widgety.cli.run command" \
  --weakness "CWE-78" \
  --impact "RCE on user host when widgety processes attacker-supplied filename" \
  --attacker-control "filename argument from CLI / config / package metadata" \
  --sink "subprocess.run(..., shell=True) at widgety/cli.py:84"

# 6. Build a reproducer in a clean sandbox.
# (out of scope for the harness; produce a script + sample inputs,
#  store under $RUN_DIR/evidence/<candidate_id>/repro.sh)

# 7. Dedup against OSV (warm cache first if you are offline).
harness osv-cache prefetch widgety
harness dedup $RUN_DIR <CAND_ID> --check-osv \
  --osv-ecosystem PyPI --osv-package widgety

# 8. Run the promotion gate.
harness gate $RUN_DIR <CAND_ID> --promote

# 9. Record root cause, search for variants, capture patch diff if
#    a fix exists. Each step writes an artifact the next gate checks.

# 10. Final strict gate before submitting.
harness report-gate $RUN_DIR <CAND_ID> --mark-ready --fail

# 11. Submit and later record the outcome.
harness submissions add $RUN_DIR <CAND_ID> --platform huntr --id HUNT-XXXX
harness outcome-record --run-dir $RUN_DIR --candidate-id <CAND_ID> \
  --status triaged --note "h1 acknowledged within 6h"
```

Every step writes a durable artifact under `$RUN_DIR`. If you crash
or hand off mid-session, the next operator (or you on resume) can
reconstruct state by reading the run directory alone.

---

## 9. What is explicitly out of scope for you as the LLM

- Editing files outside `vapt/engagements/<program>/runs/<run_id>/`
  except for the harness's own ledger writes.
- Installing system packages, modifying `~/.venv-vapt`, pulling
  container images. These are operator-environment changes; surface
  the need and stop.
- Running probes against unauthorized hosts. This includes
  "exploratory" pings.
- Writing or modifying scoring weights, gate logic, or workflow.md
  semantics. These are doctrine. Propose changes; do not perform
  them silently.
- Claiming a candidate is novel without running `dedup --check-osv`
  against a populated cache or live network.
- Skipping `report-gate` because "the gate seems pedantic". The
  pedantry is the product.

If you find yourself wanting to do any of these, stop and report.

---

## 10. Quick reference: the doctrine surfaces

You will reach for these often:

- `vapt/harness/knowledge/INDEX.md` - which doctrine doc to read for
  which question.
- `vapt/harness/knowledge/principles.md` - the substrate's
  non-negotiables.
- `vapt/harness/knowledge/workflow.md` - the candidate state machine
  with transition preconditions.
- `vapt/harness/knowledge/scoring.yaml` - scoring weights that the
  gate and prioritization read.
- `vapt/harness/knowledge/patterns.yaml` - canonical surface and sink
  patterns.
- `vapt/harness/knowledge/vuln_classes/` - one-pagers per vuln class
  with reproducer skeletons.
- `vapt/harness/knowledge/programs/` - per-program scope, payout,
  triage notes.

Read these before improvising. They encode lessons the harness was
designed around.

---

## 11. When you are unsure

Default to the slow, deterministic path: read more doctrine, run an
acceptance check, ask the operator. Do not move a candidate forward
on intuition. Every shortcut you take here pollutes the outcome data
the substrate uses to learn.

The harness is opinionated on purpose. Trust the opinions; they were
won the expensive way.
