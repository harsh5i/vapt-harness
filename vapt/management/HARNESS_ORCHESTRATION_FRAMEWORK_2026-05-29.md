# Harness Orchestration Framework — Orient the Model, Don't Hope

Date: 2026-05-29
Status: Phase A + B + C all landed 2026-05-29 (commit 714bce6; see section 9)
Author: operator + Claude

## 1. The problem this fixes

The harness today is a **library of 94 commands**. The *methodology* — what to do,
in what order, with what intent, and what to record — lives in the model's head.
It is re-derived on every run and varies with the model, its context, and chance.
That is the "probabilistic performance" we are trying to eliminate.

Concrete evidence from the 2026-05-29 DemoForum run:

- `runs/demo-forum/2026-05-29-initial/state.json` has stages
  `prepare, map, semantic_graph`. It **skipped `source_graph` and `hypothesize`**,
  so **zero candidates ever entered the ledger**.
- The actual hunt (taint triage of ~250 sink lines) was done by hand and written
  to a prose `engagement/demo-forum/findings.md`. None of it passed through
  `candidate-add` / `dedup` / `gate` / `outcome-record`. **The loop never saw the
  work.** `submissions.jsonl` stayed empty, so the learner stayed starved.

The harness *had* a deterministic spine and the model walked around it. A harness
that can be walked around is a toolbox.

## 2. Core principle

**Invert the relationship.** The harness orchestrates; the model is a worker the
harness drives. Methodology stops being vibes and becomes executable structure.

- The model does not decide *what step* to take. The harness computes that.
- The model supplies *intelligence within a bounded step* and returns structured
  evidence.
- State only advances when the step's gate passes. Recording is part of the
  transition, not an optional courtesy.

Rigid on **sequence, gates, recording**. Flexible on **the judgment applied inside
a step**, with a logged escape hatch for justified deviation (§8).

## 3. What already exists (reuse, do not rebuild)

| Capability | Where | Reuse as |
|---|---|---|
| Deterministic step sequencer | `recommend_next_action` (harness.py:5405) | the state machine core — make it binding |
| Engagement state | `state.json` via `load_run` (214) | extend with intent + loop cursor |
| Candidate ledger | `load_candidates` (954), `candidate-add` (1194) | the only sanctioned home for findings |
| Promotion / report gates | `cmd_gate` (1972), `cmd_report_gate` (1913), `promotion_findings` (1705) | transition guards |
| Novelty gate | `dedup_checked` (744), `dedup --check-osv` | transition guard |
| Outcome capture | `cmd_outcome_record` (6250) | the loop's write-back, make automatic |
| Session orientation | `cmd_session_start` (5538) | the loop's read context |
| Budget / scope | `budget_status` (5383), target `in_scope`/`out_of_scope` | step preconditions |
| Campaign machinery | `cmd_campaign_plan` (6963), `campaign_run` (7927), `campaign_gate` (8120) | multi-candidate driver |

The spine exists. It is **advisory**. The work is to make it **binding** and to
**close the loop**.

## 4. What is missing (build) — three pieces

### A. A binding operating loop
A single sanctioned entry point the model must round-trip through:

```
orient  → harness emits ONE bounded step (task + inputs + required artifact + gate)
execute → model performs ONLY that step
submit  → model returns structured result + evidence
advance → harness validates against the gate; on pass, records outcome and
          advances the cursor; on fail, re-emits the same step with the blocker
```

The model is forbidden from free-form scanning outside this loop. "I'll just run
taint-trace and eyeball it" is structurally unavailable — the only way to make
progress is to ask the loop for the next step.

### B. An intent layer (approach the target *with intent*)
`recommend_next_action` is target-agnostic — the same generic order for every
target. "Intent" means a per-target **threat model** captured during recon and
stored in `state.json`, used to **order** hypotheses and triage:

```yaml
intent:
  objective: "find critical/0day; bug-bounty-grade, PoC-backed"
  threat_model:
    prioritized_surfaces:   # drives hypothesis ordering for THIS target
      - {surface: network_ssrf, weight: 1.0, rationale: "DemoForum onebox/webhook fetch paths"}
      - {surface: authz_boundary, weight: 0.9, rationale: "guardian coverage gaps"}
      - {surface: sql_injection, weight: 0.6}
    deprioritized: [memory_safety_native, supply_chain]
    asset_map: [admin endpoints, SSO, upload pipeline, webhooks]
  success_criteria: "reproducible PoC against a hardened instance; gate-clean"
  scope_ref: target.in_scope / target.out_of_scope
```

The sequencer consumes `intent.threat_model` to choose *which* surface to chase
first and to weight scoring, rather than scanning everything uniformly.

### C. A closed outcome loop (improve *basis the executions*)
Every step's result is recorded automatically as a structured outcome, feeding
`submissions.jsonl` + `scoring.yaml` so the next step and future engagements get
sharper. This is what makes the harness *learn* rather than *scan*, and it
structurally fixes the empty-`submissions.jsonl` starvation because recording is
a transition side-effect, not a thing the model may forget.

```jsonl
{"step":"triage","surface":"sql_injection","target":"demo-forum",
 "verdict":"defended","reason":"parameterized_bind","sink":"app/.../x.rb:55",
 "guard":"parameterized_bind","cost_min":3,"ts":"..."}
{"step":"triage","surface":"sql_injection","verdict":"needs_proof",
 "sink":"...search.rb:837 .where(\"... #{tsquery}\")","candidate_id":"CAND-007"}
```

Defended/FP verdicts down-weight that surface×pattern; `needs_proof`/confirmed
up-weights. The guard reasons from the taint precision pass (commit 969a563) feed
directly in as the FP taxonomy.

## 5. The step contract (concrete schema)

`orient` returns one step object; the model returns a matching result object.

```yaml
step:
  id: "S-0007"
  state: "triage"              # phase in the machine
  intent_surface: "sql_injection"
  task: "Triage these 6 unguarded sql_injection flows against source. For each,
          return verdict in {defended, needs_proof, false_positive} + evidence."
  inputs:
    artifact: runs/.../taint_traces/taint_trace_*.md
    items: ["app/.../x.rb:837", ...]
  required_result: "per-item verdict + 1-line evidence + (if needs_proof) candidate-add"
  gate: "every item has a verdict; needs_proof items have a ledger candidate"
  on_pass: advance_to("proof" if any needs_proof else "next_surface")
  deviation_allowed: true       # see §8
```

```yaml
result:
  step_id: "S-0007"
  items:
    - {ref: "...:837", verdict: needs_proof, evidence: "tsquery interpolated; sanitizer unverified", candidate_id: "CAND-007"}
    - {ref: "...:55",  verdict: defended,    evidence: "parameterized_bind", guard: parameterized_bind}
  deviation: null
```

## 6. State model (engagement machine)

States and their advance-gates (reusing existing gate functions):

```
recon ──(prepare done)──▶ map ──(map done)──▶ reachability
  └ writes intent.threat_model                  (source_graph + semantic_graph)
reachability ──▶ hypothesize ──(candidates exist, intent-ordered)──▶ triage
triage ──(every flow has a verdict; guard-aware)──▶ proof
proof  ──(dedup_checked && promotion_findings ok && proof==passed)──▶ enrich
enrich ──(root_cause + variant + patch_diff substantive)──▶ report
report ──(report_gate clean)──▶ submit (engagement/, never the repo)
```

The cursor (current state + per-state checklist) lives in `state.json`. This is
`recommend_next_action`'s ladder, made explicit, intent-ordered, and binding.

## 7. Enforcement (how the bypass becomes impossible)

- **Single entry:** the operator guide instructs the model that the *only*
  sanctioned way to make progress is `orient → submit`. Ad-hoc tool runs are for
  *gathering evidence inside a step*, never for advancing state.
- **Ledger-only findings:** triage verdicts of `needs_proof` MUST create a ledger
  candidate. Prose side-files are not progress. `report` reads the ledger, not
  free text.
- **Gate-blocked transitions:** `proof`/`report` already refuse on unmet
  blockers; wire `triage→proof` to refuse if any flow lacks a verdict.
- **Loop integrity check:** a `phaseN-check`-style fixture asserts that a run
  cannot reach `report` without a cursor trail through every prior state, and
  that every advanced state emitted an outcome record.

## 8. Rigid vs flexible — the deviation escape hatch

Pure rigidity blinkers the model against the target-specific intuition that finds
0days. So: sequence, gates, and recording are rigid; the intelligence *within* a
step is free. When the model believes the next *required* step is wrong (e.g. a
recon insight says jump straight to a specific authz path), it may deviate — but
only via a logged `deviation: {from_step, to, justification}` that:

1. is recorded as an outcome, and
2. is reviewed in retro and, if it paid off, becomes a scoring signal that
   reshapes future intent ordering.

Deviation is allowed, never silent. The harness learns from good deviations
instead of being surprised by them.

## 9. Phasing (reuse-first, each independently shippable)

- **Phase A — bind the spine. [DONE 2026-05-29]** `orient`/step-contract + `submit`
  commands over `recommend_next_action`; `state.loop_cursor` + `loop-integrity-check`
  (3 fixtures under `vapt/harness/tests/fixtures/loop_integrity/`); `triage->proof`
  verdict-gated via `candidate-set --triage-verdict`. Outcomes -> `step_outcomes.jsonl`
  (separate from `submissions.jsonl`).
- **Phase B — intent layer. [DONE 2026-05-29]** `intent-set`/`intent-show` write
  `state.intent.threat_model` from a 6-token `INTENT_VOCAB`; `hypothesize` orders
  matching-kind hypotheses first (survive --max cap), `score` adds bounded +5 to
  aligned candidates. Never suppresses off-intent findings.
- **Phase C — close the outcome loop. [DONE 2026-05-29]** Triage verdicts
  (fp/defended down-weight, needs_proof up-weight) fold into `outcome_tuning`
  weakness adjustments and flow through `_score_candidate`, even with zero
  submissions. Verified by FP smoke: fp-heavy CWE-89 -> adj -5.0 -> candidate
  score 4->3. Phase A already emits per-step outcomes to `step_outcomes.jsonl`;
  Phase C consumes them for tuning.

## 10. Validation

Mirror the existing `phaseN-check` pattern: a fixture engagement that must
(a) refuse to reach `report` if any state was skipped, (b) refuse `triage→proof`
with an unverdicted flow, (c) produce one outcome record per advanced state, and
(d) show intent ordering changing the hypothesis order for two different threat
models. Acceptance is deterministic and CI-able.

## 11. One-line thesis

Make `recommend_next_action` the *only* road, give it *intent*, and make every
step it drives *write back what happened*. The model stops performing and starts
complying — and the harness gets sharper every run instead of starting cold.
