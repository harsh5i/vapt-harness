# Harness Roadmap: Phase 5 - From N-Day Engine to 0day-Capable Substrate

Status: design specification. Phases 1-4 complete per
`MYTHOS_SUBSTRATE_ROADMAP.md` and `MYTHOS_SUBSTRATE_PHASE4_FOUNDATION_2026-05-25.md`.
This document supersedes the strategic intent of
`HARNESS_DISCOVERY_ENGINE_ROADMAP_2026-05-26.md`, which becomes a
historical tactical reference for the Phase 4 discovery work.

Audience: harness engineering team.
Project type: authorized vulnerability assessment and external program
research tooling.

---

## 1. Problem Statement

Phases 1-4 produced a deterministic, gated, provenance-enforced
substrate with 15 probes, 13 agent roles, mutation coverage tracking,
watch/queue ingestion, and an outcome-tuning loop. Audit on 2026-05-28
identified four blocking gaps that prevent the substrate from acting
as a learning engine:

1. `bug_bounties/_shared/corpus/submissions.jsonl` is empty. The
   outcome-tuning loop is wired but starving. Nothing is learned.
2. `harness/harness.py` is 11267 lines, 94 subcommands, 329 defs in
   one file. Parallel agent work and module-scoped refactors are
   compounding in cost.
3. Priority-1 tooling from `VAPT_CAPABILITY_ASSESSMENT.md` (ZAP, sqlmap,
   SecLists, JWT tooling, screenshot pipeline) is still unwired.
4. Target acquisition is manual. Nine targets are hand-picked. The
   watch/queue exists but is fed by humans, not by registry sweeps.

A fifth gap is structural rather than blocking: the probe contract
assumes URL-shaped targets and request/response-shaped outputs. This
forecloses source-reading probes, which are the prerequisite for
logic-flaw 0day discovery.

---

## 2. End Target

The substrate becomes capable of two distinct discovery modes on the
same plumbing:

- **N-day at scale.** Known-pattern probes (HTTP, deserialization,
  SSRF, authz drift, parser canonicalization, etc.) run autonomously
  across a continuously-expanding target set, with outcomes feeding
  back into probe weights. This is the near-term commercial path.
- **Logic-flaw 0day.** Source-reading probes consume `{repo, commit,
  AST}` targets, generate hypotheses about bug classes, and emit
  `{file:line, bug-class, hypothesis, reproducer}` candidates. The
  same gates apply. This is the long-term differentiator.

Out of scope for Phase 5: memory-corruption 0day (requires AFL++ /
libfuzzer / symbex layer), cryptographic flaws (requires symbolic
reasoning), protocol-state 0day (requires deep state-machine modeling).
These remain future phases.

---

## 3. Design Principles (Phase 5)

Inherits all principles from `MYTHOS_SUBSTRATE_ROADMAP.md` ss 3.
Adds:

1. **Earn the right.** Every move must validate against real outcome
   data before the next move depends on it. N-day flywheel must spin
   before source-reading probes are introduced.
2. **Probe-type agnosticism.** Substrate primitives (campaign, gate,
   ledger, mutation, outcome-tune) do not assume URL targets or
   request/response outputs.
3. **Doctrine convergence.** No new strategic doc until a prior one is
   either superseded or explicitly retained as tactical reference.

---

## 4. Move Sequence

The order is load-bearing. Skipping or reordering breaks the earn-the-right
principle.

```text
Move 1: Feed the engine       -> outcome-tune learns
Move 2: Decompose harness.py  -> parallel work unblocked
Move 3: Close the toolchain   -> probes reach full surface
Move 4: Autodiscover targets  -> queue self-populates
Move 5: Generalize probe IF   -> source-reading probes plug in
```

---

## 5. Move 1 - Feed the Engine

Status: not started.

The outcome-tuning loop (`HARNESS_OUTCOME_DRIVEN_TUNING_2026-05-26.md`)
is implemented but has zero input rows. Until real submission outcomes
flow, every weight in the system is a guess.

Sub-tasks:

- Backfill `bug_bounties/_shared/corpus/submissions.jsonl` from any
  prior bounty runs, partial reports, or synthetic outcomes derived
  from known-good fixtures. Tag synthetic rows so they can be excluded
  from production weight updates.
- Add `submission record` CLI subcommand that takes `{campaign_id,
  candidate_id, program, status, payout, triage_notes}` and writes
  an audited row.
- Add OSV cache (`runtime/osv_cache.sqlite`) so dedup gates degrade
  to "cache-only" rather than "incomplete" when offline. Cache TTL
  enforced; staleness surfaced in gate output.
- Verify outcome-tune actually moves weights: run with synthetic
  outcomes that should boost `ssrf_outbound` weight on
  Grafana-shaped targets, confirm next `campaign-plan` reflects it.

Exit criteria:

- `submissions.jsonl` has at least 20 real or labeled-synthetic rows.
- `submission record` round-trips through outcome-tune within one
  command sequence and changes at least one weight by a measurable
  delta.
- `osv-dedup` gate runs offline against cache without marking
  candidates `dedup-incomplete`.

Artifacts:

- `vapt/bug_bounties/_shared/corpus/submissions.jsonl` (populated)
- `vapt/runtime/osv_cache.sqlite`
- `vapt/docs/PHASE5_MOVE1_FEEDING_EVIDENCE_<date>.md`

---

## 6. Move 2 - Decompose harness.py

Status: not started.

The 11267-line monolith blocks the 13-role agent layout from working
concurrently. Split must anticipate Move 5 (source-reading probes), so
the package layout cannot assume URL probes.

Target layout under `vapt/harness/`:

```text
harness/
  cli.py              # entrypoint, dispatch only
  campaign/           # plan, run, score, lifecycle
  probes/             # registry, base class (unchanged)
  gates/              # promote, report, dedup, cvss, osv
  ledger/             # candidates, submissions, outcomes
  watch/              # sources, polling, queue
  mutation/           # variant gen, coverage
  tools/              # external tool wrappers (Move 3)
  source/             # placeholder for Move 5 (repo, AST, diff)
  agents/             # role files (unchanged)
  config/             # yaml configs (unchanged)
```

`harness.py` shrinks to a thin dispatcher that imports from
`harness.cli`. All subcommand handlers move into their owning package.

Sub-tasks:

- Topological extraction: gates first (no dependencies on campaign),
  then ledger, then watch, then mutation, then campaign last.
- Each extracted package must have a `tests/` dir with at least one
  unit test per public function. This addresses the integration-only
  test surface flagged in 2026-05-28 audit.
- `harness.py` retains the existing CLI surface unchanged. No
  subcommand names change. No JSON shapes change.
- Cross-cutting types (`Candidate`, `Campaign`, `RunEvidence`) move
  to `harness/types.py`.

Exit criteria:

- `harness/cli.py` <= 500 lines.
- No file under `harness/` exceeds 1500 lines.
- All existing `phaseN-check` CLI commands pass against fixtures.
- Unit test count >= 50, covering every gate function.

Artifacts:

- `vapt/harness/{cli,types}.py`
- `vapt/harness/{campaign,gates,ledger,watch,mutation,tools,source}/`
- `vapt/harness/tests/`
- `vapt/docs/PHASE5_MOVE2_DECOMP_NOTES_<date>.md`

---

## 7. Move 3 - Close the Toolchain

Status: not started.

`VAPT_CAPABILITY_ASSESSMENT.md` lists ZAP, sqlmap, SecLists, JWT
tooling, and screenshots as Priority-1 unwired. Probes cannot reach
the full surface without them.

Sub-tasks:

- Wrap each tool behind the sandbox runner contract from Phase 3.
  Stable input/output schemas, deterministic exit codes, evidence
  paths written to `runs/<id>/evidence/<tool>/`.
- ZAP: passive scan + active scan modes, JSON report parser.
- sqlmap: parameterized run with `--batch --crawl=0`, evidence
  capture of injection points.
- SecLists: vendored as a submodule or pinned tarball under
  `vapt/env/seclists/`; probes reference by path.
- JWT tooling: `jwt_tool` or in-house equivalent for none-alg,
  weak-key, kid-injection, jku-confusion probes.
- Screenshot pipeline: Playwright headless capture for
  visual-evidence candidates.

Exit criteria:

- `VAPT_CAPABILITY_ASSESSMENT.md` Priority-1 column is all
  `wired`.
- At least one probe per tool produces a real candidate against
  a captive fixture.
- Sandbox runner enforces network egress restrictions for active
  tools (no egress beyond declared target hosts).

Artifacts:

- `vapt/harness/tools/{zap,sqlmap,jwt,screenshot}.py`
- `vapt/env/seclists/` (pinned)
- `vapt/harness/probes/*` (new probes leveraging wrapped tools)
- `vapt/docs/PHASE5_MOVE3_TOOLCHAIN_CLOSURE_<date>.md`

---

## 8. Move 4 - Autodiscover Targets

Status: not started.

Phase 4 wired watch/queue ingestion but feeds remain manual: a human
chooses what to watch. Move 4 closes that loop.

Sub-tasks:

- Add `discovery/` watch source family:
  - GHSA delta polling: new advisories since last cursor become
    queue candidates.
  - OSV feed polling: same, against OSV-format ecosystems.
  - Registry sweeps: PyPI, npm, crates.io top-N by download count,
    filtered by bug-bounty-program membership lookup.
  - CVE delta polling: NVD JSON feed cursor.
- Add `discovery-plan` CLI: ranks newly discovered targets by
  surface signals (recent commits, advisory density, program
  payout history).
- Queue entries from autodiscovery carry `source: auto` tag and
  must pass the same scope/authorization check before campaign
  promotion. No auto-discovered target runs without an explicit
  operator claim.

Exit criteria:

- 24-hour soak run produces >= 10 queue entries from autodiscovery
  alone.
- Zero auto-discovered targets reach a campaign without an
  operator claim.
- Scope-check rejection rate is logged and queryable.

Artifacts:

- `vapt/harness/watch/discovery/{ghsa,osv,registry,nvd}.py`
- `vapt/runtime/discovery_cursors.json`
- `vapt/docs/PHASE5_MOVE4_AUTODISCOVERY_SOAK_<date>.md`

---

## 9. Move 5 - Generalize the Probe Interface

Status: not started. Depends on Moves 1-4.

The probe contract today assumes URL-shaped targets and HTTP-shaped
output. This forecloses source-reading probes, which are the path to
logic-flaw 0day. Move 5 widens the contract without breaking existing
probes.

Sub-tasks:

- Widen `Target` to a tagged union:
  - `TargetURL{url, headers, auth, scope}` (existing).
  - `TargetRepo{repo, commit, dep_graph, ast_index, scope}` (new).
- Widen `ProbeOutput` to a tagged union:
  - `ProbeOutputRequest{request, response, evidence}` (existing).
  - `ProbeOutputCodeFinding{file, line, bug_class, hypothesis,
    reproducer_steps, evidence}` (new).
- Add `source/` package primitives:
  - `acquire(repo, commit)` -> local mirror with locked SHA.
  - `index(mirror)` -> AST index using `tree-sitter` for top 8
    languages.
  - `dep_graph(mirror)` -> import/call graph.
- Add at least two reference source-reading probes to validate the
  contract:
  - `patch_variant_hunter`: given a fixed CVE patch, find the same
    bug class elsewhere in the codebase.
  - `auth_chain_audit`: trace authorization decisions across
    routes, flag missing checks.
- Outcome-tune learns separate weight curves for `ProbeOutputRequest`
  and `ProbeOutputCodeFinding` classes. Same loop, different bins.

Exit criteria:

- All 15 existing probes continue to run without modification.
- Both reference source-reading probes produce candidates against
  a captive fixture repo with seeded bugs.
- At least one source-reading candidate passes the full gate
  (promote, report, dedup, CVSS) end-to-end.
- Outcome-tune updates code-finding weights independently of
  request weights, verified by synthetic outcomes.

Artifacts:

- `vapt/harness/types.py` (widened Target, ProbeOutput)
- `vapt/harness/source/{acquire,index,dep_graph}.py`
- `vapt/harness/probes/{patch_variant_hunter,auth_chain_audit}.py`
- `vapt/bug_bounties/_fixtures/seeded_bugs_repo/`
- `vapt/docs/PHASE5_MOVE5_PROBE_GENERALIZATION_<date>.md`

---

## 10. Capabilities Unlocked by Phase Position

The substrate's discovery capability is bounded by which moves are
complete. This is the honest mapping flagged in the 2026-05-28
conversation.

| After Move | Capability |
|------------|-----------|
| Move 1 done | Outcome-tuned n-day discovery on existing 9 targets. |
| Move 2 done | Maintainable substrate; parallel agent work feasible. |
| Move 3 done | Full-surface n-day reach; ZAP/sqlmap/JWT/SecLists probes online. |
| Move 4 done | Continuous n-day discovery across self-acquired targets. |
| Move 5 done | Logic-flaw 0day candidate generation, same gates. |

What Phase 5 does **not** deliver, even after Move 5:

- Memory-corruption 0day (no fuzzing layer).
- Cryptographic flaw discovery (no symbolic reasoning).
- Protocol-state 0day (no state-machine modeling).
- 0day in well-audited surface (substrate cannot out-research
  full-time human teams who have already mapped that surface).

---

## 11. Risks

- **Synthetic submission bias.** Backfilling `submissions.jsonl` with
  synthetic rows can teach outcome-tune the wrong weights. Mitigation:
  tag synthetic rows and gate them behind an `--include-synthetic`
  flag in tune runs.
- **Decomposition regression.** Splitting a 11.2K monolith with
  integration-only tests risks silent breakage. Mitigation: snapshot
  all `phaseN-check` outputs against a frozen fixture set before
  starting Move 2, diff after each extraction step.
- **Tool sandbox drift.** Active scanners (ZAP, sqlmap) can cause
  collateral if egress rules slip. Mitigation: sandbox runner default-
  denies egress; per-target allowlists derived from scope file.
- **Autodiscovery scope leak.** Auto-acquired targets could promote
  out-of-program work. Mitigation: explicit operator claim before
  campaign promotion is non-negotiable.
- **Source-reading hallucination.** LLM-driven source probes will
  produce plausible-sounding candidates with no real bug. Mitigation:
  the reproducer field is required, the gate enforces a working
  reproducer before promotion. Same gate, no special case.

---

## 12. Open Items Carried Forward

From `MYTHOS_SUBSTRATE_ROADMAP.md`:

- 24-hour daemon soak still pending (cannot be time-compressed).

From `HARNESS_DISCOVERY_ENGINE_ROADMAP_2026-05-26.md`:

- Mutation coverage executor-enforcement (currently plan/record only).
  Folded into Move 2 decomposition: mutation package gets enforcement
  hooks once isolated.

New, from 2026-05-28 audit:

- Empty `submissions.jsonl`. Move 1 owns this.
- 11267-line `harness.py`. Move 2 owns this.
- Priority-1 unwired tools. Move 3 owns this.
- Manual target acquisition. Move 4 owns this.
- URL-shaped probe contract. Move 5 owns this.

---

## 13. Document Status

- **This document:** active doctrine for Phase 5.
- **`MYTHOS_SUBSTRATE_ROADMAP.md`:** retained as foundational
  doctrine, covers Phases 1-4 and substrate principles.
- **`HARNESS_DISCOVERY_ENGINE_ROADMAP_2026-05-26.md`:** demoted to
  tactical reference for the discovery engine work that landed in
  Phase 4. Strategic intent is superseded by this document.

Future Phase 5 implementation docs follow the existing convention:
`MYTHOS_SUBSTRATE_PHASE5_MOVE<N>_<TOPIC>_<date>.md`.
