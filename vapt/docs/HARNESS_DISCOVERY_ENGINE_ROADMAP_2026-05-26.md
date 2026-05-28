# Harness Discovery Engine Roadmap - 2026-05-26

## Problem

The harness is good at recording, gating, and proving candidates, but weak at
forcing discovery. Learnings are captured in docs and Flux, yet too few become
executable modules, mutations, coverage gates, or next actions.

## Objective

Upgrade the harness from an artifact manager into a campaign engine:

```text
target profile -> campaign plan -> module execution -> coverage result ->
mutation/next module -> candidate or closed boundary
```

## Phase 1 - Planner And Coverage

Status: `implemented`

- Add a reusable module catalog.
- Add `campaign-plan` to rank modules from target scope and prior run evidence.
- Emit missing coverage and next best modules after every negative campaign.
- Keep target adapters and target runtimes under `vapt/bug_bounties/<target>/`.

Exit criteria:

- `campaign-plan` works for Grafana OSS and demo-pyml.
- Plan output distinguishes tested, partial, candidate, and untested modules.

Artifacts:

- `vapt/harness/config/campaign_modules.yaml`
- `vapt/bug_bounties/grafana-oss/docs/CAMPAIGN_PLAN_2026-05-26.md`
- `vapt/bug_bounties/demo-pyml/docs/CAMPAIGN_PLAN_2026-05-26.md`
- `vapt/bug_bounties/demo-mlops/docs/CAMPAIGN_PLAN_2026-05-26.md`

## Phase 2 - Generic Module Interface

Status: `implemented`

- Define a target-agnostic module contract.
- Define adapter requirements per module.
- Convert Grafana authz/SSRF logic into generic module shape with Grafana adapter wrappers.

Exit criteria:

- No target-specific runtime code is added under `vapt/harness`.
- Generic modules can declare required adapter methods and stop conditions.

Artifacts:

- `vapt/harness/config/module_contract.yaml`
- `vapt/bug_bounties/grafana-oss/adapters/grafana_oss.yaml`
- `vapt/bug_bounties/grafana-oss/docs/CAMPAIGN_ADAPTER_CHECK_2026-05-26.md`
- `vapt/bug_bounties/grafana-oss/tests/phase2-alias-smoke/`

Notes:

- `campaign-adapter-check --target grafana_oss --fail` validates the Grafana
  adapter against the generic module catalog.
- `grafana_campaign.py` accepts generic module IDs (`authz_matrix`,
  `ssrf_callback`) and maps them to target-local implementations.

## Phase 3 - Mutation Engine

Status: `implemented-initial`

- Add variant generators for roles, object ownership, stale IDs, redirects,
  encodings, symlinks, parser edge cases, and token scopes.
- Store mutation coverage in run evidence.

Exit criteria:

- Each runtime module executes multiple variants, not one happy path and one
  negative path.

Artifacts:

- `vapt/harness/config/mutation_catalog.yaml`
- `vapt/harness/harness.py mutation-plan`
- `vapt/bug_bounties/grafana-oss/docs/MUTATION_PLAN_2026-05-26.md`
- `vapt/bug_bounties/grafana-oss/runs/grafana-oss/2026-05-26-campaign-2/evidence/mutation_coverage/all_modules.json`

Notes:

- Grafana adapter modules now declare mutation families.
- Adapter validation checks unknown mutation family IDs.
- Current implementation plans and records mutation coverage. The next hardening
  step is executor-level enforcement that a module result references the
  mutation variants it actually executed.

## Phase 4 - Patch-First Novelty

Status: `implemented-initial`

- Rank recent security fixes and advisory-adjacent changes before broad scans.
- Queue incomplete-fix and sibling-variant hypotheses.
- Persist duplicate/advisory references as first-class evidence.

Exit criteria:

- Mature targets default to patch-diff campaigns before generic broad scans.

Artifacts:

- `vapt/harness/harness.py patch-first-plan`
- `vapt/bug_bounties/grafana-oss/docs/PATCH_FIRST_PLAN_2026-05-26.md`
- `vapt/bug_bounties/demo-pyml/docs/PATCH_FIRST_PLAN_2026-05-26.md`

Notes:

- `patch-first-plan` ranks locally available release diffs, known advisories,
  and watch queue entries before generic campaign modules.
- Target profile lookup now accepts both profile filenames and target `id`
  values, so `grafana-oss` and `grafana_oss` both resolve correctly.

## Phase 5 - Campaign Dashboard

Status: `implemented-initial`

- Add a target coverage dashboard showing closed, partial, untested, and
  candidate-producing boundaries.
- Require a next action for every `no_findings` campaign.

Exit criteria:

- A user can see why the harness stopped, what remains untested, and which
  module should run next.

Artifacts:

- `vapt/harness/harness.py campaign-dashboard`
- `vapt/bug_bounties/grafana-oss/docs/CAMPAIGN_DASHBOARD_2026-05-26.md`
- `vapt/bug_bounties/demo-pyml/docs/CAMPAIGN_DASHBOARD_2026-05-26.md`

Notes:

- Dashboard output lists closed, partial, candidate-signal, tested-unknown, and
  untested module counts.
- Every non-closed module receives a required next action.
- Prior `no_findings` campaigns receive an explicit next action instead of
  silently ending the BB effort.

## Current Increment

Phase 2 completed with:

- `vapt/harness/config/module_contract.yaml`
- `vapt/harness/harness.py campaign-adapter-check`
- `vapt/bug_bounties/grafana-oss/adapters/grafana_oss.yaml`

Post-roadmap hardening completed:

- `vapt/harness/harness.py mutation-coverage-check`
- `vapt/docs/HARNESS_MUTATION_COVERAGE_VALIDATOR_2026-05-26.md`
- `vapt/bug_bounties/grafana-oss/docs/MUTATION_COVERAGE_CHECK_2026-05-26.md`
- `vapt/harness/harness.py campaign-run`
- `vapt/docs/HARNESS_GENERIC_CAMPAIGN_RUNNER_2026-05-26.md`
- `vapt/harness/tests/fixtures/adapters/fixture_adapter.yaml`
- `vapt/harness/tests/results/campaign-run-fixture/orchestrator/campaign_run.json`
- `vapt/harness/harness.py campaign-gate`
- `vapt/docs/HARNESS_CAMPAIGN_LIFECYCLE_GATE_2026-05-26.md`
- `vapt/harness/tests/results/campaign-run-fixture/orchestrator/campaign_gate.json`
- `vapt/harness/harness.py candidate-link-campaign`
- `vapt/docs/HARNESS_CANDIDATE_CAMPAIGN_GATE_INTEGRATION_2026-05-26.md`
- `vapt/harness/tests/results/candidate-campaign-gate-fixture/candidates.yaml`
- `vapt/harness/harness.py campaign-start`
- `vapt/docs/HARNESS_CAMPAIGN_START_2026-05-26.md`
- `vapt/bug_bounties/demo-pyml/campaigns/harness-start-smoke/campaign_start.json`
- `vapt/bug_bounties/grafana-oss/campaigns/harness-start-smoke/campaign_start.json`

Completed increment: `campaign-start --refresh-advisories` now refreshes
OSV/GHSA-style advisory sources into the watch queue, writes
`advisory_refresh.md/json` into the campaign workspace, and adds fresh
`queue claim` steps to `NEXT_COMMANDS.md`.

Completed increment: `candidate-add` now auto-attaches `campaign_start` context
when run inside a campaign workspace, records candidates as `campaign_seed`, and
promotion/report gates block them until campaign run/gate evidence is linked.

Completed increment: `candidate-from-queue` now converts claimed watch/advisory
queue entries into candidates, records queue provenance, marks queue entries
`converted`, and makes promotion/report gates validate queue provenance.

Completed increment: `campaign-flow-check` now runs campaign start, advisory
refresh, queue conversion, campaign run, campaign gate, candidate linkage, and
queue/campaign provenance validation as one harness health path.

Completed increment: `outcome-record`, `outcome-tune`, and
`outcome-tune-check` now capture terminal results and feed learned module,
evidence-kind, and weakness/CWE adjustments into `campaign-plan` and `score`.

Next increment is target-class playbook generation from outcome history:
for a new target, the harness should emit the highest-performing modules,
proof patterns, and anti-patterns for that target class before any scanning.
