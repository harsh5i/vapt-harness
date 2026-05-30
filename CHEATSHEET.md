# VAPT Harness — Operator Cheat Sheet

One page. The 80% of daily usage. Authoritative capability status lives in
[`STATUS.md`](STATUS.md); workflow contracts live in
[`vapt/ONBOARDING.md`](vapt/ONBOARDING.md).

All commands are `python3 vapt/harness/harness.py <verb>` from the repo root.
The `_h` shorthand below stands for that prefix.

## Lifecycle (cold start to submitted)

```
_h init <target.yaml>             # initialize a target profile
_h session-start <run_dir>        # emit cold-start JSON for a fresh run
_h next-action <run_dir>          # advisory: what the harness thinks is next
_h orient <run_dir>               # issue THE next binding step (step contract)
_h submit <run_dir>               # record the pending step's outcome + advance
```

`orient` and `submit` are the binding loop. `next-action` is advisory; if
output drifts from `orient`, trust `orient`.

## Candidate workflow

```
_h candidate-add <run_dir>        --title ... --weakness CWE-... ...
_h candidate-from-queue <run_dir> <queue_id>
_h candidates <run_dir>           [--json]
_h candidate-set <run_dir> <id> --status <state> [--triage-verdict ...]
_h dedup <run_dir> [--candidate-id ...] [--check-osv] [--osv-cache-only]
_h gate <run_dir> <candidate_id>             # promotion gate
_h report-gate <run_dir> <candidate_id>      # report-readiness gate
```

State order (no skipping): `candidate → deduped → promoted → proved
→ root_cause_recorded → variant_searched → patch_diffed → report_ready
→ submitted`. Terminal verdicts: `triaged`, `duplicate`, `n_a`, `resolved`,
`paid`.

## Intent + loop integrity

```
_h intent-set <run_dir> --threat <token> [--threat ...] [--rationale ...]
_h intent-show <run_dir>
_h loop-integrity-check        # bundled fixtures; CI-safe
_h intent-ordering-check       # bundled fixture; CI-safe
```

Threat tokens: `realtime_authz_drift`, `route_authz_gap`,
`parser_storage_boundary`, `ssrf_outbound_boundary`,
`command_execution_boundary`, `native_memory_boundary`.

## Outcomes + tuning

```
_h outcome-record <run_dir> <candidate_id> --final-status <state> ...
_h outcome-tune                # excludes synthetic by default
_h outcome-tune --include-synthetic
_h weights show [--json]       # effective weights + STARVED flag
```

Synthetic rows never feed prod tuning without `--include-synthetic`. Real
outcomes shift weights; synthetic seeding is for cold-start scaffolding only.

## Scanners (ROE-gated, fail-closed)

```
_h scope-check <run_dir> <url> --scanner <zap-full|zap-baseline|sqlmap|jwt|screenshot>
_h scan-zap-baseline <run_dir> --target-url <url>
_h scan-zap-full <run_dir> --target-url <url>     # requires active_scan_allowed
_h scan-sqlmap <run_dir> --target-url <url>       # requires active_scan_allowed
_h scan-screenshot <run_dir> --target-url <url>
_h scan-jwt <run_dir> --token <jwt> | --token-file <path>
_h tools-capability [--json]                       # which scanners are reachable
_h tool-health
```

Active scanners refuse without `active_scan_allowed: true` in the target
profile. Out-of-scope hosts refuse. Refusals write a JSON record under
`<run_dir>/logs/authorizations/` and exit non-zero — no silent pass.

## Source reading + discovery

```
_h source-acquire <run_dir>
_h source-index <run_dir>
_h source-probe --local-path <path> [--probe patch_variant_hunter|auth_chain_audit]
_h discovery-sweep --severity-floor high --since-days 7
_h discovery-list
_h discovery-claim <proposal_id>
```

`source-probe` AST walker is currently single-statement (T4.3). Probes only
run after operator claim.

## Campaigns

```
_h campaign-start <target_id> --name <campaign_id> [--refresh-advisories]
_h campaign-plan <target>
_h campaign-run <campaign_dir>
_h campaign-gate <campaign_dir>
_h campaign-dashboard <target>
_h campaign-flow-check                              # bundled fixture
_h campaign-adapter-check
```

## Watch + queue

```
_h watch-add <profile_path>
_h watch-list [--json]
_h watch-tick [--target <id>]                       # one poll cycle
_h watch-daemon                                     # foreground loop
_h queue list [--target <id>]
```

`vapt/engagements/<id>/` is gitignored. Pre-commit guard blocks accidental
staging — see `.pre-commit-config.yaml`.

## Phase + corpus checks (CI-safe)

```
_h phase2-check                # gated on cloned engagement source
_h phase3-check
_h phase4-check
_h outcome-tune-check
_h mutation-coverage-check <path>
```

## When something refuses

| Symptom | Cause | Fix |
|---|---|---|
| `authorization: denied` JSON, exit 2 | Out-of-scope host or missing `active_scan_allowed` | Update target profile; declare `scope_hosts` and (for active scanners) `active_scan_allowed: true` |
| `STARVED` in `weights show` | No real outcomes in `submissions.jsonl` | Run a real engagement through the loop; `outcome-record` non-synthetic |
| `cache_only:no_cache_entry` in dedup | OSV cache miss with `--osv-cache-only` | Drop `--osv-cache-only` or warm the cache |
| `blocking=...` from a gate | Workflow ordering or required field missing | Fill the listed fields; promote in order |
| `phase2-check` fails on clean clone | Needs the engagement source cloned first | Clone the target source under `engagements/<id>/` then re-run |

## Reference

- Truth: [`STATUS.md`](STATUS.md)
- Cold-start contract: [`vapt/ONBOARDING.md`](vapt/ONBOARDING.md)
- Backlog: `vapt/management/IMPROVEMENT_BACKLOG_2026-05-30.md`
- Roadmap: `vapt/management/HARNESS_ORCHESTRATION_FRAMEWORK_2026-05-29.md`
