# Phase 5 - Move 1 - Feeding Evidence - 2026-05-28

Status: Move 1 substantively complete. Synthetic seeding, tuner safety
flag, and OSV cache are live. Open follow-ups: formal CLI acceptance
check, optional real-history backfill, module heuristic refinement.

References:
- `MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` ss 5

## What Landed

### Synthetic seeder
- New CLI: `submissions seed-synthetic [--clear] [--json]`.
- Derives one synthetic row per row in
  `vapt/bug_bounties/_shared/corpus/candidates.jsonl` (17 rows today).
- Each row inherits real enrichment from its source candidate:
  `target_id`, `weakness`, `cwe`, `surface`, `sink`, `cvss`, `title`.
- Module is inferred from weakness/surface keywords
  (`authz_matrix`, `ssrf_callback`, `serialization_rce`,
  `path_traversal_audit`, `prompt_injection_audit`, `websocket_authz`,
  fallback `manual_review`). Heuristic is intentionally coarse and
  will be refined in step 2.
- Status is assigned by `crc32` of `{target_id}:{candidate_id}` over a
  realistic outcome distribution:
  duplicate 40 percent, not_applicable 25 percent, triaged 15 percent,
  resolved 10 percent, paid 7 percent, informative 3 percent.
  Deterministic, idempotent across reruns.
- All seeded rows carry `synthetic: true` and
  `synthetic_source: vapt/bug_bounties/_shared/corpus/candidates.jsonl`.

### Tuner safety flag
- `outcome_tuning()` accepts `include_synthetic: bool` and segregates
  the counts. Defaults to False.
- `outcome-tune` CLI gains `--include-synthetic` flag.
- Output now includes `synthetic_excluded` and `synthetic_included`
  fields so operators can see at a glance whether they ran in
  production mode or development mode.

## Verified Behaviour

Run on 2026-05-28T22:27 from `vapt/` root.

| Step | Command | Result |
|------|---------|--------|
| 1 | `submissions seed-synthetic --json` | 17 rows written, total=17. |
| 2 | `outcome-tune --json` (default) | `terminal_count=0`, `synthetic_excluded=17`. Production-safe. |
| 3 | `outcome-tune --include-synthetic --json` | `terminal_count=17`, `synthetic_included=17`. |
| 4 | `outcome-tune-check --fail --json` | passed; pre-existing fixture still green. |
| 5 | `submissions seed-synthetic --clear --json` | total=0; idempotent reset. |
| 6 | reseed | total=17; deterministic regeneration. |

Sample weight movements observed in step 3
(`/tmp/tune-syn.yaml`, abbreviated):

- `module_adjustments.manual_review.score_adjustment` = `0.3`
- `evidence_kind_adjustments.manual_observation.score_adjustment` = `2.25`
- `evidence_kind_adjustments.reproducer_verified.score_adjustment` = `-1.17`
- `weakness_adjustments.CWE-20.score_adjustment` (positive) confirms
  weakness-bucket signal flow.

Conclusion: the outcome-tuning loop is no longer starving when run
in development mode, and production runs remain unchanged.

## OSV Cache (step 2)

### Design

- New SQLite store at `vapt/harness/cache/osv.sqlite`. WAL mode.
- Two tables: `osv_package(ecosystem, package, version, fetched_at, payload)`
  and `osv_vuln(vuln_id, fetched_at, payload)`. Primary keys make
  inserts idempotent.
- `OSV_CACHE_FRESH_HOURS = 168` (7 days). Within window the cache
  short-circuits the network call. Past window the network is tried
  first and the cache is the safety net on failure.
- Three operating modes flow through `--osv-cache-only` and
  `--osv-fresh-only` on the `dedup` subcommand:
  - default: cache-then-network. Stale entries trigger a refresh.
  - cache-only: never touch the network. Required for true offline.
  - fresh-only: ignore cache. Required when you suspect cache drift.
- Every result carries a `_cache` block:
  `{hit, age_hours, stale, source, network_error?}`. `_osv_dedup`
  aggregates these into a `cache` summary on the dedup record.

### Safety property added

If `--osv-cache-only` is used and the cache has no entry for any
queried vuln or package, `_osv_dedup` records the synthetic error
`cache_only:no_cache_entry - refusing to claim no-known-duplicate
without a real lookup`. The upstream `cmd_dedup` then degrades the
candidate to `dedup-incomplete` rather than producing a false-negative
`no-known-duplicate`. The h2o-3 silent-degrade failure mode from
2026-05-27 is now impossible: offline runs either succeed against
cache or visibly fail.

### CLI added

- `harness osv-cache stats [--json]` — row counts, oldest/newest
  timestamps, fresh window.
- `harness osv-cache prefetch <target> [<target> ...] [--timeout N]
  [--refresh] [--json]` — warm cache from `_load_target_profile`
  (`vapt/bug_bounties/*/targets/<id>.yaml`) with a legacy fallback
  to `<id>/target.yaml`.
- `harness osv-cache clear [--json]` — delete the SQLite file.

### Verified behaviour

Run on 2026-05-28T22:33 from `vapt/` root.

| Step | Command | Result |
|------|---------|--------|
| 1 | `osv-cache stats --json` (empty) | `exists=false`, zero rows. |
| 2 | `osv-cache prefetch grafana-oss demo-pyml h2o-3 demo-target` | 1 package + 95 vulns fetched. One transient timeout (`GO-2024-2851`) surfaced cleanly. |
| 3 | `osv-cache stats --json` | `package_rows=1`, `vuln_rows=95`, fresh window 168h. |
| 4 | Python harness call: `_osv_vuln_query("GHSA-2X6G-H2HG-RQ84", 20, cache_only=True)` | Hit, `cache_hit=True`, `age_h=0.057`, `stale=False`, aliases include CVE-2022-39306. |
| 5 | Same call with `GHSA-FAKE-FAKE-FAKE` | Clean miss, `None`. |
| 6 | `outcome-tune-check --fail --json` | Pass (no regression). |
| 7 | `submissions seed-synthetic --json` then `outcome-tune --include-synthetic` | 17 rows seed, terminal_count=17 (no regression). |

### Storage note

The cache file is currently uncommitted. Two acceptable policies:

- **Commit it** for reproducibility across machines and CI. Then
  prefetch is a one-time bootstrap.
- **Gitignore it** and treat prefetch as a per-checkout setup step.
  Cleaner diffs, but each fresh clone needs network warm-up.

Choice deferred to operator. The harness functions identically either
way.

## Known Gaps Carried to Next Step

1. **Module heuristic is shallow.** 15 of 17 rows mapped to
   `manual_review` because their weakness strings did not match the
   keyword set. Refine by reading `campaign_modules.yaml` and
   matching on declared module taxonomy.
2. **OSV cache not yet built.** Offline dedup gate still degrades to
   `dedup-incomplete`. Tracked as next sub-task.
3. **No CLI acceptance check yet.** The verification above is manual.
   Add `outcome-feeding-check` modeled on `outcome-tune-check` so the
   seed + tune + clear cycle is regression-tested.
4. **Real history backfill deferred.** Operator-recorded prior
   submissions can be folded in later via the existing
   `outcome record` CLI; synthetic vs real coexist cleanly because
   the `synthetic` flag separates them.

## Artifacts

- `vapt/harness/harness.py` (modified):
  - `outcome_tuning()` now takes `include_synthetic`.
  - `cmd_outcome_tune` honours the new flag, emits counts.
  - `cmd_submission_seed_synthetic` and helpers
    (`_synthetic_status_for`, `_synthetic_module_for`,
    `_synthetic_evidence_kind`) added.
  - `SYNTHETIC_OUTCOME_DISTRIBUTION` constant declares the seed
    distribution in one place.
  - CLI subparser additions for `outcome-tune --include-synthetic`
    and `submissions seed-synthetic --clear --json`.
- `vapt/bug_bounties/_shared/corpus/submissions.jsonl`
  (now 17 synthetic rows, was empty).
