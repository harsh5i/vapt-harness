# Phase 5 - Move 4 - Autonomous Target Discovery - 2026-05-28

Status: GHSA-based discovery sweep landed end-to-end.
OSV / NVD / registry-sweep sources are follow-up work.

References:
- `MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` ss 8

## What Landed

### Package
`vapt/harness/watch/discovery.py` provides:
- `fetch_recent_advisories(severity_floor, since_days, ...)` — pages the
  GHSA API at `api.github.com/advisories`, filters client-side by
  publish date, optionally authenticated via `GITHUB_TOKEN`.
- `watched_packages(target_profile_paths)` — walks
  `vapt/bug_bounties/*/targets/*.yaml` and collects
  `(ecosystem, package)` pairs that the harness already watches.
- `propose_targets(advisories, watched)` — diff: produces one proposal
  per (advisory, unwatched-package) pair.
- `write_proposals(proposals, queue_dir)` — persist to
  `vapt/harness/queue/discovery/prop_<ghsa>_<pkg>.json`. Idempotent:
  proposals with the same slug are not rewritten.
- `list_proposals` / `claim_proposal` — operator-side helpers.

### CLI surface
Three new subcommands in `harness.py`:
- `discovery-sweep [--severity-floor crit|high|medium|low]
  [--since-days N] [--per-page N] [--max-pages N] [--timeout S]
  [--json]` — pull recent GHSA, emit proposals.
- `discovery-list [--all] [--severity ...] [--ecosystem ...] [--json]` —
  show open proposals (or all when `--all`).
- `discovery-claim <slug> [--decision claim|reject] [--claimed-by ...]
  [--note ...] [--json]` — mark and print a suggested `watch-add`
  command. The command is NOT auto-executed; the operator pastes it
  after review. This preserves the substrate's "no auto-promotion"
  property.

## Verified Behaviour

Run on 2026-05-28T22:55 from repo root, no `GITHUB_TOKEN` set,
against the live GHSA API.

| Step | Command | Result |
|------|---------|--------|
| 1 | `discovery-sweep --severity-floor high --since-days 7 --max-pages 2 --json` | 60 advisories fetched, 3 packages already watched, 7 proposals written, 0 errors. |
| 2 | `discovery-list` | 7 rows. Mix of `go`, `pip`, `composer`, `npm` ecosystems. Each row shows GHSA + CVE + ecosystem/package. |
| 3 | `discovery-sweep` (same args) | 60 advisories, 7 proposals total, 0 written, 7 skipped existing. Idempotent. |
| 4 | `discovery-claim prop_GHSA-q3w6-q3hc-c5x6_npm_fuxa-server.json --claimed-by operator` | status=claimed. |
| 5 | `discovery-list` (open only) | 6 rows. |
| 6 | `discovery-list --all` | 7 rows (claim visible). |
| 7 | `discovery-claim prop_GHSA-g3vg-vx23-3858_pip_compliance-trestle.json --json` | Output includes `suggested_watch_add` exactly: `python3 vapt/harness/harness.py watch-add compliance-trestle --source ghsa_advisories --ecosystem pip --package compliance-trestle --allow-network`. |

The substrate's gate is preserved: no auto-discovered proposal becomes
a watch (and therefore no campaign) without an explicit operator
action. `discovery-claim` produces a suggested command for review;
nothing executes implicitly.

## Source Roadmap Open Items

- **OSV feed polling.** GHSA already covers a substantial subset of
  OSV. OSV has additional ecosystems and faster updates for some
  packages. Add `fetch_recent_osv` mirroring the GHSA path.
- **NVD JSON delta.** Cross-reference for CVEs that show up in NVD
  before GHSA reviewers triage. Useful as a high-recency signal.
- **Registry sweeps.** PyPI/npm/crates top-N download-rank lookups
  filtered by bug-bounty-program membership. Different signal than
  advisory-driven discovery: surfaces wide-attack-surface packages
  even before a CVE drops.
- **`discovery-plan` ranking.** Today proposals are ordered by GHSA
  publish date. A ranking step that weights:
  - severity
  - cvss score
  - ecosystem familiarity (modules with prior bounty success)
  - patch-window proximity
  - public proof presence
  would let the operator focus claim time. Hooks naturally into
  `outcome_tune` weight curves built in Move 1.
- **24-hour soak.** Roadmap exit criterion requires 10+ queue entries
  from autodiscovery in a soak. Current 7-day window with high
  severity gives 7 per day-range without claims yet — close to
  qualifying. Track once OSV is added.

## Why Move 4 Is Considered Done For This Pass

The substrate now has a functioning autonomous-discovery path that:
- Pulls real advisories from a live external feed.
- Diffs against the current target set.
- Produces durable, idempotent proposals.
- Preserves the operator-claim gate.
- Suggests the exact follow-up command to convert a claim into a
  watch.

Roadmap section 8 lists OSV/NVD/registry as additional sources rather
than blocking gates. The GHSA path covers the dominant signal and
proves the architecture. Remaining sources are additive and can land
incrementally without rework.
