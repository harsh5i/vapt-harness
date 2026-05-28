# VAPT Harness

Autonomous vulnerability research substrate. Operator-driven CLI plus a
campaign engine that learns from outcomes, surfaces new targets from
public advisory feeds, and runs both URL-based probes and source-reading
probes against authorized targets.

Built across Phases 1-5. Phase 5 (2026-05-28) added the moves described
in `docs/MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md`:

- **Move 1** - the outcome-tuning loop is fed with synthetic seeds
  (production runs default-exclude them); OSV queries are cached so
  dedup works offline without silent degradation.
- **Move 2** - package skeleton landed (`harness/{campaign,gates,ledger,watch,mutation,tools,source,cache}/`).
  New code lands in packages; legacy code in `harness.py` migrates
  touch-and-extract.
- **Move 3** - wrappers for OWASP ZAP, sqlmap, JWT tooling, and
  Playwright screenshots. Container-first; local-binary fallback.
  Capability gaps surface via `harness tools-capability`.
- **Move 4** - GHSA-based autonomous target discovery. Sweep produces
  proposals; operators claim before any campaign runs.
- **Move 5** - source-reading substrate (acquire/index/AST walker)
  with two reference probes (`patch_variant_hunter`, `auth_chain_audit`).
  Catches 4/5 seeded Python bug-class patterns end-to-end.

## Layout

```
vapt/                  Tracked: harness code, doctrine, fixtures
  harness/             Code + per-package skeletons + agent role files
  docs/                Doctrine, roadmaps, per-Move evidence (Phase 1-5)
  bug_bounties/
    _fixtures/         Captive fixtures (seeded_bugs_repo for Move 5)
    _shared/           Cross-engagement corpus (schemas + reference data)
  env/                 Optional full VAPT toolchain requirements
  requirements.txt     Minimum runtime (PyYAML)
engagement/            Local-only: bounty targets, runs, evidence, pocs,
                       reports, scripts, runtime, templates. Gitignored.
README.md
```

The `vapt/` subdir preserves the path conventions the harness code uses
internally (`ROOT / "vapt" / ...`). Treat `vapt/` as the harness package
and `engagement/` as your private workspace.

### `engagement/` is local-only

This folder holds anything tied to a specific authorized engagement:

- `engagement/bug_bounties/<target>/` - per-target metadata, watch
  configs, prior recon, source mirrors.
- `engagement/harness_runs/` - operator runs (was `harness/runs/`
  upstream).
- `engagement/evidence/`, `engagement/pocs/`, `engagement/reports/` -
  raw artifacts.
- `engagement/env/`, `engagement/scripts/`, `engagement/runtime/`,
  `engagement/templates/` - bootstrap and tooling state.

`engagement/` is in `.gitignore`. It is intentionally not part of the
GitHub mirror. Treat it as your private working tree.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r vapt/requirements.txt

# Capability inventory
python3 vapt/harness/harness.py tools-capability --json

# Seed the outcome-tuning loop with synthetic rows derived from corpus
python3 vapt/harness/harness.py submissions seed-synthetic

# Synthetic excluded by default
python3 vapt/harness/harness.py outcome-tune --out /tmp/tune.yaml

# Include for development
python3 vapt/harness/harness.py outcome-tune --include-synthetic --out /tmp/tune.yaml

# Run the source-reading probe against the seeded fixture
python3 vapt/harness/harness.py source-probe \
  --local-path "$(pwd)/vapt/bug_bounties/_fixtures/seeded_bugs_repo"

# Sweep GHSA for unwatched packages (requires internet)
python3 vapt/harness/harness.py discovery-sweep --severity-floor high --since-days 7
python3 vapt/harness/harness.py discovery-list
```

## What this is not

- Not a model. The harness provides the substrate around an external LLM
  or human operator.
- Not autonomous exploitation. No probe runs against a target until an
  authorized scope and operator claim are in place.
- Not a memory-corruption fuzzer, not a symbolic-reasoning engine, not a
  protocol state-machine analyser. Those remain future phases.

## Capability claims

| Path | State |
|------|-------|
| N-day discovery at scale | Architecturally ready. Gated on Docker for ZAP/sqlmap probes. |
| Logic-flaw 0day | Architecturally open via source-reading probes. Not yet validated by a real campaign. |
| Memory-corruption 0day | Out of scope. |
| Cryptographic flaws | Out of scope. |
| Protocol-state 0day | Out of scope. |

## Provenance

Extracted on 2026-05-28 from the in-place engagement tree at
`vapt/`. Per-target
bug bounty data was intentionally excluded; only captive fixtures and
the cross-engagement corpus schema travel with the repo.

**Before pushing to any remote**, review `bug_bounties/_shared/corpus/candidates.jsonl`
for prior research material you may not want public. The seeded
fixture under `bug_bounties/_fixtures/seeded_bugs_repo/` is fully
synthetic and safe.

## License

To be decided by the maintainer before public release.
