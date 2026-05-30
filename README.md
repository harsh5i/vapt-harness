# VAPT Harness

Evidence-gated vulnerability research harness for authorized assessment.
Operator-driven CLI plus a campaign engine that tunes prioritization from
recorded outcomes, surfaces new targets from public advisory feeds, and runs
both URL-based probes and source-reading probes against authorized targets.

**`STATUS.md` is the single source of truth** for what is actually implemented
vs. partial vs. future. This README describes intent and usage; do not read a
capability as working unless `STATUS.md` marks it `implemented`.

Built across Phases 1-5. Phase 5 (2026-05-28) added the moves described
in `management/MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md`:

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

Entering `vapt/` follows a **Mandatory -> Management -> Records** view:

```
vapt/
  ONBOARDING.md        Mandatory: the LLM cold-start contract. Read first.
  harness/             The engine: harness.py, knowledge/, agents/, config/,
                       probes/, gates/, fixtures/ (captive), corpus/ (learning).
  engagements/         Records: one subfolder per target, structured as the
                       harness directs (targets/, adapters/, runs/<t>/<id>/).
                       Per-target dirs are gitignored - bounty data stays local.
  management/          Roadmaps, plans, design notes, diagnostics. Context for
                       improving the harness; not part of execution.
  env/                 Optional full VAPT toolchain requirements
  requirements.txt     Minimum runtime (PyYAML)
README.md
```

The `vapt/` subdir preserves the path conventions the harness code uses
internally (`ROOT / "vapt" / ...`). The engine and its captive fixtures +
learning corpus travel with the repo; per-target Records do not.

### `engagements/` is local-only

Each `engagements/<target>/` holds everything tied to one authorized
target: the `targets/<id>.yaml` profile, `adapters/`, and
`runs/<target>/<run-id>/` (recon, evidence, candidate ledger, reports).
The `.gitignore` excludes `vapt/engagements/*/`, so target data is never
part of the GitHub mirror. Only the captive fixtures
(`vapt/harness/fixtures/`) and the cross-engagement corpus schema
(`vapt/harness/corpus/`) travel with the repo.

## Using the harness as an LLM operator

If you are an external language model with shell access being asked
to run authorized vulnerability research with this harness, read
`vapt/ONBOARDING.md` first. It is the cold-start
contract: identity, authorization, the lifecycle state machine,
which role file to read at each stage, command reference grouped by
lifecycle phase, gates and what they reject, common silent failure
modes, and a worked end-to-end example.

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
  --local-path "$(pwd)/vapt/harness/fixtures/seeded_bugs_repo"

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

Authoritative per-capability status lives in [`STATUS.md`](STATUS.md). Summary:

| Path | State |
|------|-------|
| Evidence-gated candidate lifecycle | Implemented. |
| N-day discovery (advisory-driven) | Partial. Scanners wired but not yet ROE-gated; Docker-gated for ZAP/sqlmap. |
| Logic-flaw 0day via source-reading | Partial / future. AST is single-statement, synthetic-validated; not proven on a real campaign. |
| Memory-corruption / crypto / protocol-state 0day | Out of scope (future). |

## Provenance

Extracted on 2026-05-28 from the in-place engagement tree at
`vapt/`. Per-target
bug bounty data was intentionally excluded; only captive fixtures and
the cross-engagement corpus schema travel with the repo.

**Before pushing to any remote**, review `vapt/harness/corpus/candidates.jsonl`
for prior research material you may not want public. The seeded
fixture under `vapt/harness/fixtures/seeded_bugs_repo/` is fully
synthetic and safe.

## License

To be decided by the maintainer before public release.
