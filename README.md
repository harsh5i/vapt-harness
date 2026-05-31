# VAPT Harness

Evidence-gated vulnerability research harness for authorized assessment.
Operator-driven CLI plus a campaign engine that tunes prioritization from
recorded outcomes, surfaces new targets from public advisory feeds, and runs
both URL-based probes and source-reading probes against authorized targets.

**`STATUS.md` is the single source of truth** for what is actually implemented
vs. partial vs. future. This README describes intent and usage; do not read a
capability as working unless `STATUS.md` marks it `implemented`. For day-to-day
operator commands, see [`CHEATSHEET.md`](CHEATSHEET.md).

What the harness provides:

- An evidence-gated candidate lifecycle (`candidate-add → dedup → gate → prove → variant → patch-diff → report-gate → submit`) where each state has a hard precondition; you cannot skip ahead.
- A binding orient/submit loop that hands one step at a time to the AI/operator and only advances when the recorded outcome satisfies the gate.
- A learning loop that folds real triage verdicts and terminal outcomes into score weights so the next run prioritizes better.
- A scope/ROE gate that refuses scanner execution out-of-scope or without explicit `active_scan_allowed` in the target profile; refusals write a JSON record and exit non-zero.
- Source-reading probes with an intra-function taint-flow AST walker for Python (and a Ruby walker for guard-awareness).
- Reusable campaign-module adapters and a runtime queue fed by local-git, release, and GHSA/OSV advisory polling.

## Layout

Entering `vapt/` follows a **Mandatory -> Records** view:

```
vapt/
  ONBOARDING.md        Mandatory: the LLM cold-start contract. Read first.
  harness/             The engine: harness.py, knowledge/, agents/, config/,
                       probes/, gates/, fixtures/ (captive), corpus/ (learning).
  engagements/         Records: one subfolder per target, structured as the
                       harness directs (targets/, adapters/, runs/<t>/<id>/).
                       Per-target dirs are gitignored - target data stays local.
  env/                 Optional full toolchain requirements
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
| N-day discovery (advisory-driven) | Partial. Scanner wrappers are ROE-gated (fail-closed scope + `active_scan_allowed`). Remaining gaps: Docker / local tool availability for ZAP/sqlmap and real-campaign validation. |
| Logic-flaw 0day via source-reading | Partial / future. AST is single-statement, synthetic-validated; not proven on a real campaign. |
| Memory-corruption / crypto / protocol-state 0day | Out of scope (future). |

## Repo contents

This repo ships the engine, its operating knowledge under
`vapt/harness/knowledge/`, the captive fixture under
`vapt/harness/fixtures/seeded_bugs_repo/` (fully synthetic), and the
unit test suite.

Operational state is per-operator and gitignored:

- `vapt/engagements/<id>/` — target profiles, runs, evidence, reports.
- `vapt/harness/corpus/candidates.jsonl`, `submissions.jsonl` — the
  cross-engagement ledgers.
- `vapt/harness/queue/<id>/` — per-target queue state.

The harness creates these on first use.

## License

Apache License 2.0. See [LICENSE](LICENSE).
