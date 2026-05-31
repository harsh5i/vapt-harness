# Harness package

This directory is the engine. `harness.py` is the CLI entrypoint; everything
else is one of the leaf modules it re-exports from.

For day-to-day operator usage, read these first (in this order):

1. [`/STATUS.md`](../../STATUS.md) — capability truth (what is implemented, what is partial, what is not started)
2. [`/CHEATSHEET.md`](../../CHEATSHEET.md) — the 80% of daily commands on one page
3. [`/vapt/ONBOARDING.md`](../ONBOARDING.md) — the cold-start contract: identity, authorization, lifecycle, gates, silent-failure modes
4. [`/README.md`](../../README.md) — purpose, layout, quick start

## Package layout

| Path | Role |
|---|---|
| `harness.py` | Thin entrypoint hosting in-file constants + re-import shims |
| `cli.py` | argparse dispatcher (`build_parser` + `main`) |
| `core.py`, `atomic_io.py`, `validators.py`, `outcome_tuning.py` | Stdlib-only leaf layer |
| `ledger/` | candidate / submission / outcome primitives + workflow handlers |
| `gates/` | promotion / report / OSV / authorization gates |
| `tools/` | container/local discovery, capped-exec, scanner wrappers + cmd handlers |
| `watch/` | watch state + per-source polling + advisory matching |
| `campaign/` | campaign-context + lifecycle cmd handlers |
| `source/` | target lookup + AST walkers + source-graph / probe cmds |
| `mutation/` | mutation catalog + coverage validation |
| `probes/` | reusable Probe classes (websocket authz drift, SSRF, parser canon, etc.) |
| `agents/` | role-prompt markdowns used by `explain` and `playbook` |
| `knowledge/` | doctrine + lesson markdowns searched by `knowledge` |
| `templates/`, `rules/`, `targets/` | reusable templates, semgrep rules, target-profile scaffolds |
| `config/` | `surfaces.yaml`, `campaign_modules.yaml` operator-tunable config |
| `corpus/` | cross-engagement learning corpus (candidates.jsonl, submissions.jsonl) |
| `tests/` | pytest suite + fixtures + bundled regression baselines |
| `fixtures/` | captive fixtures the harness uses internally (seeded_bugs_repo, etc.) |
| `mcp/` | MCP-server manifest |
| `helpers.py`, `checks.py`, `commands_lifecycle.py`, `commands_auxiliary.py` | Extracted helpers + remaining cmd handlers |

## Operating reminders

- Run harness commands through `.venv-vapt/bin/python` (or system `python3` if PyYAML is installed).
- Candidate ledger mutators take `candidates.yaml.lock`. Concurrent runs against the same run directory are still discouraged.
- Cold-start an AI/operator session with `session-start <run_dir>` so the run state is in context.
- Scanner wrappers refuse without an ROE-declared target profile. Refusals write a JSON record under `<run_dir>/logs/authorizations/` and exit non-zero — never silently skip.
- Watch profiles live under `watches/`, watch state under `watches/state/`, runtime queue under `queue/<target_id>/`.
- Per-target engagement data (target profiles, runs, evidence, PoCs, reports) lives under `vapt/engagements/<target>/` and stays local — see `.gitignore`.

## Reference hygiene

External security repositories are treated as untrusted input. The harness may
learn taxonomy, workflow shape, and evidence standards from public references,
but it does not execute copied commands, import prompt instructions, or vendor
payload corpora by default.
