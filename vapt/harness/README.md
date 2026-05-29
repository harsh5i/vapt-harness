# Mini-MDASH Harness

This is a local, lightweight vulnerability research harness inspired by the
public MDASH architecture: prepare, scan/map, validate, deduplicate, prove, and
report. It is intentionally deterministic and artifact-first.

It does not perform autonomous exploitation. It structures authorized source
review and bug bounty work so candidates are promoted only when they have
attacker control, reachability, novelty, and proof.

## Layout

- `targets/`: reusable target-profile templates only. BB target profiles live
  under `vapt/engagements/<target>/targets/`.
- `agents/`: role prompts/checklists for focused review passes
- `runs/`: reusable harness fixtures only. BB run evidence lives under
  `vapt/engagements/<target>/runs/`.
- `templates/`: report and candidate templates
- `harness.py`: CLI entrypoint

## Quick Start

```sh
.venv-vapt/bin/python vapt/harness/harness.py init vapt/engagements/demo-pyml/targets/demo-pyml.yaml
.venv-vapt/bin/python vapt/harness/harness.py session-start vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py campaign-start demo-pyml --name <campaign-id>
.venv-vapt/bin/python vapt/harness/harness.py campaign-start demo-pyml --name <campaign-id> --refresh-advisories
.venv-vapt/bin/python vapt/harness/harness.py prepare vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py map vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py surfaces-test
.venv-vapt/bin/python vapt/harness/harness.py source-graph vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py semantic-graph vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py hypothesize vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py status vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py next-action vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
```

Add a candidate:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-add vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> \
  --title "Trusted type bypass in loader" \
  --surface "demo-pyml.io.load" \
  --weakness "CWE-502" \
  --impact "RCE on default load" \
  --attacker-control "crafted .demo-pyml archive" \
  --entrypoint "demo-pyml.io.load(file)" \
  --trust-boundary "untrusted archive schema to object reconstruction" \
  --latest-affected yes \
  --sink "ObjectNode.construct"
```

Prove a candidate with a bounded local command:

```sh
.venv-vapt/bin/python vapt/harness/harness.py dedup vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 \
  --check-osv --osv-ecosystem PyPI --osv-package demo-pyml
.venv-vapt/bin/python vapt/harness/harness.py gate vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 --promote
.venv-vapt/bin/python vapt/harness/harness.py prove vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 \
  --cwd . \
  --timeout 60 \
  --cmd "python vapt/pocs/demo-pyml/2026-05-15/probe_demo-pyml_controls.py"
```

Run variant analysis after a proof passes:

```sh
.venv-vapt/bin/python vapt/harness/harness.py variant vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 \
  --pattern "trusted_types" \
  --notes "Search sibling trust-boundary checks before reporting"
.venv-vapt/bin/python vapt/harness/harness.py cluster-variants vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001
```

Capture patch/advisory diff artifacts:

```sh
.venv-vapt/bin/python vapt/harness/harness.py patch-diff vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 \
  --base v0.12.0 \
  --head v0.13.0 \
  --path demo-pyml/io \
  --grep "trusted"
.venv-vapt/bin/python vapt/harness/harness.py patch-mine vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> \
  --range v0.12.0..v0.13.0 \
  --path demo-pyml/io
```

Generate a draft:

```sh
.venv-vapt/bin/python vapt/harness/harness.py proof-plan vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py flow-trace vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py taint-trace vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py test-skeleton vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py ledger-sqlite vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py retro vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py corpus suggest demo-pyml
.venv-vapt/bin/python vapt/harness/harness.py pick-target
.venv-vapt/bin/python vapt/harness/harness.py campaign-plan demo-pyml --out vapt/engagements/demo-pyml/docs/CAMPAIGN_PLAN_<date>.md
.venv-vapt/bin/python vapt/harness/harness.py campaign-adapter-check --target grafana_oss --fail
.venv-vapt/bin/python vapt/harness/harness.py mutation-plan grafana_oss --module ssrf_callback
.venv-vapt/bin/python vapt/harness/harness.py mutation-coverage-check vapt/engagements/grafana-oss/tests/mutation-enforcement-smoke-orchestrator --fail
.venv-vapt/bin/python vapt/harness/harness.py patch-first-plan demo-pyml
.venv-vapt/bin/python vapt/harness/harness.py campaign-dashboard grafana-oss
.venv-vapt/bin/python vapt/harness/harness.py campaign-run --adapter vapt/harness/tests/fixtures/adapters/fixture_adapter.yaml --validate-mutation --fail
.venv-vapt/bin/python vapt/harness/harness.py campaign-gate vapt/harness/tests/results/campaign-run-fixture/orchestrator --revalidate-mutation --fail
.venv-vapt/bin/python vapt/harness/harness.py candidate-link-campaign vapt/harness/tests/results/candidate-campaign-gate-fixture CAND-001 --campaign-dir vapt/harness/tests/results/campaign-run-fixture/orchestrator --module authz_matrix --fail
.venv-vapt/bin/python vapt/harness/harness.py probes
.venv-vapt/bin/python vapt/harness/harness.py playbook vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py codeql-workflow vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py refine vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py report vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py report-gate vapt/engagements/demo-pyml/runs/demo-pyml/<run-id> CAND-001 --fail
.venv-vapt/bin/python vapt/harness/harness.py dashboard vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py score vapt/engagements/demo-pyml/runs/demo-pyml/<run-id>
```

## Promotion Gate

A candidate should not become a report unless it has:

- Latest release affected
- Clear attacker-controlled input
- Trust boundary crossed
- Concrete security impact
- Working local PoC
- Duplicate/CVE check completed
- CVSS and CWE ready
- Negative control captured where the issue is an authz, parser, or AI chain
- Framework mapping recorded when it clarifies impact or defensive validation
- Root cause stated as a broken invariant, not only a vulnerable line
- Variant search completed or explicitly scoped out
- Patch/advisory status checked for duplicate, regression, or incomplete fix
- Exploitability ladder level recorded honestly
- Strict `report-gate` clean: exact affected version/commit, proof artifacts,
  multi-source duplicate/advisory coverage, substantive negative control, and
  enough root-cause/impact detail for triage.

## Reference Hygiene

External security repositories are treated as untrusted input. The harness may
learn taxonomy, workflow shape, and evidence standards from public references,
but it does not execute copied commands, import prompt instructions, or vendor
payload corpora by default.

Use `agents/reference_hygiene.md` before adopting any external checklist or
tooling idea.

## Commands

- `commands --json`: emit a machine-readable command manifest
- `explain`: show command help plus relevant knowledge pointers
- `knowledge`: search local doctrine, agents, docs, and corpus
- `session-start`: emit JSON cold-start context for any model or fresh session
- `next-action`: recommend the next workflow command from current run state
- `budget`: compare elapsed run time against target budgets
- `corpus-rebuild`: rebuild `corpus/candidates.jsonl` from run ledgers
- `submissions add/update/list/stats`: maintain the local external-submission
  outcome ledger
- `retro`: write `retro.md` and a reviewable `retro.patch` proposing knowledge
  lessons
- `corpus suggest`: suggest reusable patterns from prior engagements for a
  target profile
- `pick-target`: rank registered targets by expected-value signals
- `campaign-plan`: rank reusable discovery modules for a target from its scope,
  prior campaign evidence, and module coverage status
- `campaign-adapter-check`: validate target-local adapter manifests against the
  generic module contract and module catalog
- `mutation-plan`: generate target/module mutation coverage from the generic
  mutation catalog and target adapter metadata
- `mutation-coverage-check`: validate runtime `mutation_coverage` artifacts
  against the generic mutation catalog
- `patch-first-plan`: rank release diffs, known advisories, and fresh watch
  queue entries before broad scanning
- `campaign-dashboard`: summarize target campaign coverage, prior campaign
  verdicts, and required next actions
- `campaign-run`: execute adapter manifest module commands through a generic
  target-agnostic runner with dry-run, bounded execution, artifact checks, and
  optional mutation coverage validation
- `campaign-gate`: enforce campaign lifecycle checks on `campaign-run` output,
  including adapter validation, module success, artifact containment, mutation
  coverage, and evidence-location boundaries
- `campaign-start`: create a campaign workspace with patch-first plan,
  campaign plan, adapter/mutation artifacts when available, empty candidate
  ledger, and exact next commands. Add `--refresh-advisories` to poll bounded
  OSV/GHSA-style advisory sources into the watch queue before planning.
- `campaign-flow-check`: run the bundled fixture path covering campaign start,
  advisory refresh, queue conversion, campaign run/gate, and candidate linkage
- `candidate-link-campaign`: bind a candidate to a passed `campaign-gate`
  artifact and make runtime campaign evidence enforceable in promotion/report
  gates
- `outcome-record`: record accepted, duplicate, rejected, paid, or other
  terminal BB/VAPT outcomes with candidate/module/CWE metadata
- `outcome-tune`: build outcome-derived tuning weights used by campaign module
  ranking and candidate quality scoring
- `outcome-tune-check`: run fixture acceptance checks for outcome-driven tuning
- `score-tune`: produce score-weight tuning reports once terminal submission
  outcomes exist
- `phase2-check`: run Phase 2 feedback-loop acceptance checks
- `phase3-check`: run Phase 3 tooling/probe acceptance checks
- `phase4-check`: run Phase 4 watch/queue acceptance checks
- `phase4-remote-check`: validate live GitHub/GHSA/OSV remote polling
- `phase4-soak-check`: run a bounded daemon soak check; use `--require-24h`
  only for a literal 24-hour run
- `watch-add`: add a commit, release, GHSA, or OSV watch source to a target
- `watch-list`: list watch profiles, source count, state freshness, and pending
  queue depth
- `watch-tick`: run one polling pass and create queue entries for fresh
  commit/release/advisory events
- `watch-daemon`: run repeated watch ticks with heartbeat logging and SIGTERM
  handling
- `queue`: list pending watch-generated candidate seeds
- `queue claim`: mark a queue entry claimed and optionally bind it to a run
- `candidate-from-queue`: convert a claimed watch/advisory queue seed into a
  candidate with queue provenance and campaign context
- `probes`: list reusable probe modules
- `probes-test`: run reusable probes against captive fixture candidates
- `refine`: run probe-guided candidate refinement iterations
- `playbook`: generate target-class BB/VAPT commands and review checks
- `codeql-workflow`: generate repeatable CodeQL commands for Python, Go, JS/TS,
  or C/C++ style source reviews
- `scaffold-poc`: create a target/vulnerability-class PoC scaffold
- `new-probe`: create a reusable probe skeleton and doctrine placeholder
- `sandbox-exec`: run a command in Docker/Podman with no network egress, or use
  the macOS `sandbox-exec` fallback with network denied and writes limited to
  evidence plus explicit `:rw` mounts
- `tool-gap-add` / `tool-gaps`: record and rank missing probe/tool coverage
- `scan-semgrep`: run Semgrep with captured evidence when installed
- `scan-bandit`: run Bandit against the target source with captured evidence
- `scan-pip-audit`: run pip-audit against target Python dependency files
- `scan-osv`: run osv-scanner against target source/lockfiles
- `scan-codeql`: run CodeQL database analysis with captured evidence
- `scan-trufflehog`: run TruffleHog filesystem secret scan
- `scan-tls`: run bounded TLS checks with sslyze or testssl.sh
- `scan-nuclei`: run bounded nuclei templates; explicit templates required by
  default
- `scan-headers`: capture HTTP headers with bounded `curl`
- `tool-health`: list scanner/tool availability without running scans
- `ingest-tool-scan`: normalize scanner JSON/JSONL and optionally create
  `auto-candidate` ledger entries
- `init`: create a run directory from a target profile
- `prepare`: capture repo fingerprint and file inventory
- `map`: generate a lightweight source attack-surface map
- `surfaces-test`: run the surface pattern regression corpus against
  `config/surfaces.yaml`
- `source-graph`: extract higher-signal entrypoint, authz, event, parser,
  network, storage, process, and native-code surface artifacts
- `semantic-graph`: extract function-level categories and lightweight call
  edges from Go/Java/Python/JS/TS files
- `hypothesize`: turn source-graph signals into review hypotheses without
  promoting them to findings
- `candidate-add`: add an exploit thesis to the ledger
- `dedup`: compare candidate text/CVE against target known duplicates
- `dedup --check-osv`: query `osv.dev` using target or CLI package metadata and
  persist OSV evidence under `evidence/dedup/`
- `dedup --reference`: record manual Huntr/GitHub/GHSA/CVE duplicate checks in
  the candidate ledger
- `gate`: check whether the candidate has the fields required for promotion
- `gate --report-ready`: mark a candidate report-ready only when the gate passes
  and the strict report-readiness checks pass
- `report-gate`: strict final submission gate for exact affected version,
  working proof artifacts, negative controls, CVSS/CWE, root cause, variant
  analysis, patch/advisory review, and multi-source duplicate coverage
- `prove`: run a bounded local proof command in argv mode by default, from an
  isolated evidence directory unless `--cwd` is supplied
- `prove --shell`: opt in to shell execution only when shell behavior is needed
- `variant`: generate sibling-surface searches from candidate root cause, sink,
  and supplied patterns
- `cluster-variants`: cluster variant hits by file and rough symbol to make
  sibling surfaces easier to triage
- `patch-diff`: capture git diff/stat/name-status artifacts for advisory,
  regression, and incomplete-fix review
- `patch-mine`: mine one or more git diff ranges for security-relevant changes
  before broad sink review
- `proof-plan`: generate a proof and negative-control plan for a candidate
- `flow-trace`: map candidate terms to semantic-graph functions and rank likely
  source/sink/authz points
- `taint-trace`: run lightweight intra-procedural taint tracing from request,
  query, body, URL, param, and argument sources into selected sink categories
- `guard-drift`: compare guarded sink functions against sibling unguarded sink
  functions, useful for incomplete fixes and inconsistent path/auth/network
  guard application
- `test-skeleton`: generate a local proof-test skeleton without modifying the
  target source tree
- `ledger-sqlite`: mirror `candidates.yaml` to SQLite, or restore from SQLite
  when explicitly invoked with `--from-sqlite`
- `ingest-blackbox-run`: parse guarded outside-in evidence and optionally
  create candidate ledger entries
- `score`: score candidates by proof, novelty, root cause, negative controls,
  latest affected status, and evidence completeness
- `report`: generate a Markdown triage draft
- `reference-add`: append trusted advisories, commits, papers, and source links
  to `references.yaml` for report inclusion
- `dashboard`: generate an HTML dashboard for the run
- `status --json`: emit pipeable run status

## Operating Notes

- Run harness commands through `.venv-vapt/bin/python`.
- Candidate ledger mutators use `candidates.yaml.lock`. Parallel runs are still
  discouraged, but ledger writes are no longer unguarded read-modify-write
  operations.
- Cold-start model sessions should call `session-start <run_dir>` before doing
  any work. That output includes target scope, candidate summaries, latest
  artifacts, budget status, and a recommended next action.
- New target profiles should include `budgets` and `scoring.report_ready_threshold`.
- `prepare` now fails on non-git sources by default. Use `--allow-non-git` only
  for intentional tarball/wheel review.
- `gate` validates CWE format and CVSS v3.0/v3.1 vectors, computes the CVSS
  base score, and exits non-zero when promotion blockers remain.
- Canonical status transitions are enforced when `candidate-set --status` uses a
  roadmap workflow state such as `deduped`, `promoted`, `proved`,
  `root_cause_recorded`, `variant_searched`, `patch_diffed`, or `report_ready`.
- `dedup` exits non-zero when a known duplicate or possible regression is found.
- `score --fail-under <n>` exits non-zero when any scored candidate falls below
  the threshold.
- `patch-diff` verifies refs before running `git diff` and emits a fetch hint
  for shallow or missing refs.
- Surface patterns now live in `config/surfaces.yaml`; `map`, `source-graph`,
  `semantic-graph`, and `taint-trace` consume the same categories.
- `prove` writes raw stdout/stderr directly to disk and materializes capped
  `.out`/`.err` views, avoiding full in-memory output buffering.
- Use `ingest-blackbox-run <run_dir> <evidence_dir> --create-candidates` to
  bridge guarded outside-in scan evidence into the candidate ledger.
- After every external submission, record the platform outcome with
  `submissions add` and later `submissions update`. Without this, scoring and
  target selection cannot learn from results.
- Run `retro <run_dir>` at the end of every engagement. Review `retro.patch`
  before applying any knowledge change.
- Run `corpus-rebuild` after important ledger changes so `knowledge` and
  `corpus suggest` can reuse fresh evidence.
- Use `refine` after a candidate has enough fields for a class-specific probe.
  The delivered probes cover websocket authz drift, IDOR differential authz,
  serialization RCE, SSRF, parser canonicalization, prompt-injection tool
  chains, durable RAG poisoning, and model-card local file read. Run
  `probes-test` after probe edits to verify the captive fixtures.
- Use `sandbox-exec` for untrusted external tooling or payload experiments.
  It has no raw-shell fallback by design.
- Use `tool-gap-add` when a candidate needs a probe that does not exist yet;
  `tool-gaps` ranks what should be built next.
- Scanner wrappers write stdout/stderr/status/summary artifacts under
  `<run_dir>/tool_scans/<tool>/`. Missing tools create `.missing.json` refusal
  artifacts instead of stalling. `scan-nuclei` refuses to run without explicit
  templates unless `--allow-default-templates` is supplied.
- Use `tool-health --json` before planning a new engagement to see which local
  wrappers can run in the current venv/PATH.
- Use `ingest-tool-scan <run_dir> <artifact> --tool <tool>` to normalize scanner
  results. Add `--create-candidates` only when medium-or-higher scanner
  findings deserve manual review as `auto-candidate` triage seeds. They still
  require deduplication, latest-version verification, root cause, proof, and
  negative controls before reporting.
- Watch profiles live under `vapt/harness/watches/`; watch state lives under
  `vapt/harness/watches/state/`; generated work queue entries live under
  `vapt/harness/queue/<target_id>/`.
- Use local `repo_path` watch sources for offline, reproducible commit and
  release monitoring. Remote GitHub/GHSA/OSV polling is source-level opt-in via
  `--allow-network`; without it the harness records a skipped source instead of
  silently reaching out.
- Advisory watches can match on package name, package aliases, ecosystem, CWE,
  and trigger-text overlap. OSV-style affected versions and ranges are copied
  into queue entries for downstream dedup and latest-affected review.
- `campaign-start --refresh-advisories` reuses the same watch/queue layer and
  writes `advisory_refresh.md/json` inside the campaign workspace. Fresh queue
  entries are added to `NEXT_COMMANDS.md` as `candidate-from-queue --claim`
  steps before campaign run or dashboard steps.
- `candidate-add` auto-attaches `campaign_start` context when run inside a
  campaign workspace. Use `--campaign-module` to record the producing module
  early, and use `candidate-link-campaign` after `campaign-run`/`campaign-gate`
  pass to make runtime evidence promotion-ready.
- `candidate-from-queue` marks queue entries `converted`, records candidate id
  back into the queue YAML, and makes promotion/report gates validate the queue
  provenance before a queue-derived candidate can advance.
- Run `outcome-record` after every submitted report receives a meaningful
  status, then run `outcome-tune`. Future `campaign-plan` and `score` calls use
  `vapt/harness/corpus/outcome_tuning.yaml` to prioritize modules and candidate
  shapes that have performed better historically.
- If an advisory contains `fixed_commit` or `patch_range` and the watch has a
  local `repo_path`, the queue entry includes patch-window diff hunks, changed
  files, and matched trigger patterns.
- Treat queue entries as seeds, not findings. Claim an entry, inspect the diff
  or advisory, create a normal run/candidate, then use dedup, gate, proof,
  variant, patch-diff, score, and report as usual.
- MCP-facing wrapper metadata lives under `vapt/harness/mcp/`. The CLI remains
  the authoritative interface.
- Source mapping uses fixed-string `rg` searches so patterns like `eval(` and
  `Template(` do not break the mapper.
- New source-map categories cover realtime websocket/event paths, CORS/browser
  boundaries, AI prompt-injection chains, plugin systems, file storage, and
  supply-chain surfaces.
- Advanced source-map categories cover parser differentials, auth protocols,
  race/TOCTOU, and native memory-safety surfaces.
- Use `agents/websocket_authz.md` for REST-vs-realtime authorization drift.
- Use `agents/ai_security_reviewer.md` for AI/prompt-injection candidates.
- Use `agents/atomic_validation.md` to turn a thesis into one bounded local
  validation step with expected result and cleanup.
- Use `agents/root_cause_variant.md` after the first PoC passes.
- Use `agents/patch_diff_advisory.md` before drafting or submitting.
- Use `agents/exploitability_ladder.md` when deciding whether the bug is P1/P2
  or only P3/P4.
- Use `agents/web_protocol_research.md` for parser, cache, proxy, and auth
  protocol mismatch research.
- Use `agents/memory_safety_research.md` for native parser and exploit-dev
  candidates.
