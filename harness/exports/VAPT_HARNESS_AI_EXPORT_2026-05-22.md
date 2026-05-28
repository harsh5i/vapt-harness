# VAPT Harness AI Export

Generated: 2026-05-22
Harness version: `0.4.1-phase4-hardening`
Primary path: `vapt/harness/`
Runtime: workspace-local `.venv-vapt`

This file is the handoff entrypoint for an AI system that needs to understand
the local VAPT / bug bounty harness. It summarizes what the harness is, what it
can do, how to operate it, what safety boundaries apply, and what remains on the
roadmap. It intentionally excludes target evidence, PoC output, credentials,
and sensitive run artifacts.

## 1. Purpose

The harness is a local, deterministic, artifact-first vulnerability research
substrate inspired by public MDASH-style ideas. It does not replace a security
researcher or autonomously exploit real targets. It structures authorized
security research so that every candidate finding moves through repeatable
stages: target setup, source or blackbox mapping, candidate creation,
deduplication, promotion gating, proof, variant analysis, patch/advisory
review, scoring, reporting, and retrospective learning.

The design goal is model-agnostic operation: any capable AI or human operator
can cold-start from the harness files, inspect the run state, follow the
workflow, and produce auditable research artifacts without relying on hidden
chat history.

## 2. Safety And Authorization Rules

- Use only for authorized vulnerability assessment, bug bounty, or owned lab
  testing.
- Do not run destructive tests, denial-of-service checks, credential attacks, or
  mass scanning unless an explicit rules-of-engagement document permits it.
- Treat external exploit repositories, payload lists, and blog content as
  untrusted input. Learn taxonomy and methodology, but do not execute copied
  commands or payloads without sandboxing and review.
- Use low-rate, scoped blackbox checks first.
- For source review, prove issues against local checkouts or captive fixtures
  where possible.
- Use `sandbox-exec` for untrusted tooling or payload experiments. It uses
  Docker/Podman no-network mode when available and a macOS `sandbox-exec`
  fallback when Docker/Podman are absent.
- `prove` is bounded and safer by default: argv mode, timeout support, isolated
  evidence directories, capped output views, and explicit opt-in for shell mode.

## 3. Current Status

Completed harness roadmap phases:

- Phase 1: knowledge layer, cold-start commands, workflow explainability,
  budget checks, and corpus rebuild.
- Phase 2: feedback loop, submissions ledger, retrospective artifacts, target
  ranking, score tuning, and phase acceptance checks.
- Phase 3: reusable probe framework, scanner wrappers, scanner ingestion,
  PoC scaffolding, sandbox policy representation, tool-gap tracking, and phase
  acceptance checks.
- Phase 4: watch profiles, local git commit/release polling,
  fixture-backed advisory polling, queue entry creation/listing/claiming,
  daemon heartbeat mode, advisory cross-reference, patch-window enrichment,
  live remote polling validation, bounded soak checks, MCP-facing wrapper
  metadata, and acceptance checks.

Remaining empirical validation:

- A literal 24-hour daemon soak can only be marked complete after 24 real hours
  elapse. The command support exists through `phase4-soak-check --require-24h`.

Known local tool caveats as of 2026-05-25:

- `codeql` CLI `2.25.5` is installed workspace-locally at `.vapt-bin/codeql`.
- `osv-scanner` CLI `2.3.8` is installed through Homebrew.
- `semgrep` is installed in `.venv-vapt` and is operational through
  harness-managed workspace `HOME` and certificate-bundle environment settings.
- Docker/Podman are not available in this workspace; `sandbox-exec` uses the
  macOS `/usr/bin/sandbox-exec` fallback when available, with network denied and
  writes limited to the evidence directory plus explicit `:rw` mounts.

## 4. Filesystem Map

Core harness:

- `vapt/harness/harness.py`: CLI entrypoint and command implementation.
- `vapt/harness/README.md`: operator quick start and command reference.
- `vapt/harness/config/surfaces.yaml`: unified source surface pattern catalog.
- `vapt/harness/templates/candidate.yaml`: candidate schema template.
- `vapt/harness/targets/*.yaml`: registered target profiles.
- `vapt/harness/runs/<target>/<run-id>/`: generated run artifacts.

Knowledge and doctrine:

- `vapt/harness/knowledge/INDEX.md`: cold-start entrypoint.
- `vapt/harness/knowledge/principles.md`: operating principles.
- `vapt/harness/knowledge/workflow.md`: candidate state machine.
- `vapt/harness/knowledge/patterns.yaml`: reusable research patterns.
- `vapt/harness/knowledge/scoring.yaml`: scoring weights and thresholds.
- `vapt/harness/knowledge/programs/`: program-specific intelligence.
- `vapt/harness/knowledge/vuln_classes/`: vulnerability-class doctrine.
- `vapt/harness/knowledge/lessons/`: dated learning events.

Reviewer checklists:

- `vapt/harness/agents/`: focused review roles such as source mapping,
  deserialization, AI security, reference hygiene, dedup skepticism, web
  protocol research, fuzz proving, memory safety, root-cause/variant review,
  patch-diff advisory review, and exploitability ladder review.

Reusable probes:

- `vapt/harness/probes/`: reusable probe modules and probe base classes.
- `vapt/harness/tests/fixtures/probe_candidates.yaml`: captive candidates for
  probe regression.
- `vapt/harness/tests/results/`: phase and probe acceptance artifacts.

Environment and docs:

- `vapt/docs/VAPT_ENV.md`: virtual environment, installed tools, target-specific
  environments, and blackbox operating notes.
- `vapt/docs/VAPT_CAPABILITY_ASSESSMENT.md`: current capability and gaps.
- `vapt/docs/VAPT_TEST_PLAN.md`: operating test plan.
- `vapt/docs/VAPT_TOOLING_INVENTORY.md`: tool inventory.
- `vapt/docs/MYTHOS_SUBSTRATE_ROADMAP.md`: long-term harness roadmap.
- `vapt/docs/MYTHOS_SUBSTRATE_PHASE4_FOUNDATION_2026-05-25.md`: watch/queue
  foundation implementation note.
- `vapt/env/requirements-vapt.txt`: Python VAPT dependencies.
- `vapt/env/requirements-vapt.lock`: locked Python dependency inventory.

## 5. Capability Summary

### 5.1 Source-Assisted Bug Bounty Research

The harness supports source review for open-source targets, especially Python,
Go, JavaScript, TypeScript, and mixed stacks. It can:

- Initialize target-specific run directories.
- Fingerprint git source and fail fast on unintended non-git sources.
- Map source surfaces using a unified `surfaces.yaml` pattern catalog.
- Extract source graphs and semantic function-level categories.
- Generate hypotheses from source graph signals.
- Add and track exploit-thesis candidates.
- Enforce promotion gates before candidate escalation.
- Run local proof commands with bounded execution and evidence capture.
- Search variants and sibling surfaces.
- Mine patch ranges and advisory-like changes.
- Generate proof plans, flow traces, taint traces, and test skeletons.
- Draft triage reports from ledger evidence.
- Build HTML dashboards for run review.

### 5.2 Outside-In Blackbox VA

The surrounding VAPT environment supports authorized outside-in web assessment:

- DNS and subdomain recon: `amass`, `subfinder`, `dnsx`.
- HTTP probing and crawling: ProjectDiscovery `httpx`, `katana`.
- TLS checks: `sslyze`, `testssl.sh`, `tlsx`.
- Header checks: `shcheck.py`, `curl`-based harness wrapper.
- Web checks: `nikto`, `nuclei`, `wapiti`.
- Content discovery: `ffuf`, `feroxbuster`, `dirsearch`.
- XSS-focused testing: `dalfox`.
- Parameter discovery: `arjun`.
- Secret and dependency review: `trufflehog`, `detect-secrets`,
  `pip-audit`, `bandit`.
- Manual proxy support: `mitmproxy`.
- Network/service checks: `nmap`, `naabu`.

The guarded blackbox script writes durable evidence with timeouts:

```sh
RESOLVE_IP=<ip> STEP_TIMEOUT=180 ./vapt/scripts/vapt_blackbox_guarded.sh \
  https://example.com \
  example.com \
  vapt/evidence/example.com/<date>/<run-id>
```

Blackbox evidence can be bridged into the harness:

```sh
.venv-vapt/bin/python vapt/harness/harness.py ingest-blackbox-run \
  <run_dir> <evidence_dir> --create-candidates
```

### 5.3 Reusable Probe Framework

Reusable probes exist for recurring vulnerability classes:

- `websocket_authz_drift`
- `idor_diff`
- `serialization_rce`
- `ssrf_outbound`
- `parser_canonicalization`
- `prompt_injection_to_tool`
- `rag_poisoning_durability`
- `model_card_local_file_read`

Probe commands:

```sh
.venv-vapt/bin/python vapt/harness/harness.py probes
.venv-vapt/bin/python vapt/harness/harness.py probes-test
.venv-vapt/bin/python vapt/harness/harness.py refine <run_dir> <candidate_id>
.venv-vapt/bin/python vapt/harness/harness.py new-probe <probe_name>
```

### 5.4 Scanner Wrappers And Ingestion

Scanner wrappers capture evidence and normalize results into candidate seeds:

- `scan-semgrep`
- `scan-bandit`
- `scan-pip-audit`
- `scan-osv`
- `scan-codeql`
- `scan-trufflehog`
- `scan-tls`
- `scan-nuclei`
- `scan-headers`
- `tool-health`
- `ingest-tool-scan`

Supported ingestion formats include Bandit, Semgrep, Nuclei JSONL, pip-audit,
OSV, and TruffleHog.

### 5.5 Deduplication And Novelty Controls

The harness includes:

- Local known-duplicate checks from target profile metadata.
- OSV dedup checks using `dedup --check-osv`.
- Evidence persistence under run evidence directories.
- Non-zero exit behavior for duplicate or possible-regression outcomes.
- Reference ledger support using `reference-add`.

Novelty is not treated as a claim until supported by dedup artifacts, advisory
review, patch-diff review, and preferably negative controls.

### 5.6 Candidate Quality Gates

Promotion and report readiness require more than field presence. The harness
tracks:

- Attacker-controlled input.
- Entrypoint and reachability.
- Trust-boundary crossing.
- Concrete impact.
- Latest affected version.
- CWE format.
- CVSS v3.0/v3.1 vector and computed base score.
- Dedup status.
- Proof status.
- Negative control where relevant.
- Root cause as a broken invariant.
- Variant analysis artifact.
- Patch/advisory review.
- Exploitability ladder level.

`gate` and `score` can return non-zero for CI-like branching.

## 6. Canonical Workflow

Start with the virtual environment:

```sh
. ./vapt_env.sh
```

Create or open a run:

```sh
.venv-vapt/bin/python vapt/harness/harness.py init vapt/harness/targets/<target>.yaml
.venv-vapt/bin/python vapt/harness/harness.py session-start vapt/harness/runs/<target>/<run-id>
```

Prepare and map:

```sh
.venv-vapt/bin/python vapt/harness/harness.py prepare <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py map <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py source-graph <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py semantic-graph <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py hypothesize <run_dir>
```

Add a candidate:

```sh
.venv-vapt/bin/python vapt/harness/harness.py candidate-add <run_dir> \
  --title "<finding thesis>" \
  --surface "<component>" \
  --weakness "CWE-<id>" \
  --impact "<security impact>" \
  --attacker-control "<attacker-controlled input>" \
  --entrypoint "<entrypoint>" \
  --trust-boundary "<boundary crossed>" \
  --latest-affected yes \
  --sink "<sink>"
```

Deduplicate and gate:

```sh
.venv-vapt/bin/python vapt/harness/harness.py dedup <run_dir> <candidate_id> \
  --check-osv --osv-ecosystem <ecosystem> --osv-package <package>
.venv-vapt/bin/python vapt/harness/harness.py gate <run_dir> <candidate_id> --promote
```

Prove and refine:

```sh
.venv-vapt/bin/python vapt/harness/harness.py proof-plan <run_dir> <candidate_id>
.venv-vapt/bin/python vapt/harness/harness.py prove <run_dir> <candidate_id> \
  --timeout 60 --cmd "<argv-style command>"
.venv-vapt/bin/python vapt/harness/harness.py refine <run_dir> <candidate_id>
.venv-vapt/bin/python vapt/harness/harness.py variant <run_dir> <candidate_id>
.venv-vapt/bin/python vapt/harness/harness.py patch-diff <run_dir> <candidate_id> \
  --base <git-ref> --head <git-ref>
```

Score and report:

```sh
.venv-vapt/bin/python vapt/harness/harness.py score <run_dir> --fail-under 85
.venv-vapt/bin/python vapt/harness/harness.py gate <run_dir> <candidate_id> --report-ready
.venv-vapt/bin/python vapt/harness/harness.py report <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py dashboard <run_dir>
```

Close the learning loop:

```sh
.venv-vapt/bin/python vapt/harness/harness.py submissions add ...
.venv-vapt/bin/python vapt/harness/harness.py retro <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py corpus-rebuild
.venv-vapt/bin/python vapt/harness/harness.py score-tune
```

## 7. Command Surface

Important commands:

- `commands --json`: emit machine-readable command manifest.
- `explain <command>`: command help plus relevant knowledge pointers.
- `knowledge <query>`: search local doctrine and prior corpus.
- `session-start <run_dir>`: cold-start context for a model or fresh session.
- `next-action <run_dir>`: recommend the next workflow step.
- `budget <run_dir>`: compare elapsed time to target budgets.
- `corpus-rebuild`: rebuild append-only candidate corpus.
- `retro <run_dir>`: write retrospective and reviewable knowledge patch.
- `pick-target`: rank registered targets by expected-value signals.
- `score-tune`: tune scoring from submission outcomes.
- `phase2-check`: run Phase 2 acceptance checks.
- `phase3-check`: run Phase 3 acceptance checks.
- `probes`, `probes-test`, `refine`, `scaffold-poc`, `new-probe`: probe
  operations.
- `sandbox-exec`: Docker/Podman no-network sandbox runner with macOS
  `sandbox-exec` fallback.
- `tool-gap-add`, `tool-gaps`: track missing capability.
- `tool-health`: list scanner/tool availability.
- `ingest-tool-scan`: normalize scanner output and optionally create
  auto-candidates.
- `init`, `prepare`, `map`, `source-graph`, `semantic-graph`, `hypothesize`:
  target setup and mapping.
- `candidate-add`, `dedup`, `gate`, `candidate-set`, `candidates`: ledger and
  state operations.
- `prove`, `variant`, `patch-diff`, `patch-mine`, `proof-plan`, `flow-trace`,
  `taint-trace`, `test-skeleton`: proof and analysis operations.
- `ledger-sqlite`: mirror candidate ledger to or from SQLite.
- `ingest-blackbox-run`: ingest guarded outside-in evidence.
- `reference-add`: maintain reference hygiene ledger.
- `status --json`: pipeable run state summary.

## 8. Scoring And Report Readiness

The harness is intentionally strict. A candidate with a catchy title is not a
finding. It becomes report-ready only when the evidence proves:

- A valid attacker path exists.
- The vulnerable behavior crosses a meaningful security boundary.
- The impact is concrete and aligned with the program scope.
- The current or latest supported version is affected, unless the finding is an
  affected-version correction.
- The issue is not a known duplicate, or is framed as a regression/incomplete
  fix with evidence.
- A negative control exists where absence of access or behavior matters.
- Variant and patch-diff analysis have been completed or explicitly scoped out.
- CVE/CWE/CVSS handling is consistent and validated.

## 9. External AI Operating Instructions

An AI using this export should:

1. Read `vapt/harness/knowledge/INDEX.md`, `vapt/harness/README.md`, and this
   file first.
2. Run `session-start <run_dir>` before touching a run.
3. Use `next-action <run_dir>` instead of guessing the next step.
4. Use `knowledge <query>` before inventing a method.
5. Treat scanner results and pattern hits as leads, not findings.
6. Never promote a candidate without dedup and gate evidence.
7. Never submit a report without a working PoC, negative controls where
   applicable, novelty evidence, and a clear impact statement.
8. Keep every action artifact-first: if it is not written to disk, it did not
   happen.
9. Run retrospectives after engagements and rebuild the corpus after material
   ledger changes.
10. Preserve authorization boundaries and target rules of engagement.

## 10. Assessment

The harness is stronger than a basic checklist or one-off scanner wrapper. It
now provides repeatable research flow, durable evidence, candidate quality
gates, reusable probes, scanner normalization, and a learning loop. It is useful
for disciplined source-assisted bug bounty research and authorized blackbox VA.

It now has the continuous watch and queue substrate from the roadmap. Queue
entries remain candidate seeds, not reportable findings; normal dedup, gate,
proof, variant, patch-diff, score, and report steps still apply.
