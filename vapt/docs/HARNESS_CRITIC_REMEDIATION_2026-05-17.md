# Harness Critic Remediation - 2026-05-17

This records the first remediation pass against the independent harness review.

## Fixed

- `prove` no longer shell-executes by default.
  - Default mode parses `--cmd` with `shlex` and executes argv directly.
  - `--shell` is now explicit opt-in.
  - Default cwd is an isolated candidate evidence directory.
  - `--cwd` can be supplied for repo-root or target-repo proofs.
  - Process group is killed on timeout.
  - Optional CPU, memory, and file-size limits are available.
  - stdout/stderr are capped in persisted artifacts.
- Candidate ledger writes now use `candidates.yaml.lock`.
  - Applied to candidate add/set, dedup, gate, prove, score, variant markers,
    cluster markers, patch-diff markers, proof-plan markers, flow traces, and
    test skeleton markers.
- Candidate loading now performs schema normalization.
  - Older candidates get missing fields populated in memory and on the next
    ledger write.
  - Invalid history/dedup/framework field shapes are normalized.
- Promotion gate now rejects placeholder field values.
  - `x`, `todo`, `tbd`, and empty values do not satisfy core fields.
- CWE and CVSS validation added.
  - CWE must match `CWE-NNN`.
  - CVSS v3.0/v3.1 vectors are parsed and base score is computed.
- `dedup --check-osv` added.
  - Queries `osv.dev` by target/CLI package metadata and candidate CVE/GHSA IDs.
  - Persists raw JSON and Markdown evidence under `evidence/dedup/`.
  - No longer presents static substring-only checks as broad novelty research.
- Exit codes improved.
  - `gate` exits non-zero on blockers.
  - `dedup` exits non-zero on known duplicate or possible regression.
  - `score --fail-under N` exits non-zero below threshold.
  - `patch-diff` exits non-zero on missing refs.
- `patch-diff` verifies refs before running diff.
  - Missing/shallow refs now produce an artifact with a fetch hint.
- `prepare` fails on non-git source by default.
  - `--allow-non-git` is required for intentional tarball/wheel review.
- Pattern coverage expanded.
  - Added child process, Java runtime/process builder, Go exec, httpx, aiohttp,
    axios, urllib, Go `http.NewRequest`, cookie/session/CSRF/SameSite patterns.
- References ledger added.
  - `reference-add` appends primary sources to `references.yaml`.
  - `report` includes the references ledger.
- `status --json` added for pipeable automation.

## Closed In Follow-Up Pass

- Full unification of `PATTERNS` and `GRAPH_QUERIES` into one config:
  `vapt/harness/config/surfaces.yaml`.
- Regression corpus for surface patterns:
  `vapt/harness/tests/surface_corpus/` and
  `vapt/harness/tests/surface_expectations.yaml`, exercised by
  `surfaces-test`.
- Proof output buffering:
  `prove` now writes raw stdout/stderr directly to disk and materializes capped
  `.out`/`.err` views.
- SQLite ledger option:
  `ledger-sqlite` mirrors `candidates.yaml` into `candidates.sqlite` and can
  restore YAML when explicitly called with `--from-sqlite`.
- Blackbox evidence ingestion:
  `ingest-blackbox-run` parses guarded scan evidence and can create candidates.
- Taint/dataflow:
  `taint-trace` adds lightweight intra-procedural source-to-sink tracing from
  request/query/body/URL/param/argument sources into configured sink categories.

## Remaining Caveats

- `taint-trace` is intentionally lightweight and intra-procedural. It is now a
  real dataflow pass, but not a CodeQL-grade interprocedural analysis engine.
- SQLite is a mirror/restore path, not the primary live ledger. YAML remains the
  default source of truth for simple reviewability.
- Blackbox ingestion normalizes common nuclei JSON/JSONL and text evidence; each
  ingested candidate still needs human validation before promotion.
- Variant-term ranking and scoring rationale can still be improved, but they are
  no longer blockers for harness operation.

## Smoke Checks

- `python -m py_compile vapt/harness/harness.py`: passed.
- `status --json` on DemoTarget run: passed.
- `score --fail-under 85` on `MM-CAND-001`: passed.
- `gate MM-CAND-001`: passed with CWE/CVSS validation.
- `patch-diff` with a missing ref: exited non-zero and wrote a fetch-hint
  artifact instead of silently producing misleading output.
- `surfaces-test`: passed after config/corpus alignment.
- `ledger-sqlite`: created `candidates.sqlite` for the DemoTarget run.
- `ingest-blackbox-run`: parsed sample nuclei JSONL evidence.
- `taint-trace`: generated DemoTarget source-to-sink trace artifacts.
- `prove`: verified file-backed raw stdout/stderr artifacts on a bounded local
  command.
