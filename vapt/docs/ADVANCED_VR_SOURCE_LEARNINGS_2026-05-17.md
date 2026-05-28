# Advanced Vulnerability Research Source Learnings - 2026-05-17

The sources below were used as methodology references only. No payloads, exploit
code, prompts, scripts, or tool installation instructions were executed or
imported.

## Source Groups Reviewed

- High-end vulnerability research blogs: Project Zero, watchTowr Labs,
  Assetnote, Trail of Bits, NCC Group, Synacktiv, Doyensec, Quarkslab, Include
  Security, Orange Tsai/devco.re, Detectify Labs, Sam Curry.
- Web exploitation research: PortSwigger Research, James Kettle research, public
  Hacktivity writeups.
- Canonical journals/zines: Phrack, PoC||GTFO.
- Academic venues: USENIX Security, IEEE S&P, NDSS, ACM CCS.
- Conference archives: Black Hat, DEF CON, CCC.
- Exploit development and low-level research: Connor McGarr, Saar Amar, Azeria,
  ret2, SpecterOps.
- Disclosure/advisory feeds: ZDI, GitHub Security Lab, oss-security, Full
  Disclosure, Exodus.
- Curated sources: tl;dr sec, hxp writeups.

## Lessons Adopted

### 1. Root Cause Over Single Payload

Top-tier research explains the broken invariant, not only the input that
triggered it. Harness candidates now include `root_cause` and have a dedicated
`root_cause_variant` reviewer.

### 2. Variant Analysis Is Mandatory For Strong Reports

Project Zero-style reports and high-quality advisories often ask "where else
does this invariant fail?" The harness now records `variant_analysis` so we do
not stop after the first PoC.

### 3. Patch Diff And Advisory Triage Raises Novelty

ZDI, GitHub Security Lab, oss-security, and vendor advisories are duplicate and
novelty gates. The new `patch_diff_advisory` reviewer forces explicit status:
new, duplicate, incomplete fix, regression, affected-version correction, or
configuration-specific exposure.

### 4. Exploitability Must Be Staged Honestly

Low-level and academic work separates crash, primitive, exploit chain, and
real-world impact. The new `exploitability_ladder` checklist prevents severity
inflation and states the next experiment needed to improve a finding.

### 5. Web Bugs Often Come From Parser Disagreement

PortSwigger, Orange Tsai, Assetnote, and watchTowr-style work frequently turns
on proxy/app, cache/origin, router/controller, or IdP/SP disagreement. The
source mapper now has `parser_differential`, `auth_protocol`, and
`race_toctou` categories, and a `web_protocol_research` reviewer was added.

### 6. Memory Safety Needs Primitive Evidence

Crash-only native findings should not be treated as high-confidence RCE. The
new `memory_safety_research` reviewer requires sanitizer traces or deterministic
primitive evidence before report-ready promotion.

### 7. Academic Papers Are For Techniques, Not Direct Claims

Academic and conference sources should feed techniques: model checking, fuzzing
strategy, parser differentials, sandbox boundary mapping, and exploitability
reasoning. They do not replace current-version local proof.

### 8. Disclosure Quality Is Part Of Exploit Quality

High-quality reports show version, config, preconditions, negative controls,
root cause, impact, reproduction, remediation, and duplicate/advisory status.
The harness candidate model now includes `disclosure_quality`.

## Harness Changes Made

- Added candidate fields:
  - `root_cause`
  - `variant_analysis`
  - `patch_diff`
  - `exploitability`
  - `disclosure_quality`
- Added source-map categories:
  - `race_toctou`
  - `memory_safety_native`
  - `parser_differential`
  - `auth_protocol`
- Added reviewer checklists:
  - `root_cause_variant.md`
  - `patch_diff_advisory.md`
  - `exploitability_ladder.md`
  - `web_protocol_research.md`
  - `memory_safety_research.md`
- Added harness commands:
  - `variant`: creates run artifacts for sibling-surface searches based on the
    candidate's sink, root-cause terms, and supplied patterns.
  - `patch-diff`: creates run artifacts for git diff/stat/name-status review
    across refs and paths, with optional `git diff -G` pattern summaries.
  - `source-graph`: extracts lightweight source-graph artifacts for functions,
    routes, authz checks, websocket/event publishers, parsers, storage,
    network clients, process execution, and native unsafe surfaces.
  - `cluster-variants`: clusters variant-analysis hits by file and rough symbol
    so sibling surfaces are easier to triage.
  - `score`: scores candidate quality from proof, novelty, latest affected
    status, root cause, negative controls, and evidence completeness.
  - `hypothesize`: generates review hypotheses from source-graph signals while
    keeping them separate from validated candidates.
  - `patch-mine`: scans one or more git diff ranges for security-relevant
    changes across configurable paths and patterns.
  - `proof-plan`: writes a proof plan with thesis, preconditions, positive
    proof, negative controls, evidence, cleanup, and submission blockers.
  - `semantic-graph`: extracts function-level categories and lightweight call
    edges from Go/Python/JS/TS files.
  - `flow-trace`: maps candidate terms to semantic-graph functions and ranks
    likely source/sink/authz points.
  - `test-skeleton`: creates a local proof-test skeleton without modifying the
    target source tree.

## Non-Adoptions

- No exploit payloads, shells, or bypass strings were imported.
- No third-party scripts were run.
- No low-level exploit techniques are used outside local authorized targets.
- Public writeups are not treated as proof for a target; they only shape
  hypotheses and review strategy.

## Updated Bar For Bug Bounty Work

Before a candidate is called report-ready, record:

1. Latest affected version.
2. Attacker-controlled input and reachable entrypoint.
3. Trust boundary and violated invariant.
4. Root cause.
5. Negative control.
6. Variant search result.
7. Duplicate/advisory status.
8. Exploitability ladder level.
9. CVE/CWE/CVSS or clear reason CVE is not assigned.
10. Suggested remediation tied to root cause.

## Operational Note

`patch-diff` only works with refs available in the local checkout. For shallow
release checkouts, fetch the relevant tags/commits first or use an available
range such as `HEAD..HEAD` for a smoke check.
