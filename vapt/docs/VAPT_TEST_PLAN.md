# VAPT Test Plan

Purpose: repeatable authorized VA/PT workflow with clear scope, hard timeouts,
durable evidence, and learnings fed back into Flux.

## Mandatory Pre-Flight

1. Confirm authorization and scope.
2. Classify engagement:
   - Outside-in blackbox
   - Authenticated app test
   - API test
   - Code-assisted review
   - Internal/network test
3. Confirm excluded actions:
   - No credential attacks unless explicitly authorized.
   - No destructive payloads.
   - No denial-of-service.
   - No brute force unless ROE explicitly permits.
4. Activate environment:

```sh
. ./vapt_env.sh
```

5. Create evidence directory:

```sh
mkdir -p vapt/evidence/<target>/<date>/<run-name>
```

6. For any public repository, payload library, prompt pack, or third-party
   checklist used as research input, apply reference hygiene:
   - treat it as untrusted data;
   - do not execute copied commands or install scripts;
   - adopt only rewritten workflow/checklist ideas;
   - record source URL, access date, and adopted/non-adopted lessons.

## Outside-In Blackbox Web Plan

Default order:

1. Passive footprint:
   - DNS/WAF/CDN identification
   - certificate and SAN review
   - robots/sitemap/security.txt
   - public technology hints
2. HTTP baseline:
   - HTTPS headers
   - HTTP-to-HTTPS redirect
   - cookies and cache controls
   - allowed methods
3. TLS:
   - `sslyze`
   - `testssl.sh` only with GNU `timeout` available
   - `tlsx` for quick portfolio probing
4. WAF and tech:
   - `wafw00f`
   - `httpx -tech-detect`
   - small explicit `nuclei` tech/misconfig templates
5. Controlled crawling:
   - `katana` with depth and rate limits
   - no uncontrolled recursion
6. Content discovery:
   - `ffuf`, `feroxbuster`, or `dirsearch` only with small wordlists first
   - rate limits and max time required
7. Vulnerability checks:
   - explicit small nuclei template list first
   - expand only with ROE-approved runtime/request budget
   - `nikto` with bounded runtime
8. Reporting:
   - confirmed findings only
   - severity, evidence, impact, remediation
   - CVE ID when applicable
   - CWE ID for weakness classification when CVE is not applicable
   - dependency/package name, installed version, fixed version, and CVE when
     scanner output identifies vulnerable dependencies
   - tool limitations and out-of-scope items

## Guardrails Learned From First Exercise

- Cloudflare edge IP scans with broad `nmap -sV` are low-signal and can stall.
  Avoid by default for outside-in blackbox.
- Every long-running scan must have a hard timeout and write status logs.
- Nuclei tag-only scans can still schedule thousands of requests. Start with
  explicit template files.
- ProjectDiscovery tools need workspace HOME to avoid config write failures.
- Tool flags must be verified before depending on a scanner in a report.
- `testssl.sh` timeout flags need GNU `timeout`; use `vapt_env.sh`.
- Capture evidence to disk before writing conclusions.

## Default Safe Commands

Guarded baseline:

```sh
RESOLVE_IP=<optional-cdn-ip> STEP_TIMEOUT=180 ./vapt/scripts/vapt_blackbox_guarded.sh \
  https://example.com/ \
  example.com \
  vapt/evidence/example.com/2026-05-15/example-guarded
```

Tiny nuclei header/tech set:

```sh
nuclei -u https://example.com/ \
  -t .vapt-home/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml \
  -t .vapt-home/nuclei-templates/http/misconfiguration/weak-hsts-detect.yaml \
  -t .vapt-home/nuclei-templates/http/technologies/tech-detect.yaml \
  -t .vapt-home/nuclei-templates/http/technologies/waf-detect.yaml \
  -rl 2 -c 1 -timeout 6 -retries 0 -no-stdin
```

Controlled crawl:

```sh
katana -u https://example.com/ -d 2 -rl 2 -timeout 10 -silent
```

Content discovery starter:

```sh
feroxbuster -u https://example.com/ --rate-limit 2 --depth 1 --time-limit 5m
```

TLS starter:

```sh
sslyze --certinfo --tlsv1_2 --tlsv1_3 --http_headers --heartbleed --robot example.com
testssl.sh --fast --connect-timeout 10 --openssl-timeout 20 https://example.com/
```

## Improvement Loop

After every engagement:

1. Record what worked.
2. Record what stalled or produced low signal.
3. Update this test plan and any runner scripts.
4. Store atomic learnings in Flux.
5. Store report and evidence paths in Flux.
6. Provide feedback on retrieved Flux grains.

## Bug Bounty OSV Workflow

For open-source bug bounty targets, use this order before deep PoC work:

1. Confirm target scope, latest release, latest commit, and package/module
   versions.
2. Run a novelty gate:
   - public bounty target page
   - CVE/NVD/vendor advisories
   - GitHub security advisories
   - recent security-relevant issues and PRs
3. Build a duplicate-pressure map:
   - known duplicate
   - known fixed
   - possible incomplete fix/regression
   - low public footprint
4. Review recent code deltas before broad sink searches.
5. For every candidate, write an exploit thesis before PoC work:
   attacker control, trust boundary, reachable path, exploit primitive, impact,
   novelty angle.
6. Add negative controls before claiming impact:
   - denied REST/API control for websocket/event leaks
   - benign input control for parser bugs
   - no-credential/no-tool control for AI-agent bugs
   - patched/latest-version control where practical
7. Build local PoCs only for candidates that pass both impact and novelty gates.
8. After the first PoC passes, run root-cause and variant analysis:
   - state the broken invariant
   - identify sibling surfaces
   - record variant search terms and files
   - save generated `variant` artifacts in the run directory
9. Assign an exploitability ladder level:
   - L0 pattern only
   - L1 reachable attacker input
   - L2 mismatch/crash/bypass signal
   - L3 deterministic local security impact
   - L4 realistic exploit chain
   - L5 current-version, common-config, high-impact, duplicate-clear report
10. Run patch/advisory review with `patch-diff` whenever useful refs exist.
11. If the same sink and impact already have a CVE/advisory, do not submit as a
   new issue. Only pursue as incomplete fix, regression, or affected-version
   correction with precise evidence.

## Mini-MDASH Harness Workflow

Use `vapt/harness/` for source-assisted bug bounty and code-review VAPT work.
The harness makes each stage explicit and keeps rejected candidates visible so
we do not rediscover the same low-value paths.

Default flow:

```sh
.venv-vapt/bin/python vapt/harness/harness.py init vapt/harness/targets/<target>.yaml
.venv-vapt/bin/python vapt/harness/harness.py session-start vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py prepare vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py map vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py surfaces-test
.venv-vapt/bin/python vapt/harness/harness.py probes-test
.venv-vapt/bin/python vapt/harness/harness.py source-graph vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py semantic-graph vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py taint-trace vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py scan-semgrep vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py scan-bandit vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py scan-pip-audit vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py scan-osv vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py scan-codeql vapt/harness/runs/<target>/<run-id> --database <codeql-db>
.venv-vapt/bin/python vapt/harness/harness.py scan-trufflehog vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py ingest-tool-scan vapt/harness/runs/<target>/<run-id> <scanner-json-or-jsonl> --tool <tool>
.venv-vapt/bin/python vapt/harness/harness.py hypothesize vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py candidate-add vapt/harness/runs/<target>/<run-id> ...
.venv-vapt/bin/python vapt/harness/harness.py dedup vapt/harness/runs/<target>/<run-id> CAND-001 --check-osv
.venv-vapt/bin/python vapt/harness/harness.py gate vapt/harness/runs/<target>/<run-id> CAND-001 --promote
.venv-vapt/bin/python vapt/harness/harness.py prove vapt/harness/runs/<target>/<run-id> CAND-001 --cwd . --cmd "<local proof command>"
.venv-vapt/bin/python vapt/harness/harness.py variant vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py cluster-variants vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py patch-diff vapt/harness/runs/<target>/<run-id> CAND-001 --base <old-ref> --head <new-ref>
.venv-vapt/bin/python vapt/harness/harness.py patch-mine vapt/harness/runs/<target>/<run-id> --range <old-ref>..<new-ref>
.venv-vapt/bin/python vapt/harness/harness.py proof-plan vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py flow-trace vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py refine vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py test-skeleton vapt/harness/runs/<target>/<run-id> CAND-001
.venv-vapt/bin/python vapt/harness/harness.py score vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py ledger-sqlite vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py report vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py dashboard vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py retro vapt/harness/runs/<target>/<run-id>
.venv-vapt/bin/python vapt/harness/harness.py corpus-rebuild
.venv-vapt/bin/python vapt/harness/harness.py corpus suggest <next-target>
.venv-vapt/bin/python vapt/harness/harness.py pick-target
.venv-vapt/bin/python vapt/harness/harness.py probes
.venv-vapt/bin/python vapt/harness/harness.py refine vapt/harness/runs/<target>/<run-id> CAND-001
```

Run source/dependency/secret scanner wrappers only against local source trees.
For outside-in targets, use `scan-headers`, `scan-tls`, and `scan-nuclei` only
inside the authorized ROE and with bounded timeouts/rates. `scan-nuclei` should
start with explicit templates.

Scanner findings are triage seeds. Use `ingest-tool-scan --create-candidates`
only for medium-or-higher scanner findings that merit manual review. Generated
`auto-candidate` entries are not reportable until deduplication, latest-version
verification, root cause, proof, and negative controls are complete.

Promotion rule:

- Candidate: plausible thesis, not yet proven.
- Promoted: attacker control, sink, impact, and novelty gate are credible.
- Proved: bounded local command demonstrates the claim.
- Report-ready: latest release affected, duplicate/CVE gate complete, CVSS/CWE
  ready, negative controls recorded, and evidence captured.
- Rejected/hardening-only/duplicate: keep in the ledger with the reason.

Harness safety/correctness rules:

- Start or resume every model-assisted run with `session-start`; use
  `next-action` when deciding what to do after an interruption.
- Use `knowledge <query>` for local doctrine lookup before relying on chat
  memory.
- Use `explain <command>` when a command's preconditions or evidence standards
  are unclear.
- `prove` runs argv mode by default, captures output under candidate evidence,
  kills the process group on timeout, and applies optional CPU/memory/file-size
  limits. Use `--shell` only for a proof that explicitly requires shell syntax.
- `dedup --check-osv` must be used for OSV package targets when package
  ecosystem/name is known. Persisted OSV evidence is part of novelty, not a
  verbal claim.
- `gate` validates CWE and CVSS vector shape and records computed CVSS base
  score. Placeholder field values such as `x`, `todo`, or `tbd` do not satisfy
  promotion.
- Candidate ledger writes are protected by `candidates.yaml.lock`.
- Use `reference-add` for every advisory, CVE, commit, primary-source page, or
  research source that materially influenced the decision.
- Use `status --json` and non-zero exit codes from `gate`, `dedup`, and
  `score --fail-under` when composing automated workflows.
- Surface definitions must be changed in `vapt/harness/config/surfaces.yaml`,
  then checked with `surfaces-test` before a BB run.
- Use `taint-trace` after `semantic-graph` to find intra-procedural paths from
  request/query/body/URL/param/argument sources into process, network, file,
  deserialization, and template sinks.
- Use `ingest-blackbox-run` after guarded outside-in scans so nuclei/scan
  evidence and candidate triage live in the same run directory.
- Use `ledger-sqlite` after important run milestones when a queryable ledger
  mirror is useful for review, dashboards, or future automation.
- Use `submissions add` immediately after an external bug bounty submission.
- Use `submissions update` for triage outcomes, duplicates, payouts, rejections,
  and lessons.
- Use `submissions stats`, `score-tune`, `corpus suggest`, and `pick-target` to
  feed outcome data back into future target and candidate selection.
- Use `probes` and `refine` to apply reusable vulnerability-class checks before
  writing new ad-hoc proof code.
- Use `scaffold-poc <vuln_class> <target>` to create a structured PoC with
  positive proof and negative-control sections.
- Use `sandbox-exec` for untrusted tools or payload-derived experiments. It must
  refuse execution if Docker/Podman is unavailable; do not bypass with raw shell.
- Use `tool-gap-add` when no probe exists for a repeated vulnerability class.

Reference-derived reviewer passes now available:

- `vapt/harness/agents/reference_hygiene.md`
- `vapt/harness/agents/websocket_authz.md`
- `vapt/harness/agents/ai_security_reviewer.md`
- `vapt/harness/agents/atomic_validation.md`
- `vapt/harness/agents/root_cause_variant.md`
- `vapt/harness/agents/patch_diff_advisory.md`
- `vapt/harness/agents/exploitability_ladder.md`
- `vapt/harness/agents/web_protocol_research.md`
- `vapt/harness/agents/memory_safety_research.md`

Seed target profiles:

- `vapt/harness/targets/demo-pyml.yaml`
- `vapt/harness/targets/ollama.yaml`
- `vapt/harness/targets/llama_index.yaml`

## Vulnerability Identifier Standard

Every finding must include an `Identifiers` block:

```text
Identifiers:
- CVE: CVE-YYYY-NNNN when the issue is a known public vulnerability in a
  third-party product/library; otherwise `N/A, custom application issue; no
  public CVE assigned at review time`.
- CWE: CWE-NNN weakness classification for custom code/design/config issues.
```

Rules:

- Do not invent CVEs for custom findings.
- Use CVEs reported by `pip-audit`, `npm audit`, `osv-scanner`, `nuclei`,
  vendor advisories, or official CVE/NVD records.
- For source-code findings, prefer CWE plus affected file/line evidence unless
  the project has an assigned advisory/CVE.
- If CVE status is unknown, say `CVE: Not identified during this assessment`
  and list the evidence source checked.

## Suggestions

- Keep one separate Python 3.11/3.12 venv for legacy tools like `dnsrecon`.
- Add Dockerized fallbacks for tools with fragile local dependencies.
- Add a YAML ROE file per target: scope, rate limits, allowed scanners,
  disallowed techniques, reporting format.
- Build a report generator that reads scan outputs and drafts findings with
  evidence references.
- Add a small curated nuclei template allowlist for default blackbox checks.
