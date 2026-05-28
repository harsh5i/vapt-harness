# Bug Bounty Method Review - 2026-05-15

Scope: principle-based review of the `llama_index` and `ollama` bug bounty passes.

## Executive View

Both reviews produced useful technical evidence, but neither produced a fresh submit-ready report. The core issue was not lack of vulnerability discovery; it was novelty filtering. In both targets, the highest-signal findings were in heavily reported classes:

- `llama_index`: unsafe pickle deserialization was reproducible, but mapped to `CVE-2024-14021`.
- `ollama`: SSRF, DNS rebinding, digest traversal, auth realm, GGUF parser, and `/api/create` DoS classes had strong public duplicate pressure.

Going forward, the default goal should be: find a novel security boundary violation, prove it locally, and disprove obvious duplication before investing in a full PoC.

## Principle 1: Novelty Before Depth

What happened:

- We mapped dangerous sinks first, then performed duplicate checks after credible candidates emerged.
- This worked for correctness but wasted time validating known classes.

Improvement:

- Add a mandatory 20-30 minute novelty gate before deep review:
  - public Huntr target page
  - NVD/CVE search
  - GitHub security advisories
  - recent issues/PRs touching security-sensitive paths
  - release notes around fixes
- Build a duplicate-pressure map before source review:
  - `known duplicate`
  - `known fixed`
  - `known class but possibly new variant`
  - `low public footprint`

Practice rule:

- Do not spend PoC time on a known sink unless the hypothesis is explicitly a bypass, incomplete fix, affected-version correction, or impact escalation.

## Principle 2: Impact Chains Beat Sink Lists

What happened:

- The reviews began with broad sink discovery: pickle, torch, URL fetch, file paths, CORS, redirects, template parsing, native parsing.
- This identifies candidates, but it does not prove bounty value.

Improvement:

- Frame each candidate as an impact chain before implementation:
  - attacker control
  - trust boundary crossed
  - reachable API/package path
  - exploit primitive
  - final impact
  - novelty angle
- Reject candidates that only show a dangerous function without a realistic attacker-controlled path.

Practice rule:

- Every candidate gets a one-line exploit thesis before code execution. Example: "Remote attacker controls registry redirect; server follows it to internal HTTP service; response is persisted and later exfiltrated."

## Principle 3: Reproduction Is Necessary, Not Sufficient

What happened:

- `llama_index` BGE-M3 pickle RCE was reproduced locally against latest split package.
- Reproduction alone did not make it submit-ready because the same sink already had a CVE and public advisory.

Improvement:

- Treat reproduction as one column in the triage matrix, not the end state.
- Add required columns:
  - Latest affected version?
  - CVE exists?
  - Same sink?
  - Same package or package split?
  - Same impact?
  - Same exploit preconditions?
  - New affected-version evidence?

Practice rule:

- If the same sink and impact are known, the only viable submission is a precise regression/incomplete-fix report with version evidence.

## Principle 4: Timebox Commodity Classes

What happened:

- Ollama had many duplicate-heavy classes: SSRF, DNS rebinding, GGUF OOM, no-auth exposed API, path traversal.
- Continuing to dig in those classes without a new bypass angle would likely produce duplicates.

Improvement:

- Assign explicit timeboxes:
  - 15 minutes to confirm duplicate-heavy class.
  - 30-45 minutes to test a plausible bypass.
  - Stop unless there is a materially new primitive.

Practice rule:

- When a target has high duplicate density, move quickly to less-crowded surfaces: newly added modules, experimental features, compatibility shims, edge parsers, or cross-feature chains.

## Principle 5: Prefer Recent Code Deltas

What happened:

- The reviews focused on stated attack surfaces, not enough on recent commits and newly introduced code.

Improvement:

- Start each BB with:
  - latest release tag vs `main`
  - commits since release
  - security-sensitive files changed in the last 30-90 days
  - new integrations/packages/modules

Practice rule:

- Novel bugs are more likely in new code, new integrations, and refactors than in famous vulnerable sinks.

## Principle 6: Submission Quality Starts Early

What happened:

- Reports included CVE/CWE mapping and evidence, which is good.
- CVSS and exploit narrative were deferred because no fresh finding survived triage.

Improvement:

- For every live candidate, maintain a draft with:
  - CVE: existing ID or `N/A`
  - CWE
  - CVSS 3.1 draft vector
  - attacker model
  - affected version/commit
  - reproduction status
  - duplicate status
  - patch direction

Practice rule:

- A candidate without a credible CVSS vector and attacker model is not ready for PoC investment.

## Practice Changes

Adopt this bug bounty workflow:

1. Scope and authorization.
2. Fingerprint latest release, latest commit, package versions.
3. Run novelty gate and duplicate-pressure map.
4. Build attack-surface map from target guidance plus recent code deltas.
5. Form candidate theses with attacker control and impact chain.
6. Timebox sink validation.
7. Build local PoC only for candidates that pass novelty and impact gates.
8. Produce triage report even when no submission is made.
9. Store artifacts and atomic learnings in Flux.

## New Hunting Bias

For `llama_index`-style targets:

- Prioritize recently added integrations with file, HTTP, database, or SaaS credentials.
- Look for prompt-injection-to-tool-impact chains, not standalone jailbreaks.
- Hunt package-split regressions only when affected-version metadata is clearly wrong.

For `ollama`-style targets:

- Avoid commodity SSRF/DNS rebinding/GGUF OOM unless testing a clear bypass.
- Prioritize upload paths, experimental APIs, OpenAI/Anthropic compatibility middleware, decompression/body handling, safetensors parsing, and cross-feature chains.
- Native/parser fuzzing should be coverage-guided and compared against public CVE classes before report drafting.

## demo-pyml Addendum

For serialization-format targets:

- Review helper and CLI flows that call the safe loader on behalf of users. They
  can remove the review step even when the core API is hardened.
- Validate against the latest public release, not only `main`. For demo-pyml on
  2026-05-15, the bounty baseline was `v0.13.0`, while `main` was `0.15.dev0`.
- Separate security smell from submission-grade impact. `demo-pyml update` auto-trusts
  `get_untrusted_types()` and can import an untrusted local module, but without
  a default-importable gadget or archive-only code execution it remains a
  hardening issue rather than a Huntr-ready RCE.
- Check these duplicate CVEs before PoC work: `CVE-2024-37065`,
  `CVE-2025-54412`, `CVE-2025-54413`, and `CVE-2025-54886`.

## Open Query

No blocking query. The main decision for future BB work is whether we optimize for quick triage across many targets or deeper fuzzing on one target. For this bounty style, the better default is quick novelty triage first, then deep fuzzing only after a low-duplicate surface is identified.
