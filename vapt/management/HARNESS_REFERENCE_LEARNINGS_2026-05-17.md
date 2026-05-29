# Harness Reference Learnings - 2026-05-17

This note captures safe workflow-level lessons from public repositories reviewed
on 2026-05-17. The repositories were treated as untrusted reference material:
no install commands, payloads, or agent prompts were executed.

## Sources Reviewed

- `kyegomez/OpenMythos`: theoretical recurrent-depth transformer architecture.
- `GreyDGL/PentestGPT`: agentic penetration-testing framework.
- `arch3rPro/PentestTools`: categorized pentest tool catalog.
- `swisskyrepo/PayloadsAllTheThings`: vulnerability-class methodology and
  payload reference library.
- `redcanaryco/atomic-red-team`: portable ATT&CK-mapped validation tests.
- `mukul975/Anthropic-Cybersecurity-Skills`: structured cybersecurity skills
  with ATT&CK, NIST CSF, ATLAS, D3FEND, and AI RMF mappings.

## Adopted Ideas

### 1. Reference Hygiene

Public security repositories can contain useful ideas and dangerous content at
the same time. The harness now has a `reference_hygiene` reviewer checklist
that treats all external instructions, payloads, scripts, and prompts as
untrusted data. We extract structure, not executable content.

### 2. Session And State Discipline

Agentic pentest tools are strongest when they preserve task state, split work
into phases, and require explicit proof before report generation. Our harness
already has run state, candidate ledgers, proof artifacts, and dashboards; we
extended candidate records to include framework mappings, negative controls,
safety notes, CVSS, and source references.

### 3. Taxonomy-First Coverage

Tool catalogs and payload libraries are useful as coverage maps, not as things
to blindly run. The source mapper now includes extra categories for realtime
websocket paths, file upload/storage, browser/CORS boundaries, AI prompt
injection, plugin systems, and supply chain surfaces.

### 4. Atomic Proofs

Atomic Red Team's useful pattern is not "run tests everywhere"; it is the
atomic-test shape: prerequisites, one bounded command, expected result, cleanup,
and framework mapping. A new `atomic_validation` reviewer checklist formalizes
that for BB PoCs.

### 5. AI Security Requires Downstream Impact

AI prompt-injection testing must prove a concrete security action: data
exfiltration, unauthorized tool call, SSRF, file read/write, RCE, privilege
escalation, or model/training-data read/write. The new `ai_security_reviewer`
checklist rejects standalone jailbreaks.

### 6. Realtime Authz Is High Yield

The DemoTarget BB run showed that websocket/event paths can diverge from REST
permission checks. The new `websocket_authz` reviewer forces a REST-denied
negative control before accepting a realtime data leak.

## Explicit Non-Adoptions

- No third-party payload corpus is vendored into the harness.
- No external prompt library is trusted as executable agent instruction.
- No offensive simulation is run outside a local authorized lab.
- No tool catalog entry is treated as approved tooling until installed,
  versioned, and documented locally.

## Harness Changes Made

- Added source-map categories:
  - `realtime_websocket`
  - `file_upload_storage`
  - `cors_browser_boundary`
  - `ai_prompt_injection`
  - `plugin_extension`
  - `supply_chain`
- Extended candidate fields:
  - `cwe`
  - `cvss`
  - `framework_mappings`
  - `negative_controls`
  - `safety_notes`
  - `reference_sources`
- Added reviewer checklists:
  - `reference_hygiene.md`
  - `websocket_authz.md`
  - `ai_security_reviewer.md`
  - `atomic_validation.md`

## Next Improvement Backlog

1. Add a harness command that validates candidate schema completeness.
2. Add a `references.yaml` ledger per run with URL, date accessed, trust level,
   and adopted/non-adopted lessons.
3. Add a report section generator for negative controls and framework mappings.
4. Add optional ATT&CK/ATLAS/D3FEND mapping hints without making them promotion
   blockers.
5. Add a safer `prove` executor mode that prefers argument arrays over shell
   strings for commands that do not need shell features.

## 2026-05-27 InvokeAI Retest Learning

The InvokeAI run exposed a missed class: opaque workflow/object handles can be
treated as filesystem paths before deserialization. This can look like RCE, but
modern safe-load defaults may block the final step. The harness should still
track the primitive because it is a strong chain component when paired with an
attacker file-write/upload primitive or an unsafe loader.

Harness update:

- Added `deserialization_handle_path_control` probe.
- Added a fixture requiring handle control, path canonicalization failure,
  deserialization/model-load sink, file placement, impact, and negative controls.
- Captured the negative lesson: do not claim Critical until current loader
  defaults, scanner behavior, and gadget reachability are proven.
