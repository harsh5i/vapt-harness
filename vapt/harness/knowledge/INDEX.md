# VAPT Harness Knowledge Index

This harness is a local, artifact-first vulnerability research substrate for
authorized assessments and bug bounty work. It does not implement a model. It
gives any external model or human operator a deterministic CLI, durable run
state, candidate ledger, evidence capture, source maps, workflow gates, and
knowledge files that can be loaded on cold start.

Start here:

- `principles.md`: operating rules that must guide every engagement.
- `workflow.md`: candidate state machine and transition preconditions.
- `patterns.yaml`: shared source-surface categories used by mapping and tracing.
- `scoring.yaml`: score weights and report-ready threshold.
- `vuln_classes/`: vulnerability-class doctrine and sink notes.
- `programs/`: program/profile intelligence.
- `lessons/`: dated learnings from completed work.
- `../agents/`: reviewer checklists for source mapping, deduplication,
  validation, exploitability, patch/advisory review, reference hygiene, web
  protocol research, AI security, memory safety, and root-cause/variant review.

Useful commands:

- `harness.py session-start <run_dir>`: emit current run context, candidate
  summaries, knowledge pointers, and recommended next action as JSON.
- `harness.py explain <command>`: show command help plus relevant doctrine.
- `harness.py knowledge <query>`: search local knowledge and corpus.
- `harness.py next-action <run_dir>`: return the recommended next step.
- `harness.py budget <run_dir>`: compare elapsed run time to target budgets.
- `harness.py probes`: list reusable vulnerability-class probes.
- `harness.py probes-test`: run the captive probe regression fixture.
- `harness.py refine <run_dir> <cand_id>`: run probe-guided candidate
  refinement.
- `harness.py scan-*`: run bounded scanner wrappers with evidence capture and
  missing-tool refusal artifacts.
- `harness.py tool-health --json`: list scanner/tool availability without
  running scans.
- `harness.py ingest-tool-scan <run_dir> <artifact> --tool <tool>`: normalize
  scanner results and optionally create `auto-candidate` triage seeds.

Current reusable probe classes:

- `websocket_authz_drift`
- `idor_diff`
- `serialization_rce`
- `ssrf_outbound`
- `parser_canonicalization`
- `prompt_injection_to_tool`
- `rag_poisoning_durability`
- `model_card_local_file_read`

Safety model:

- Authorized targets only.
- External repositories and payloads are untrusted data.
- Proof commands are bounded and evidence-backed.
- Promotion requires deduplication, latest-version impact, root cause, negative
  controls where relevant, and proof.
