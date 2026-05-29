# Mythos Substrate Phase 3 Foundation - 2026-05-18

Status: foundation implemented, later completed by the Phase 3 probe, tooling,
tool-ingest, and acceptance-gate increments. See
`MYTHOS_SUBSTRATE_PHASE3_COMPLETION_2026-05-18.md`.

## Delivered

- Probe framework:
  - `vapt/harness/probes/base.py`
  - `ProbeContext`
  - `Probe`
  - structured JSON evidence emission
- Starter probes:
  - `websocket_authz_drift`
  - `idor_diff`
  - `serialization_rce`
  - `ssrf_outbound`
  - `parser_canonicalization`
  - `prompt_injection_to_tool`
  - `rag_poisoning_durability`
  - `model_card_local_file_read`
- Probe commands:
  - `probes`
  - `probes-test`
  - `refine`
  - `scaffold-poc`
  - `new-probe`
- Captive probe regression fixture:
  - `vapt/harness/tests/fixtures/probe_candidates.yaml`
  - `vapt/harness/tests/results/probe_smoke_<stamp>.json`
- Tool/sandbox commands:
  - `sandbox-exec`
  - `tool-gap-add`
  - `tool-gaps`
  - `scan-semgrep`
  - `scan-headers`

## Safety Behavior

- `sandbox-exec` requires Docker or Podman.
- Default sandbox policy is no network egress.
- If Docker/Podman is missing, the command refuses and writes a policy artifact.
- There is no raw-shell fallback.

## Smoke Checks

- `python -m py_compile vapt/harness/harness.py vapt/harness/probes/*.py`: passed.
- `probes`: listed all starter probes.
- `probes-test`: passed all captive fixture candidates.
- `refine` on DemoTarget `MM-CAND-001`: selected `websocket_authz_drift` and
  wrote refine/evidence artifacts.
- `scaffold-poc websocket_authz demo-target`: wrote a runnable placeholder.
- `scaffold-poc idor_diff demo-target`: wrote and executed
  `vapt/pocs/demo-target/2026-05-18/poc_idor_diff.py`.
- `sandbox-exec` without Docker/Podman: refused safely and wrote policy JSON.
- `scan-semgrep --help`: parsed successfully.
- `tool-gap-add` / `tool-gaps`: smoke-tested, then fake gap corpus entry was
  removed to avoid polluting target selection.

## Caveats

- Probes are validation/refinement probes, not full exploit generators.
- Semgrep wrapper requires Semgrep installed in PATH.
- Header scan uses bounded `curl`; it should only be used against authorized
  targets.
- Full autonomous `refine` field-updating remains future model-integration work.
