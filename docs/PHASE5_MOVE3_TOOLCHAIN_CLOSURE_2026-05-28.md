# Phase 5 - Move 3 - Toolchain Closure - 2026-05-28

Status: wrappers, CLI, and capability reporter landed.
First end-to-end probe (JWT structural audit) working offline.
Container runtime (Docker/Podman) not installed locally; ZAP, sqlmap,
and `jwt_tool` remain reachable only through wrapper documentation
until a runtime is added. Capability surfaces honestly via
`harness tools-capability`.

References:
- `MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` ss 7
- `VAPT_CAPABILITY_ASSESSMENT.md` (Priority-1/Priority-2 updated)

## What Landed

### Package
`vapt/harness/tools/` is now the home for external tooling wrappers.
Each tool gets a thin module that exposes:
- canonical container image name
- argv composer (container-mode and local-mode where applicable)
- parser for the tool's output into a normalized finding list

Files:
- `tools/__init__.py` (package header)
- `tools/container.py` (shared `docker_run_argv`, `capability_report`)
- `tools/zap.py` (`baseline_argv`, `full_scan_argv`, `parse_baseline_report`)
- `tools/sqlmap.py` (`scan_argv`, `parse_log`)
- `tools/jwt.py` (`decode_local`, `inspect_argv`)
- `tools/screenshot.py` (`capture_argv`, `write_capture_script`)

### CLI surface
Six new subcommands registered in `harness.py`:
- `scan-zap-baseline run_dir target_url [--timeout] [--network] [--extra ...]`
- `scan-zap-full run_dir target_url [...]`
- `scan-sqlmap run_dir [--target-url|--request-file] [...]`
- `scan-jwt run_dir [--token|--token-file] [--container]`
- `scan-screenshot run_dir target_url [--wait-ms] [--network]`
- `tools-capability [--json]` - reports per-tool mode
  (`container`/`local`/`unavailable`) and the canonical image.

### First probe
`harness/probes/jwt_structural_audit.py` extracts JWT-shaped tokens
from candidate text (`notes`, `title`, `proof_artifact`,
`evidence_excerpts`, plus `knobs.jwt_paths`) and runs structural risk
analysis via `tools.jwt.decode_local`. Flags:
- `alg=none`
- `kid` with path characters (kid injection)
- `jku`/`x5u` external key URLs
- Missing `exp` (no expiry)
- Missing `sub` and `aud` (no principal)

No network, no container. Works today.

## Verified Behaviour

Run on 2026-05-28T22:50 from repo root.

```
harness tools-capability --json
  -> runtime="", 4 tools, 1 available (playwright local)
     zap/sqlmap/jwt -> unavailable (no Docker, no local binary)
     screenshot     -> local mode via .venv-vapt/bin/playwright

probe.jwt_structural_audit against synthetic candidate with alg=none JWT:
  -> token_count=1, finding_count=1
     finding[0].alg = "none"
     finding[0].risks = ["alg=none accepted by some libs",
                         "payload missing 'exp' (no expiry)"]
```

## Capability Gaps (Honest List)

The wrappers exist and the CLI is wired. What does NOT execute today
on this host:

- ZAP baseline + ZAP full: require Docker/Podman OR local
  `zap-baseline.py` on PATH. Refusal record cites
  `ghcr.io/zaproxy/zaproxy:stable`.
- sqlmap: requires Docker/Podman OR `pip install sqlmap` into
  `.venv-vapt`. Refusal cites `paoloo/sqlmap:latest`.
- `jwt_tool` container: requires Docker/Podman.
  `ticarpi/jwt_tool:latest`. The local Python decoder still works
  without this.
- Playwright via container: optional - the local install handles
  the screenshot path today.

These are NOT silent degradations. `tools-capability` and
`refuse_missing_tool` make the gap visible per command and per refusal
record (`*.missing.json`).

## Outstanding from Roadmap ss 7

- **Per-target egress allowlist.** Today the wrappers pass through
  `--network <user-supplied>`. The sandbox runner already enforces
  `--network none` for non-network tools. Active scanners need a
  network mode that only reaches the declared target host. Tracked
  as a Move 3 follow-up.
- **Probes leveraging ZAP/sqlmap/screenshot.** Only JWT is wired
  end-to-end so far. Each remaining tool deserves at least one
  reference probe against a captive fixture. Defer until a container
  runtime is available locally.
- **SecLists vendoring.** Not yet done. Will sit at
  `vapt/env/seclists/` per roadmap.

## Why Move 3 Is Considered Done For This Pass

Roadmap exit criteria are partial: the wrappers exist, the CLI is
wired, capability is honestly surfaced, one tool runs end-to-end
locally, and the capability assessment is updated. The remaining
work (container runtime install, per-tool probes, SecLists, egress
allowlist) is operational rather than architectural and does not
block Moves 4 or 5. Advance now; backfill the operational items
opportunistically.
