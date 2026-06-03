"""JS bundle analyzer probe.

Active static scanner. Consumes the target's JS source (or built bundles)
via `ctx.target.local_path` and emits high-recall hypothesis candidates:

    {file, line, kind, match, [secret_class]}

Three finding kinds: ``endpoint`` (root-relative /api/... paths),
``admin_route`` (admin/internal routes -- highest EV), ``secret``
(high-confidence credential patterns; placeholder and test-file
suppression built in).

This probe surfaces leads; it does not decide exploitability. An operator
or LLM auditor must confirm each finding via a live fetch, server-side
authz check, or git-blame.

Cross-reference: knowledge/case_studies/web_hackers_vs_auto.md -- JS
bundle URL enumeration was the auto-industry team's primary recon
technique.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Probe, ProbeContext, ProbeResult


def _load_analyzer():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source.js_bundle import JsBundleAnalyzer  # noqa: WPS433
    return JsBundleAnalyzer


class JsBundleAnalyzerProbe(Probe):
    name = "js_bundle_analyzer"
    vuln_class = "js_bundle_surface"
    description = (
        "Static scanner over JS/TS source. Surfaces /api endpoints, admin "
        "routes, and high-confidence secret patterns as hypothesis findings."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        target = ctx.target or {}
        local_path = target.get("local_path") or target.get("source_local_path")
        if not local_path:
            return ProbeResult({
                "name": self.name,
                "error": "target must carry local_path",
                "finding_count": 0,
                "findings": [],
            })

        root = Path(local_path)
        if not root.exists():
            return ProbeResult({
                "name": self.name,
                "error": f"local_path does not exist: {root}",
                "finding_count": 0,
                "findings": [],
            })

        knobs: dict[str, Any] = ctx.knobs or {}
        max_files = knobs.get("max_files")

        analyzer_cls = _load_analyzer()
        findings = analyzer_cls().walk(root, max_files=max_files)
        return ProbeResult({
            "name": self.name,
            "candidate_id": ctx.candidate.get("id") if ctx.candidate else None,
            "finding_count": len(findings),
            "findings": findings,
        })


# Backwards-compat alias for the legacy registry key (harness.py PROBE_REGISTRY).
JSBundleAnalyzerProbe = JsBundleAnalyzerProbe
