"""Header-trust audit probe.

Walks Ruby / Python / JavaScript / TypeScript source under
`ctx.target.local_path` and emits findings where a spoofable HTTP
header is read. Each finding carries a severity hint derived from
case-study evidence (HIGH for proven framework bypasses, MEDIUM for
spoofable IP/proto/method overrides).

Cross-reference: ``knowledge/case_studies/nextjs_middleware_bypass.md``
(x-middleware-subrequest), ``knowledge/case_studies/proxylogon_proxyshell.md``
(internal-routing headers), ``knowledge/case_studies/capital_one_aws_imds.md``
(SSRF via header-derived host).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Probe, ProbeContext, ProbeResult


def _load_auditor():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source.header_trust import HeaderTrustAuditor  # noqa: WPS433
    return HeaderTrustAuditor


class HeaderTrustProbe(Probe):
    name = "header_trust"
    vuln_class = "header_trust"
    description = (
        "Static scanner over Ruby/Python/JS/TS source. Flags reads of "
        "spoofable HTTP headers (proxy IP/proto/method overrides, "
        "internal-contract headers, framework-bypass headers)."
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

        auditor_cls = _load_auditor()
        findings = auditor_cls().walk(root, max_files=max_files)
        return ProbeResult({
            "name": self.name,
            "candidate_id": ctx.candidate.get("id") if ctx.candidate else None,
            "finding_count": len(findings),
            "findings": findings,
        })
