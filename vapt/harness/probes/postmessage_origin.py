"""postMessage origin-check probe.

Active static scanner. Walks JS source under ``ctx.target.local_path``,
locates ``addEventListener("message", ...)`` and ``onmessage = ...``
registrations, and emits one finding per handler whose origin check is
missing or weak.

Two finding kinds:
  - ``no_origin_check``    -- handler body never references ``.origin``.
  - ``weak_origin_check``  -- handler uses indexOf / includes / endsWith
                              / startsWith / regex on ``event.origin``.

Cross-reference: ``knowledge/case_studies/postmessage_origin.md``
(Frans Rosén). Strong-equality checks (``=== / !==``) are filtered out
as well-formed.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Probe, ProbeContext, ProbeResult


def _load_walker():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source.postmessage import PostMessageWalker  # noqa: WPS433
    return PostMessageWalker


class PostMessageOriginProbe(Probe):
    name = "postmessage_origin"
    vuln_class = "postmessage_origin"
    description = (
        "Static scanner over JS/TS source. Flags postMessage handlers "
        "without strict-equality origin checks (missing or weak)."
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

        walker_cls = _load_walker()
        findings = walker_cls().walk(root, max_files=max_files)
        return ProbeResult({
            "name": self.name,
            "candidate_id": ctx.candidate.get("id") if ctx.candidate else None,
            "finding_count": len(findings),
            "findings": findings,
        })
