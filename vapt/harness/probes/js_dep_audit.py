"""JS dependency CVE matcher probe.

Walks `ctx.target.local_path` for ``package-lock.json`` and ``yarn.lock``
files, normalises every (name, version) pair, and cross-references the
local OSV cache (offline-safe; shared with `gates/osv.py`). Emits one
finding per (package, version) that the cache lists as vulnerable.

Cross-reference: ``knowledge/case_studies/portswigger_top10_2024.md``
(inherited client-side CVEs from outdated JS dependencies).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Probe, ProbeContext, ProbeResult


def _load_module():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source.js_deps import LockfileParser, DependencyAuditor  # noqa: WPS433
    return LockfileParser, DependencyAuditor


def _default_osv_cache() -> Path:
    return Path(__file__).resolve().parents[1] / "cache" / "osv.sqlite"


class JsDepAuditProbe(Probe):
    name = "js_dep_audit"
    vuln_class = "vulnerable_dependency"
    description = (
        "Lockfile-based JS dependency audit. Parses package-lock.json + "
        "yarn.lock, matches against the local OSV cache, emits one finding "
        "per CVE'd (package, version)."
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
        osv_cache_path = Path(
            knobs.get("osv_cache_path") or _default_osv_cache()
        )

        LockfileParser, DependencyAuditor = _load_module()
        deps = LockfileParser().discover(root)
        findings = DependencyAuditor(osv_cache_path=osv_cache_path).match(deps)
        return ProbeResult({
            "name": self.name,
            "candidate_id": ctx.candidate.get("id") if ctx.candidate else None,
            "deps_scanned": len(deps),
            "finding_count": len(findings),
            "findings": findings,
        })
