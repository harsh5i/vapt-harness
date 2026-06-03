"""Tarball-vs-git supply-chain diff probe.

Compares two directory trees (or a tarball archive and a directory)
and emits a finding per differing path. Requires both paths via
`ctx.knobs.tarball_root` and `ctx.knobs.git_root` (the probe does
NOT fetch tarballs over the network; that is the operator's step).

Cross-reference: ``knowledge/case_studies/xz_utils_supply_chain.md``
(the canonical example: malicious m4 macros shipped only in the
release tarball, never in the git tag).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Probe, ProbeContext, ProbeResult


def _load_differ():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source.supply_chain_diff import SupplyChainDiffer  # noqa: WPS433
    return SupplyChainDiffer


class SupplyChainDiffProbe(Probe):
    name = "supply_chain_diff"
    vuln_class = "supply_chain"
    description = (
        "Diffs a release tarball against the corresponding git tag; "
        "emits one finding per file that exists only in the tarball, "
        "differs in content, or exists only in git."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        knobs: dict[str, Any] = ctx.knobs or {}
        tarball_root = knobs.get("tarball_root")
        git_root = knobs.get("git_root")
        if not tarball_root or not git_root:
            return ProbeResult({
                "name": self.name,
                "error": "knobs.tarball_root and knobs.git_root are required",
                "finding_count": 0,
                "findings": [],
            })
        tar_path = Path(tarball_root)
        git_path = Path(git_root)
        if not tar_path.exists() or not git_path.exists():
            return ProbeResult({
                "name": self.name,
                "error": f"path missing: tarball={tar_path.exists()} git={git_path.exists()}",
                "finding_count": 0,
                "findings": [],
            })
        differ_cls = _load_differ()
        findings = differ_cls().diff(tarball_root=tar_path, git_root=git_path)
        return ProbeResult({
            "name": self.name,
            "candidate_id": ctx.candidate.get("id") if ctx.candidate else None,
            "finding_count": len(findings),
            "findings": findings,
        })
