"""patch_variant_hunter probe (Phase 5 Move 5).

Given a target whose `target` dict carries `{repo, commit}` or
`{local_path}`, acquire the source (Move 5 substrate), index it, walk
the Python AST (`ast_python`) and Ruby source (`ast_ruby`), and emit
per-finding candidates of shape:

    {file, line, bug_class, hypothesis, snippet, source_target}

Probe contract widening (vs URL-based probes):

- `ctx.target` may carry `local_path` (no clone needed) OR
  `repo_url`+`commit`.
- `ctx.knobs.bug_classes` is an optional allowlist (subset of
  ast_python._classify_call output). Default = all.
- `ctx.knobs.max_files` caps walked files for soak control.

The probe does NOT decide whether a finding is exploitable; it surfaces
high-recall hypotheses for an LLM auditor or human reviewer to confirm.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from probes.base import Probe, ProbeContext, ProbeResult


def _load_source_modules():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source import acquire, index, ast_python, ast_ruby
    return acquire, index, ast_python, ast_ruby


class PatchVariantHunter(Probe):
    name = "patch_variant_hunter"
    vuln_class = "source_audit"
    description = (
        "Source-reading probe: walks Python and Ruby files in the target repo and "
        "emits bug-class hypothesis candidates for operator/LLM review."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        acquire_mod, index_mod, ast_python_mod, ast_ruby_mod = _load_source_modules()
        target = ctx.target or {}
        local_path = target.get("local_path") or target.get("source_local_path")
        repo_url = target.get("repo_url") or target.get("source_repo_url")
        commit = target.get("commit") or target.get("source_commit")
        root = Path(__file__).resolve().parents[3]
        if local_path:
            descriptor = {"repo_url": str(local_path), "commit": commit or "local", "path": str(local_path), "mode": "local"}
        elif repo_url:
            descriptor = acquire_mod.acquire(root=root, repo_url=repo_url, commit=commit)
        else:
            return ProbeResult({
                "name": self.name,
                "error": "target must carry local_path or repo_url",
                "finding_count": 0,
                "findings": [],
            })

        repo_path = Path(descriptor["path"])
        max_files = ctx.knobs.get("max_files")
        idx = index_mod.index_tree(repo_path, max_files=max_files)
        python_files = [repo_path / p for p in idx["languages"].get("python", [])]
        ruby_files = [repo_path / p for p in idx["languages"].get("ruby", [])]
        allow_classes: set[str] | None = None
        if ctx.knobs.get("bug_classes"):
            allow_classes = {str(x) for x in ctx.knobs["bug_classes"]}
        findings = ast_python_mod.scan_files(python_files, repo_root=repo_path, max_files=max_files)
        findings += ast_ruby_mod.scan_files(ruby_files, repo_root=repo_path, max_files=max_files)
        if allow_classes is not None:
            findings = [f for f in findings if f["bug_class"] in allow_classes]
        for f in findings:
            f["source_target"] = {
                "repo": descriptor.get("repo_url"),
                "commit": descriptor.get("commit"),
                "mode": descriptor.get("mode"),
            }
        return ProbeResult({
            "name": self.name,
            "source_descriptor": descriptor,
            "index": {"total_indexed": idx["total_indexed"], "languages": list(idx["languages"].keys())},
            "python_file_count": len(python_files),
            "ruby_file_count": len(ruby_files),
            "file_count": len(python_files) + len(ruby_files),
            "bug_classes_filter": sorted(allow_classes) if allow_classes else None,
            "finding_count": len(findings),
            "findings": findings,
        })
