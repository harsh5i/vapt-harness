"""auth_chain_audit probe (Phase 5 Move 5 - scaffold).

Walks a Python codebase looking for route handlers (Flask, FastAPI, Django)
and reports which ones lack a recognized authorization decorator or call.
Output is high-recall, low-precision by design: an LLM auditor or reviewer
filters down.

Currently scaffolded:
- recognizes `@app.route`, `@blueprint.route`, `@router.get/post/...`,
  `@api_view` decorators.
- recognizes likely-authz markers: decorator names containing `login_required`,
  `require_auth`, `permission`, `roles_required`, `is_authenticated` calls.

Out of scope for this pass:
- cross-file role/permission graph
- Django middleware classification
- decorator-stack composition (any-of vs all-of)

These are tracked as follow-up work. The scaffold proves the same widened
probe contract that `patch_variant_hunter` uses works for a second probe
family.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any

from probes.base import Probe, ProbeContext, ProbeResult


ROUTE_DECORATOR_HINTS = ("route", "get", "post", "put", "delete", "patch", "api_view", "endpoint")
AUTHZ_DECORATOR_HINTS = (
    "login_required", "require_auth", "requires_auth", "permission_required",
    "roles_required", "authenticated", "auth_required", "login_required_user",
)
AUTHZ_CALL_HINTS = (
    "is_authenticated", "is_authorized", "has_permission", "check_permission",
    "ensure_authenticated", "verify_token", "verify_jwt",
)


def _decorator_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for dec in getattr(node, "decorator_list", []):
        names.append(_unparse_short(dec))
    return names


def _unparse_short(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _unparse_short(node.func)
    if isinstance(node, ast.Attribute):
        prefix = _unparse_short(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


def _is_route_handler(decorators: list[str]) -> bool:
    return any(any(h in d.split(".")[-1].lower() for h in ROUTE_DECORATOR_HINTS) for d in decorators if d)


def _has_authz_decorator(decorators: list[str]) -> bool:
    joined = " ".join(decorators).lower()
    return any(h in joined for h in AUTHZ_DECORATOR_HINTS)


def _calls_authz(body: list[ast.stmt]) -> bool:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call):
            tail = _unparse_short(node.func).split(".")[-1].lower()
            if any(h in tail for h in AUTHZ_CALL_HINTS):
                return True
    return False


def _scan_file(path: Path, repo_root: Path) -> list[dict[str, Any]]:
    try:
        source = path.read_text(errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError):
        return []
    rel = str(path.relative_to(repo_root))
    out: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = _decorator_names(node)
        if not _is_route_handler(decorators):
            continue
        if _has_authz_decorator(decorators) or _calls_authz(node.body):
            continue
        out.append({
            "file": rel,
            "line": node.lineno,
            "bug_class": "missing_authz_route",
            "hypothesis": (
                f"route handler `{node.name}` has decorators {decorators} but no recognized "
                "authz decorator or in-body authz call; verify whether this is intentional"
            ),
            "snippet": "",
        })
    return out


class AuthChainAudit(Probe):
    name = "auth_chain_audit"
    vuln_class = "source_audit"
    description = (
        "Source-reading probe scaffold: lists route handlers lacking a recognized "
        "authz decorator or call. High recall; reviewer filters."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from source import index as index_mod
        target = ctx.target or {}
        local_path = target.get("local_path")
        if not local_path:
            return ProbeResult({"name": self.name, "error": "scaffold requires local_path", "finding_count": 0, "findings": []})
        repo_path = Path(local_path)
        idx = index_mod.index_tree(repo_path, max_files=ctx.knobs.get("max_files"))
        findings: list[dict[str, Any]] = []
        for rel in idx["languages"].get("python", []):
            findings.extend(_scan_file(repo_path / rel, repo_path))
        return ProbeResult({
            "name": self.name,
            "repo_path": str(repo_path),
            "python_files": len(idx["languages"].get("python", [])),
            "finding_count": len(findings),
            "findings": findings,
        })
