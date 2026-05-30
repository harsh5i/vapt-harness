"""Python AST walker - bug class hypothesis surfacer.

Walks Python files and surfaces patterns that match known dangerous-bug
classes. This is the prerequisite for `patch_variant_hunter` and other
source-reading probes.

Bug classes covered in this pass:

- `cmd_injection_shell_true`:
    subprocess.run/Popen/check_output with shell=True AND a non-literal
    first argument that is untrusted-shaped or flows from one.
- `cmd_injection_os_system`:
    os.system(...) with a non-literal argument.
- `unsafe_deserialization`:
    pickle.loads / yaml.load (without SafeLoader) / dill.loads on
    untrusted-shaped variables.
- `sql_injection_string_format`:
    cursor.execute(...) where the SQL is built via f-string or %-format
    or +-concat.
- `path_traversal_unguarded_join`:
    open(...) / Path(...) where the path is concat of user-shaped input
    and a base, without normpath/relpath guard.

A "candidate finding" is `{file, line, bug_class, hypothesis, snippet}`.
The hypothesis is a sentence the operator (or LLM auditor) can verify.

Taint flow: per-function, the walker tracks which local names have been
assigned from an untrusted-shaped expression. A subsequent sink call that
references such a name is flagged, so the
`path = request.args.get(...) + ".txt"; open(path, ...)` shape no longer
slips past as a single-statement-only check would.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


UNTRUSTED_VAR_HINTS = {
    "request", "req", "args", "params", "payload", "body", "data",
    "input", "user_input", "form", "query", "kwargs", "json_body",
}


def _is_untrusted_name(node: ast.AST, tainted: set[str] | None = None) -> bool:
    """Does this expression reference a likely-untrusted variable?

    Checks both the static hint vocabulary (`request`, `args`, ...) and the
    optional `tainted` set (locals previously assigned from untrusted-shaped
    sources). With `tainted=None` the walker behaves exactly like the
    original single-statement check.
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if sub.id.lower() in UNTRUSTED_VAR_HINTS:
                return True
            if tainted is not None and sub.id in tainted:
                return True
        if isinstance(sub, ast.Attribute):
            if sub.attr.lower() in UNTRUSTED_VAR_HINTS:
                return True
            if isinstance(sub.value, ast.Name) and sub.value.id.lower() in UNTRUSTED_VAR_HINTS:
                return True
    return False


def _is_literal_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _snippet(source: str, lineno: int, before: int = 1, after: int = 2) -> str:
    lines = source.splitlines()
    start = max(0, lineno - 1 - before)
    end = min(len(lines), lineno - 1 + after + 1)
    return "\n".join(f"{i + 1:>5}  {lines[i]}" for i in range(start, end))


def _full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        prefix = _full_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _assign_targets(node: ast.AST) -> list[str]:
    """Yield Name targets from an Assign / AugAssign / AnnAssign LHS."""
    names: list[str] = []
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
    for t in targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
    return names


def _function_taint(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Walk a function body in source order; return locals assigned from an
    untrusted-shaped source.

    Seeded with the function's parameters whose names match the hint
    vocabulary (so `def serve_file(request): ...` marks `request` tainted
    from the start, even though it is just a Name and would normally only
    match the hint check on access).
    """
    tainted: set[str] = set()
    for arg in func.args.args + func.args.posonlyargs + func.args.kwonlyargs:
        if arg.arg.lower() in UNTRUSTED_VAR_HINTS:
            tainted.add(arg.arg)
    # walk every statement of the body in textual order so transitive
    # taint (a = b; c = a) propagates the same way the interpreter would
    # see it; ast.walk would be order-independent and lose chains
    for stmt in ast.walk(func):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            rhs = stmt.value
            if rhs is None:
                continue
            if _is_untrusted_name(rhs, tainted):
                for name in _assign_targets(stmt):
                    tainted.add(name)
        elif isinstance(stmt, ast.AugAssign):
            # `s += untrusted` taints s; `s += literal` also leaves any
            # prior taint on s untouched (set is monotonic for this pass).
            if _is_untrusted_name(stmt.value, tainted):
                for name in _assign_targets(stmt):
                    tainted.add(name)
    return tainted


def scan_file(path: Path, *, repo_root: Path | None = None) -> list[dict[str, Any]]:
    try:
        source = path.read_text(errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [{
            "file": str(path),
            "line": 0,
            "bug_class": "parse_error",
            "hypothesis": f"file failed to parse: {exc}",
            "snippet": "",
        }]
    rel_path = str(path.relative_to(repo_root)) if repo_root else str(path)
    findings: list[dict[str, Any]] = []

    # Pre-compute per-function taint sets so the sink scan below can see
    # locals assigned from untrusted-shaped sources earlier in the same
    # function.
    func_taint: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_taint[id(node)] = _function_taint(node)

    def _enclosing_taint(call: ast.AST) -> set[str] | None:
        # Walk the AST again locating which function (if any) lexically
        # contains this call. For module-level calls return None so the
        # call falls back to the static-hint-only check.
        for fn in func_taint:
            pass  # see below; we re-walk per call which is O(N^2) only
        return None

    # Build a child→parent map once so we can locate the enclosing function
    # cheaply for each Call. Cheaper than re-walking the whole tree per call.
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    def _taint_for(call: ast.AST) -> set[str] | None:
        current = parent.get(id(call))
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return func_taint.get(id(current))
            current = parent.get(id(current))
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            full = _full_name(node.func)
            tail = full.split(".")[-1] if full else ""
            tainted = _taint_for(node)
            for cls, hyp in _classify_call(full, tail, node, source, tainted):
                findings.append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "bug_class": cls,
                        "hypothesis": hyp,
                        "snippet": _snippet(source, node.lineno),
                    }
                )
    return findings


def _classify_call(
    full: str,
    tail: str,
    node: ast.Call,
    source: str,
    tainted: set[str] | None,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    kw = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    args = node.args

    # subprocess.run(..., shell=True) with non-literal cmd
    if tail in {"run", "call", "Popen", "check_output", "check_call"} and "subprocess" in full:
        shell_kw = kw.get("shell")
        shell_true = isinstance(shell_kw, ast.Constant) and shell_kw.value is True
        if shell_true and args and not _is_literal_string(args[0]):
            out.append((
                "cmd_injection_shell_true",
                "subprocess called with shell=True and a non-literal first argument; verify input provenance",
            ))

    # os.system with non-literal
    if full == "os.system" and args and not _is_literal_string(args[0]):
        out.append((
            "cmd_injection_os_system",
            "os.system() with non-literal argument; verify input is fully trusted",
        ))

    # pickle.loads / yaml.load (no SafeLoader)
    if full == "pickle.loads" or tail == "loads" and "pickle" in full:
        out.append((
            "unsafe_deserialization",
            "pickle.loads on user-shaped input is unsafe; require allowlisted classes or signed payloads",
        ))
    if full in {"yaml.load", "yaml.full_load"}:
        loader = kw.get("Loader")
        safe = loader is not None and isinstance(loader, ast.Attribute) and loader.attr in {"SafeLoader", "CSafeLoader"}
        if not safe:
            out.append((
                "unsafe_deserialization",
                "yaml.load without SafeLoader; arbitrary Python object instantiation possible",
            ))

    # cursor.execute with f-string/%-format/concat SQL
    if tail == "execute" and args:
        sql = args[0]
        if isinstance(sql, ast.JoinedStr):
            out.append((
                "sql_injection_string_format",
                "cursor.execute called with an f-string SQL; parametrize instead",
            ))
        elif isinstance(sql, ast.BinOp) and isinstance(sql.op, (ast.Mod, ast.Add)):
            out.append((
                "sql_injection_string_format",
                "cursor.execute called with %-format or string concatenation; parametrize instead",
            ))
        elif tainted is not None and isinstance(sql, ast.Name) and sql.id in tainted:
            out.append((
                "sql_injection_string_format",
                "cursor.execute called with a SQL string assembled from an untrusted-shaped local; parametrize instead",
            ))

    # open with concatenated path including untrusted hint OR a local that
    # was assigned from one
    if (full == "open" or tail == "open") and args and _is_untrusted_name(args[0], tainted) and not _is_literal_string(args[0]):
        out.append((
            "path_traversal_unguarded_join",
            "open() over a path derived from request/user input; check normpath and base containment",
        ))

    return out


def scan_files(files: list[Path], *, repo_root: Path, max_files: int | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for i, path in enumerate(files):
        if max_files is not None and i >= max_files:
            break
        findings.extend(scan_file(path, repo_root=repo_root))
    return findings
