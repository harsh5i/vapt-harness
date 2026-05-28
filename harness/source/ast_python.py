"""Python AST walker - bug class hypothesis surfacer.

Walks Python files and surfaces patterns that match known dangerous-bug
classes. This is the prerequisite for `patch_variant_hunter` and other
source-reading probes.

Bug classes covered in this pass:

- `cmd_injection_shell_true`:
    subprocess.run/Popen/check_output with shell=True AND a non-literal
    first argument.
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
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


UNTRUSTED_VAR_HINTS = {
    "request", "req", "args", "params", "payload", "body", "data",
    "input", "user_input", "form", "query", "kwargs", "json_body",
}


def _is_untrusted_name(node: ast.AST) -> bool:
    """Best-effort: does this expression reference a likely-untrusted variable?"""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id.lower() in UNTRUSTED_VAR_HINTS:
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
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            full = _full_name(node.func)
            tail = full.split(".")[-1] if full else ""
            for cls, hyp in _classify_call(full, tail, node, source):
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


def _classify_call(full: str, tail: str, node: ast.Call, source: str) -> list[tuple[str, str]]:
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

    # open with concatenated path including untrusted hint
    if (full == "open" or tail == "open") and args and _is_untrusted_name(args[0]) and not _is_literal_string(args[0]):
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
