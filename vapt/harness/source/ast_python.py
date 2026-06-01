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

Taint flow:

- Intra-procedural: a function-local set of names assigned from an
  untrusted-shaped expression. A subsequent sink call that references
  such a name is flagged. Handles Assign / AnnAssign / AugAssign and
  tuple-unpack.

- Inter-procedural (same file only): a fixed-point pass propagates taint
  across calls inside one file. If caller passes a tainted argument into
  a callee's parameter (positional by index or keyword by name), that
  parameter becomes a taint source in the callee. If a callee returns a
  tainted expression, the call-site expression is treated as tainted
  for assignment propagation.

Inter-procedural propagation is bounded: same file only, no attribute
or method resolution, no aliasing through containers, max 6 fixed-point
iterations.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


UNTRUSTED_VAR_HINTS = {
    "request", "req", "args", "params", "payload", "body", "data",
    "input", "user_input", "form", "query", "kwargs", "json_body",
}


def _attr_path(node: ast.AST) -> str | None:
    """Dotted path of a pure Name/Attribute chain, e.g. `self.path` or
    `self.req.body`. Returns None if any segment is a Call, Subscript, etc.
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_untrusted_name(node: ast.AST, tainted: set[str] | None = None) -> bool:
    """Does this expression reference a likely-untrusted variable?

    Checks both the static hint vocabulary (`request`, `args`, ...) and the
    optional `tainted` set (locals previously assigned from untrusted-shaped
    sources, plus dotted paths like `self.X` for attribute taint).
    With `tainted=None` the walker behaves exactly like the original
    single-statement check.
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
            if tainted is not None:
                path = _attr_path(sub)
                if path is not None and path in tainted:
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
    """Yield target identifiers from an Assign / AugAssign / AnnAssign LHS.

    Returns:
    - plain Name targets as their identifier
    - Attribute targets rooted at `self` as their dotted path (e.g.
      `self.path`, `self.req.body`)
    - tuple / list unpack elements (Names only)
    """
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
        elif isinstance(t, ast.Attribute):
            path = _attr_path(t)
            if path is not None and path.startswith("self."):
                names.append(path)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
    return names


def _initial_seed(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Params whose names match the hint vocabulary are taint sources."""
    seed: set[str] = set()
    for arg in func.args.args + func.args.posonlyargs + func.args.kwonlyargs:
        if arg.arg.lower() in UNTRUSTED_VAR_HINTS:
            seed.add(arg.arg)
    return seed


def _resolved_callee(
    call: ast.Call, funcs_by_name: dict[str, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Same-file resolution: `name(...)` -> local FunctionDef of that name.

    Attribute and computed calls are intentionally not resolved here.
    """
    if isinstance(call.func, ast.Name):
        callee = funcs_by_name.get(call.func.id)
        if isinstance(callee, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return callee
    return None


def _resolve_imported_callee(
    call: ast.Call,
    fc: "FileCtx",
    global_funcs: dict[str, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Cross-file resolution via the caller file's import maps.

    - `Name(local)` where `local` is in func_aliases -> the imported
      FunctionDef (handles `from mod import f` and `from mod import f as g`).
    - `Attribute(value=Name(mod_alias), attr=name)` where `mod_alias` is in
      module_aliases -> resolves `<mod>.<name>` against the global table
      (handles `import mod` and `import mod as alias`).

    Returns None if the call cannot be resolved to an in-package
    FunctionDef. Stdlib / third-party imports therefore never resolve.
    """
    if isinstance(call.func, ast.Name):
        fn = fc.func_aliases.get(call.func.id)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return fn
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
    ):
        mod_alias = call.func.value.id
        mod = fc.module_aliases.get(mod_alias)
        if mod is not None:
            qualified = f"{mod}.{call.func.attr}"
            fn = global_funcs.get(qualified)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return fn
    return None


def _resolve_call_in_pkg(
    call: ast.Call,
    caller: ast.FunctionDef | ast.AsyncFunctionDef,
    fc: "FileCtx",
    global_funcs: dict[str, ast.AST],
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef | None, int]:
    """Resolve a callsite to a callee + positional-offset (1 for self.method).

    Tries in order: same-file free function -> cross-file via import ->
    same-class self.method dispatch. Returns (None, 0) if unresolved.
    """
    callee = _resolved_callee(call, fc.funcs_by_name)
    if callee is not None:
        return callee, 0
    callee = _resolve_imported_callee(call, fc, global_funcs)
    if callee is not None:
        return callee, 0
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "self"
    ):
        cls = fc.class_of_func.get(id(caller))
        if cls is not None:
            method = fc.class_methods[id(cls)].get(call.func.attr)
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return method, 1
    return None, 0


def _expr_calls_tainted_returner(
    node: ast.AST,
    fc: "FileCtx",
    global_funcs: dict[str, ast.AST],
    tainted_returns: set[int],
) -> bool:
    """Does this expression contain a Call to a function whose return is
    known to be tainted? Resolves same-file and cross-file (via the
    caller file's import maps).
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            callee = _resolved_callee(sub, fc.funcs_by_name) or _resolve_imported_callee(
                sub, fc, global_funcs
            )
            if callee is not None and id(callee) in tainted_returns:
                return True
    return False


def _function_taint(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    seed: set[str],
    fc: "FileCtx",
    global_funcs: dict[str, ast.AST],
    tainted_returns: set[int],
) -> set[str]:
    """Walk a function body; return locals assigned from an untrusted-shaped
    source, seeded with the supplied param set (which includes hint-vocab
    matches plus any inter-procedural taint folded in by callers).

    Recognises an assignment as taint-introducing if RHS contains:
    - a Name in UNTRUSTED_VAR_HINTS or in the running tainted set, OR
    - a Call to a function whose return is known to be tainted (same-file
      or cross-file via the caller file's import maps).
    """
    tainted: set[str] = set(seed)
    for stmt in ast.walk(func):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            rhs = stmt.value
            if rhs is None:
                continue
            if (
                _is_untrusted_name(rhs, tainted)
                or _expr_calls_tainted_returner(rhs, fc, global_funcs, tainted_returns)
            ):
                for name in _assign_targets(stmt):
                    tainted.add(name)
        elif isinstance(stmt, ast.AugAssign):
            if (
                _is_untrusted_name(stmt.value, tainted)
                or _expr_calls_tainted_returner(stmt.value, fc, global_funcs, tainted_returns)
            ):
                for name in _assign_targets(stmt):
                    tainted.add(name)
    return tainted


def _positional_param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """In positional order: posonly + regular. Excludes *args and kwonly."""
    return [a.arg for a in func.args.posonlyargs + func.args.args]


def _all_param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {a.arg for a in func.args.posonlyargs + func.args.args + func.args.kwonlyargs}


def _is_method(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    params = fn.args.posonlyargs + fn.args.args
    return bool(params) and params[0].arg == "self"


def _module_name_from_path(path: Path, repo_root: Path | None) -> str:
    """Translate a .py path under repo_root into a dotted module name.

    `src/db.py` under root `/.../seeded_bugs_repo` -> `src.db`.
    `src/__init__.py` -> `src`.
    Falls back to the bare stem if repo_root is None or path is outside it.
    """
    if repo_root is None:
        return path.stem
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return path.stem
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else path.stem


class FileCtx:
    """Per-file analysis context: parse tree, free functions, class table,
    and the import alias maps used for cross-file callee resolution.
    """

    __slots__ = (
        "path",
        "source",
        "tree",
        "rel_path",
        "module_name",
        "funcs_by_name",
        "all_funcs",
        "classes",
        "class_of_func",
        "class_methods",
        "func_aliases",
        "module_aliases",
    )

    def __init__(
        self,
        path: Path,
        source: str,
        tree: ast.AST,
        rel_path: str,
        module_name: str,
    ) -> None:
        self.path = path
        self.source = source
        self.tree = tree
        self.rel_path = rel_path
        self.module_name = module_name
        self.funcs_by_name: dict[str, ast.AST] = {}
        self.all_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.classes: list[ast.ClassDef] = []
        self.class_of_func: dict[int, ast.ClassDef] = {}
        self.class_methods: dict[int, dict[str, ast.AST]] = {}
        # Filled by _resolve_imports after the global symbol table exists.
        self.func_aliases: dict[str, ast.AST] = {}
        self.module_aliases: dict[str, str] = {}


def _build_file_ctx(
    path: Path,
    source: str,
    tree: ast.AST,
    repo_root: Path | None,
) -> FileCtx:
    rel_path = (
        str(path.relative_to(repo_root)) if repo_root is not None else str(path)
    )
    module_name = _module_name_from_path(path, repo_root)
    fc = FileCtx(path, source, tree, rel_path, module_name)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            fc.classes.append(node)
            methods: dict[str, ast.AST] = {}
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods[sub.name] = sub
                    fc.class_of_func[id(sub)] = node
            fc.class_methods[id(node)] = methods
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fc.all_funcs.append(node)
            if id(node) not in fc.class_of_func:
                # Only module-level free functions go in funcs_by_name so
                # bare `foo(...)` can't accidentally resolve to a class method.
                fc.funcs_by_name[node.name] = node
    return fc


def _resolve_relative_module(level: int, module: str | None, current_module: str) -> str | None:
    """Resolve `from .x import y` style imports to an absolute dotted path.

    `level=1` means one-dot (current package). `level=2` means parent
    package. Returns None if the resolution goes above the package root.
    """
    if level == 0:
        return module
    parts = current_module.split(".") if current_module else []
    # Drop the current module's own name, then `level - 1` further levels.
    if not parts:
        return None
    parts = parts[:-1]  # parent package
    extra = level - 1
    if extra > 0:
        if extra > len(parts):
            return None
        parts = parts[: len(parts) - extra]
    if module:
        parts.append(module)
    return ".".join(parts) if parts else (module or None)


def _resolve_imports(fc: FileCtx, global_funcs: dict[str, ast.AST]) -> None:
    """Populate `fc.func_aliases` and `fc.module_aliases` from `import`
    statements anywhere in the tree (top-level or nested).
    """
    for node in ast.walk(fc.tree):
        if isinstance(node, ast.ImportFrom):
            mod = _resolve_relative_module(node.level, node.module, fc.module_name)
            if mod is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                qualified = f"{mod}.{alias.name}"
                fn = global_funcs.get(qualified)
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fc.func_aliases[local] = fn
                else:
                    # `from pkg import submodule` -> register as a module
                    # alias so `submodule.foo(...)` calls resolve.
                    fc.module_aliases[local] = qualified
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    fc.module_aliases[alias.asname] = alias.name
                else:
                    # `import pkg.sub` makes `pkg` the bound name, but
                    # `pkg.sub.foo(...)` only resolves if we keep the full
                    # dotted path under its own key.
                    top = alias.name.split(".")[0]
                    fc.module_aliases.setdefault(top, top)
                    fc.module_aliases[alias.name] = alias.name


def _analyze_package(
    file_ctxs: list[FileCtx], *, max_iters: int = 6
) -> dict[int, set[str]]:
    """Fixed-point inter-procedural taint across all files in `file_ctxs`.

    Returns a map func-id -> tainted local names + dotted attribute paths
    (e.g. `self.path`). Propagation covers:

    - free-function calls within one file: `helper(x)` -> `helper`'s param
    - cross-file calls via import maps: `from m import f; f(x)` or
      `import m; m.f(x)` -> param taint on the imported FunctionDef
    - self.method dispatch within one class: `self.foo(x)` resolves to
      the enclosing class's method; positional shifts by 1 to skip self
    - tainted-return: any assignment whose RHS calls a function known to
      return tainted becomes tainted on the LHS
    - self.attr taint: `self.X = tainted` in any method of class C marks
      `self.X` tainted across every method of C (flow-insensitive)

    Cross-package resolution is intentionally narrow: only functions
    defined in the file_ctxs set are reachable. Stdlib / third-party
    imports never resolve, so taint cannot leak through them.

    Bounded by max_iters to terminate on mutual recursion.
    """
    # Step 1: build the global symbol table from module-level free functions
    # in every file. Methods are excluded so `bare_name(...)` calls can't
    # accidentally resolve to a class method in another module.
    global_funcs: dict[str, ast.AST] = {}
    for fc in file_ctxs:
        for name, fn in fc.funcs_by_name.items():
            global_funcs[f"{fc.module_name}.{name}"] = fn

    # Step 2: resolve each file's imports against the global table.
    for fc in file_ctxs:
        _resolve_imports(fc, global_funcs)

    # Step 3: aggregate the per-file all_funcs into one list plus a
    # reverse index from any function id back to its file context.
    all_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    file_of_func: dict[int, FileCtx] = {}
    for fc in file_ctxs:
        for fn in fc.all_funcs:
            all_funcs.append(fn)
            file_of_func[id(fn)] = fc

    # Step 4: per-class self-attribute taint, keyed by ClassDef id (unique
    # across files because each ClassDef is a distinct Python object).
    class_self_taint: dict[int, set[str]] = {}
    for fc in file_ctxs:
        for cls in fc.classes:
            class_self_taint[id(cls)] = set()

    def _seed_with_class(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        base = _initial_seed(fn)
        fc = file_of_func[id(fn)]
        cls = fc.class_of_func.get(id(fn))
        if cls is not None:
            base |= class_self_taint[id(cls)]
        return base

    seed: dict[int, set[str]] = {id(fn): _seed_with_class(fn) for fn in all_funcs}
    tainted_returns: set[int] = set()
    local_taint: dict[int, set[str]] = {
        id(fn): _function_taint(
            fn, seed[id(fn)], file_of_func[id(fn)], global_funcs, tainted_returns
        )
        for fn in all_funcs
    }

    for _ in range(max_iters):
        changed = False

        # Propagate taint across call edges (same-file free + cross-file
        # imported + same-class self.method).
        for caller in all_funcs:
            caller_fc = file_of_func[id(caller)]
            caller_taint = local_taint[id(caller)]
            for sub in ast.walk(caller):
                if not isinstance(sub, ast.Call):
                    continue
                callee, positional_offset = _resolve_call_in_pkg(
                    sub, caller, caller_fc, global_funcs
                )
                if callee is None:
                    continue
                positional = _positional_param_names(callee)
                all_params = _all_param_names(callee)
                for i, arg in enumerate(sub.args):
                    target_idx = i + positional_offset
                    if target_idx >= len(positional):
                        break
                    if (
                        _is_untrusted_name(arg, caller_taint)
                        or _expr_calls_tainted_returner(
                            arg, caller_fc, global_funcs, tainted_returns
                        )
                    ):
                        if positional[target_idx] not in seed[id(callee)]:
                            seed[id(callee)].add(positional[target_idx])
                            changed = True
                for kw in sub.keywords:
                    if kw.arg is None or kw.arg not in all_params:
                        continue
                    if (
                        _is_untrusted_name(kw.value, caller_taint)
                        or _expr_calls_tainted_returner(
                            kw.value, caller_fc, global_funcs, tainted_returns
                        )
                    ):
                        if kw.arg not in seed[id(callee)]:
                            seed[id(callee)].add(kw.arg)
                            changed = True

        # Recompute local taint with updated seeds + return-taint awareness.
        # Fold any newly-discovered class self-taint in by union so prior
        # arg-edge propagation is preserved.
        for fn in all_funcs:
            fc = file_of_func[id(fn)]
            cls = fc.class_of_func.get(id(fn))
            if cls is not None:
                new_seed = seed[id(fn)] | class_self_taint[id(cls)]
                if new_seed != seed[id(fn)]:
                    seed[id(fn)] = new_seed
                    changed = True
            new_t = _function_taint(
                fn, seed[id(fn)], fc, global_funcs, tainted_returns
            )
            if new_t != local_taint[id(fn)]:
                local_taint[id(fn)] = new_t
                changed = True

        # Lift `self.X` taint discovered in a method up to the class's
        # shared set so other methods inherit it on the next iteration.
        for fn in all_funcs:
            fc = file_of_func[id(fn)]
            cls = fc.class_of_func.get(id(fn))
            if cls is None:
                continue
            for entry in local_taint[id(fn)]:
                if entry.startswith("self.") and entry not in class_self_taint[id(cls)]:
                    class_self_taint[id(cls)].add(entry)
                    changed = True

        # Detect tainted returns.
        for fn in all_funcs:
            if id(fn) in tainted_returns:
                continue
            fc = file_of_func[id(fn)]
            fn_taint = local_taint[id(fn)]
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    if (
                        _is_untrusted_name(sub.value, fn_taint)
                        or _expr_calls_tainted_returner(
                            sub.value, fc, global_funcs, tainted_returns
                        )
                    ):
                        tainted_returns.add(id(fn))
                        changed = True
                        break

        if not changed:
            break

    return local_taint


def _parse_for_scan(
    path: Path, repo_root: Path | None
) -> tuple[FileCtx | None, dict[str, Any] | None]:
    """Parse a single file into a FileCtx, or return a parse_error finding."""
    try:
        source = path.read_text(errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError) as exc:
        return None, {
            "file": str(path),
            "line": 0,
            "bug_class": "parse_error",
            "hypothesis": f"file failed to parse: {exc}",
            "snippet": "",
        }
    return _build_file_ctx(path, source, tree, repo_root), None


def _classify_package(
    file_ctxs: list[FileCtx],
    func_taint: dict[int, set[str]],
) -> list[dict[str, Any]]:
    """Walk every Call in every file and emit findings using the final
    per-function taint sets produced by `_analyze_package`.
    """
    findings: list[dict[str, Any]] = []
    for fc in file_ctxs:
        parent: dict[int, ast.AST] = {}
        for node in ast.walk(fc.tree):
            for child in ast.iter_child_nodes(node):
                parent[id(child)] = node

        def _taint_for(call: ast.AST) -> set[str] | None:
            current = parent.get(id(call))
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return func_taint.get(id(current))
                current = parent.get(id(current))
            return None

        for node in ast.walk(fc.tree):
            if isinstance(node, ast.Call):
                full = _full_name(node.func)
                tail = full.split(".")[-1] if full else ""
                tainted = _taint_for(node)
                for cls, hyp in _classify_call(full, tail, node, fc.source, tainted):
                    findings.append(
                        {
                            "file": fc.rel_path,
                            "line": node.lineno,
                            "bug_class": cls,
                            "hypothesis": hyp,
                            "snippet": _snippet(fc.source, node.lineno),
                        }
                    )
    return findings


def scan_file(path: Path, *, repo_root: Path | None = None) -> list[dict[str, Any]]:
    """Single-file analysis. Equivalent to `scan_files([path], repo_root=...)`
    but tolerant of `repo_root=None` for ad-hoc one-shot use.
    """
    fc, err = _parse_for_scan(path, repo_root)
    if err is not None:
        return [err]
    func_taint = _analyze_package([fc])
    return _classify_package([fc], func_taint)


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


def scan_files(
    files: list[Path], *, repo_root: Path, max_files: int | None = None
) -> list[dict[str, Any]]:
    """Package-level analysis: parses every file first, builds the global
    symbol table and per-file import maps, then runs the inter-procedural
    taint fixed-point across the union of all functions.
    """
    selected = files if max_files is None else files[:max_files]
    file_ctxs: list[FileCtx] = []
    findings: list[dict[str, Any]] = []
    for path in selected:
        fc, err = _parse_for_scan(path, repo_root)
        if err is not None:
            findings.append(err)
        else:
            assert fc is not None
            file_ctxs.append(fc)
    if file_ctxs:
        func_taint = _analyze_package(file_ctxs)
        findings.extend(_classify_package(file_ctxs, func_taint))
    return findings
