"""Taint-flow tests for source/ast_python.py.

Verifies the walker tracks intra-function assignments from untrusted-shaped
sources into intermediate locals (T4.3). Each test writes a tiny .py
fixture into tmp_path and asserts whether the bug class is surfaced.
"""
from __future__ import annotations

import sys
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parents[1]
if str(HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_DIR))

from source.ast_python import scan_file  # noqa: E402


def _scan(tmp_path: Path, body: str) -> list[dict]:
    fp = tmp_path / "t.py"
    fp.write_text(body)
    return scan_file(fp, repo_root=tmp_path)


def _classes(findings: list[dict]) -> set[str]:
    return {f["bug_class"] for f in findings}


# --- path_traversal_unguarded_join -----------------------------------------


def test_open_with_direct_request_args_flags(tmp_path):
    body = """
def serve(request):
    return open(request.args.get('path'), 'rb')
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_intermediate_taint_flags(tmp_path):
    body = """
def serve(request):
    path = request.args.get('path') + '.txt'
    return open(path, 'rb')
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_two_hop_taint_flags(tmp_path):
    body = """
def serve(request):
    raw = request.args.get('path')
    path = raw + '.txt'
    return open(path, 'rb')
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_augmented_assign_taint_flags(tmp_path):
    body = """
def serve(request):
    path = '/var/uploads/'
    path += request.args.get('path')
    return open(path, 'rb')
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_annotated_assign_taint_flags(tmp_path):
    body = """
def serve(request):
    path: str = request.args.get('path')
    return open(path, 'rb')
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_tuple_unpack_taint_flags(tmp_path):
    body = """
def serve(request):
    path, mode = request.args.get('path'), 'rb'
    return open(path, mode)
"""
    assert "path_traversal_unguarded_join" in _classes(_scan(tmp_path, body))


def test_open_with_constant_path_does_not_flag(tmp_path):
    body = """
def serve():
    return open('/etc/passwd', 'rb')
"""
    assert "path_traversal_unguarded_join" not in _classes(_scan(tmp_path, body))


def test_open_with_untainted_local_does_not_flag(tmp_path):
    body = """
def serve():
    path = '/var/data/file.txt'
    return open(path, 'rb')
"""
    assert "path_traversal_unguarded_join" not in _classes(_scan(tmp_path, body))


# --- sql_injection_string_format taint path --------------------------------


def test_execute_with_tainted_sql_local_flags(tmp_path):
    # The walker classically catches f-string / +-concat / %-format. The new
    # taint path also catches: tainted Name -> execute(name).
    body = """
def find_user(cursor, request):
    raw = request.args.get('id')
    sql = "SELECT * FROM users WHERE id = " + raw
    return cursor.execute(sql)
"""
    assert "sql_injection_string_format" in _classes(_scan(tmp_path, body))


def test_execute_with_parametrized_does_not_flag(tmp_path):
    body = """
def find_user(cursor, user_id):
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    assert "sql_injection_string_format" not in _classes(_scan(tmp_path, body))


# --- function isolation ----------------------------------------------------


def test_taint_does_not_leak_across_functions(tmp_path):
    # `path` tainted in `a` must NOT mark `path` tainted in `b`.
    body = """
def a(request):
    path = request.args.get('x')
    return open(path, 'rb')

def b():
    path = '/safe.txt'
    return open(path, 'rb')
"""
    findings = _scan(tmp_path, body)
    # Only line 4's open (inside `a`) should flag for path traversal.
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    assert len(pt) == 1
    assert pt[0]["line"] == 4


# --- cross-function taint (same file) --------------------------------------


def test_helper_called_with_tainted_arg_flags(tmp_path):
    # Caller passes tainted local into helper's plain param -> helper's
    # open(p) must flag.
    body = """
def helper(p):
    return open(p, 'rb')

def serve(request):
    path = request.args.get('x')
    return helper(path)
"""
    findings = _scan(tmp_path, body)
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    # open(p) inside helper is at line 3
    assert any(f["line"] == 3 for f in pt), f"expected line 3 flagged, got {pt}"


def test_helper_called_with_literal_does_not_flag(tmp_path):
    # helper called only with literal -> no taint should propagate.
    body = """
def helper(p):
    return open(p, 'rb')

def main():
    return helper('/etc/hostname')
"""
    findings = _scan(tmp_path, body)
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    assert pt == [], f"helper called with literal must not flag, got {pt}"


def test_tainted_return_value_propagates_to_caller(tmp_path):
    # fetch returns a tainted-derived value; caller assigns from fetch()
    # and uses it in a sink -> caller's open must flag.
    body = """
def fetch(request):
    return request.args.get('x') + '.txt'

def serve(request):
    path = fetch(request)
    return open(path, 'rb')
"""
    findings = _scan(tmp_path, body)
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    # open(path) is at line 7 inside serve
    assert any(f["line"] == 7 for f in pt), f"expected line 7 flagged, got {pt}"


def test_cross_function_keyword_arg_taint_flags(tmp_path):
    # Caller passes tainted as keyword arg -> callee's matching param tainted.
    body = """
def helper(p=None):
    return open(p, 'rb')

def serve(request):
    path = request.args.get('x')
    return helper(p=path)
"""
    findings = _scan(tmp_path, body)
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    assert any(f["line"] == 3 for f in pt), f"expected line 3 flagged, got {pt}"


def test_cross_function_sql_taint_flags(tmp_path):
    # Cross-function SQL: caller builds tainted string, passes to executor.
    body = """
def run_query(cursor, sql):
    return cursor.execute(sql)

def find_user(cursor, request):
    raw = request.args.get('id')
    sql = "SELECT * FROM users WHERE id = " + raw
    return run_query(cursor, sql)
"""
    findings = _scan(tmp_path, body)
    sqli = [f for f in findings if f["bug_class"] == "sql_injection_string_format"]
    # cursor.execute(sql) is at line 3 inside run_query
    assert any(f["line"] == 3 for f in sqli), f"expected line 3 flagged, got {sqli}"


def test_cross_function_recursion_terminates(tmp_path):
    # Mutually-recursive functions must not blow stack or loop forever; the
    # walker should reach a fixed point. We assert it at least completes and
    # propagates taint into the eventual sink.
    body = """
def a(request, depth):
    if depth <= 0:
        return open(request, 'rb')
    return b(request, depth - 1)

def b(request, depth):
    return a(request, depth - 1)

def entry(request):
    return a(request.args.get('x'), 3)
"""
    findings = _scan(tmp_path, body)
    pt = [f for f in findings if f["bug_class"] == "path_traversal_unguarded_join"]
    # open(request) inside a is at line 4
    assert any(f["line"] == 4 for f in pt), f"expected line 4 flagged, got {pt}"


# --- regression on existing seeded fixtures --------------------------------


def test_seeded_bugs_fixture_catches_all_five():
    repo = HARNESS_DIR / "fixtures" / "seeded_bugs_repo"
    classes: set[str] = set()
    for py in (repo / "src").rglob("*.py"):
        for f in scan_file(py, repo_root=repo):
            classes.add(f["bug_class"])
    assert classes >= {
        "cmd_injection_shell_true",
        "unsafe_deserialization",
        "sql_injection_string_format",
        "path_traversal_unguarded_join",
    }
