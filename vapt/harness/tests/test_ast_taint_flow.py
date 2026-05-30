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
