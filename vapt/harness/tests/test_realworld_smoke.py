"""Real-world smoke tests for the source-reading walker.

Clones small, well-known OSS Python projects to a temp dir and asserts the
walker scales to real codebases without crashing and produces coherent
candidate findings. Skipped by default because each test pulls a few MB
over the network; opt in with `VAPT_REALWORLD=1`.

Expected acceptance (recorded against the working tree on 2026-06-01):

- bottle (single-file framework, 30 files, ~4.5K LOC main file):
    3 findings -- 2 pickle.loads on signed cookies, 1 open(cfile) on a
    config path.

- flask (web framework, 83 files, ~18K LOC):
    1 finding -- open() in src/flask/testing.py:235 (testing helper).

- werkzeug (WSGI utilities, 138 files, ~36K LOC):
    13 findings, including src/werkzeug/utils.py:490 -- the send_file()
    open(path) that has historically been a traversal CVE source.

These targets are the source-acquisition + AST walker acceptance evidence
referenced from STATUS.md.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parents[1]
if str(HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_DIR))

from source.ast_python import scan_files  # noqa: E402


REALWORLD = pytest.mark.skipif(
    os.environ.get("VAPT_REALWORLD") != "1",
    reason="set VAPT_REALWORLD=1 to opt into network-dependent real-target tests",
)


def _shallow_clone(url: str, dest: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(
        ["git", "clone", "--depth=1", url, str(dest)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return dest


def _python_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


@REALWORLD
def test_bottle_walker_finds_signed_cookie_pickle(tmp_path: Path) -> None:
    repo = _shallow_clone("https://github.com/bottlepy/bottle.git", tmp_path / "bottle")
    files = _python_files(repo)
    assert len(files) > 10, "bottle should have more than 10 .py files"
    findings = scan_files(files, repo_root=repo)
    assert not any(f["bug_class"] == "parse_error" for f in findings), (
        f"walker crashed on a file: {[f for f in findings if f['bug_class'] == 'parse_error']}"
    )
    pickles = [f for f in findings if f["bug_class"] == "unsafe_deserialization"]
    assert len(pickles) >= 2, f"expected >=2 pickle findings on bottle, got {pickles}"
    assert all("bottle.py" in f["file"] for f in pickles), pickles


@REALWORLD
def test_flask_walker_scales_without_crashes(tmp_path: Path) -> None:
    repo = _shallow_clone("https://github.com/pallets/flask.git", tmp_path / "flask")
    files = _python_files(repo)
    assert len(files) > 50, "flask should have more than 50 .py files"
    findings = scan_files(files, repo_root=repo)
    assert not any(f["bug_class"] == "parse_error" for f in findings), (
        f"walker crashed on a file: {[f for f in findings if f['bug_class'] == 'parse_error']}"
    )


@REALWORLD
def test_werkzeug_walker_surfaces_send_file_open(tmp_path: Path) -> None:
    repo = _shallow_clone("https://github.com/pallets/werkzeug.git", tmp_path / "werkzeug")
    files = _python_files(repo)
    assert len(files) > 50, "werkzeug should have more than 50 .py files"
    findings = scan_files(files, repo_root=repo)
    assert not any(f["bug_class"] == "parse_error" for f in findings), (
        f"walker crashed on a file: {[f for f in findings if f['bug_class'] == 'parse_error']}"
    )
    # The historically CVE'd send_file open(path, "rb") should be surfaced.
    send_file_hits = [
        f for f in findings
        if "werkzeug/utils.py" in f["file"]
        and f["bug_class"] == "path_traversal_unguarded_join"
    ]
    assert send_file_hits, (
        f"expected werkzeug.utils.send_file's open(path) to be flagged, got {findings}"
    )
