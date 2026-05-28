"""File-level index over an acquired source tree.

Lightweight: walk filesystem, classify by extension, return per-language
file lists. AST work is deferred to language-specific modules
(`ast_python.py`, etc).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "ruby": {".rb"},
    "php": {".php"},
    "c": {".c", ".h"},
    "cpp": {".cc", ".cpp", ".hpp", ".cxx"},
}


SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "dist", "build", "target", ".cache",
}


def index_tree(repo_path: Path, *, max_files: int | None = None) -> dict[str, Any]:
    languages: dict[str, list[str]] = {lang: [] for lang in LANGUAGE_EXTENSIONS}
    total_files = 0
    skipped = 0
    for path in repo_path.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        matched = False
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                languages[lang].append(str(path.relative_to(repo_path)))
                matched = True
                break
        if matched:
            total_files += 1
        else:
            skipped += 1
        if max_files is not None and total_files >= max_files:
            break
    return {
        "repo_path": str(repo_path),
        "languages": {k: v for k, v in languages.items() if v},
        "total_indexed": total_files,
        "skipped_other": skipped,
    }
