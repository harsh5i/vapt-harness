"""Atomic file persistence + advisory file locks.

Extracted leaf layer of the harness: no dependencies on the rest of the
harness, only the stdlib. Every write goes through a temp file + os.replace so
a crash mid-write can never leave a half-written ledger. read_jsonl tolerates
blank/corrupt lines; read_json returns a caller-supplied default when missing.

The lock primitives auto-select between stdlib fcntl (Unix/macOS) and stdlib
msvcrt.locking (Windows). On Windows fcntl is unavailable so importing it at
module top would crash the harness on first import; the dispatch table below
keeps the same `file_lock(path)` / `candidate_ledger_lock(run_dir)` surface
on both platforms without any caller change.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


if sys.platform == "win32":  # pragma: no cover - Windows-only path
    import msvcrt

    def _lock_exclusive(fh) -> None:
        # Lock the first byte for the lifetime of the file handle; this is the
        # canonical msvcrt advisory-lock idiom and is enough for the harness's
        # one-writer / many-readers ledger pattern.
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)

    def _lock_release(fh) -> None:
        with contextlib.suppress(OSError):
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock_exclusive(fh) -> None:
        fcntl.flock(fh, fcntl.LOCK_EX)

    def _lock_release(fh) -> None:
        fcntl.flock(fh, fcntl.LOCK_UN)


@contextlib.contextmanager
def candidate_ledger_lock(run_dir: Path):
    lock_path = run_dir / "candidates.yaml.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as fh:
        _lock_exclusive(fh)
        try:
            yield
        finally:
            _lock_release(fh)


@contextlib.contextmanager
def file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as fh:
        _lock_exclusive(fh)
        try:
            yield
        finally:
            _lock_release(fh)


def _yaml():
    try:
        import yaml  # type: ignore

        return "pyyaml", yaml
    except Exception:
        try:
            from ruamel.yaml import YAML  # type: ignore

            yaml = YAML()
            yaml.default_flow_style = False
            return "ruamel", yaml
        except Exception as exc:
            raise RuntimeError(
                "YAML support is required. Install PyYAML or ruamel.yaml in the active "
                "environment."
            ) from exc


def load_yaml(path: Path) -> Any:
    kind, yaml = _yaml()
    with path.open("r", encoding="utf-8") as fh:
        if kind == "pyyaml":
            return yaml.safe_load(fh)
        return yaml.load(fh)


def dump_yaml(data: Any, path: Path) -> None:
    kind, yaml = _yaml()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        if kind == "pyyaml":
            yaml.safe_dump(data, fh, sort_keys=False)
        else:
            yaml.dump(data, fh)
    os.replace(tmp, path)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError):
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")
    os.replace(tmp, path)
