"""Target profile lookup: enumerate engagement target YAMLs and resolve a
single target by its declared id.

The engagement tree is the operator's truth: `vapt/engagements/*/targets/*.yaml`.
A target profile carries `id`, `source_path`, scope/ROE, and OSV metadata. The
lookup helpers here are the only sanctioned way for the rest of the harness to
find a profile by id — both the path-by-stem fast path and the id-field
fallback are preserved.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_io import load_yaml
from core import ROOT


def _target_profile_paths() -> list[Path]:
    return sorted((ROOT / "vapt" / "engagements").glob("*/targets/*.yaml"))


def _load_target_profile(target_id: str) -> tuple[Path, dict[str, Any]] | tuple[None, dict[str, Any]]:
    for path in sorted((ROOT / "vapt" / "engagements").glob(f"*/targets/{target_id}.yaml")):
        if path.exists():
            return path, load_yaml(path) or {}
    for path in _target_profile_paths():
        target = load_yaml(path) or {}
        if str(target.get("id") or "") == target_id:
            return path, target
    return None, {}
