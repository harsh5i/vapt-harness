"""Campaign context primitives: locate the campaign root from a run dir,
infer the campaign dir from an artifact path, load the campaign-module catalog.

A campaign is the per-target lifecycle root that owns a tree of run dirs and
the canonical `campaign_start.json` marker. `find_campaign_context` walks
up from a run dir until it sees that marker, so every CLI handler can resolve
the active campaign without the operator passing it explicitly.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from atomic_io import load_yaml, read_json
from core import ROOT, rel, run_path


def campaign_module_catalog_path() -> Path:
    return ROOT / "vapt" / "harness" / "config" / "campaign_modules.yaml"


def load_campaign_modules() -> list[dict[str, Any]]:
    data = load_yaml(campaign_module_catalog_path()) or {}
    modules = data.get("modules") or []
    if not isinstance(modules, list):
        raise SystemExit(f"invalid campaign module catalog: {rel(campaign_module_catalog_path())}")
    return modules


def find_campaign_context(run_dir: Path, explicit_campaign_dir: str | None = None) -> dict[str, Any]:
    roots = []
    if explicit_campaign_dir:
        roots.append(run_path(explicit_campaign_dir))
    current = run_dir.resolve()
    roots.extend([current, *current.parents])
    seen = set()
    for root in roots:
        root = root.resolve()
        if root in seen:
            continue
        seen.add(root)
        start_path = root / "campaign_start.json"
        if not start_path.exists():
            continue
        start = read_json(start_path, {})
        if not start:
            continue
        return {
            "campaign_dir": rel(root),
            "campaign_start": rel(start_path),
            "target_id": start.get("target_id") or "",
            "campaign_run": rel(root / "run" / "campaign_run.json") if (root / "run" / "campaign_run.json").exists() else "",
            "campaign_gate": rel(root / "run" / "campaign_gate.json") if (root / "run" / "campaign_gate.json").exists() else "",
            "detected_at": dt.datetime.now().isoformat(timespec="seconds"),
        }
    return {}


def infer_campaign_dir_from_artifact(raw_path: str | None) -> str:
    if not raw_path:
        return ""
    path = run_path(raw_path)
    parent = path.parent
    if parent.name == "run":
        return rel(parent.parent)
    return rel(parent)
