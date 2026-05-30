"""Candidate ledger primitives: the default-shape schema, normalization, the
single-file YAML store, and the locked update helper. Anything that touches
`candidates.yaml` lives here.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_io import candidate_ledger_lock, dump_yaml, load_yaml
from core import CURRENT_CANDIDATE_SCHEMA_VERSION


DEFAULT_CANDIDATE = {
    "id": "",
    "title": "",
    "status": "candidate",
    "surface": "",
    "weakness": "",
    "impact": "",
    "attacker_control": "",
    "entrypoint": "",
    "trust_boundary": "",
    "latest_affected": "unchecked",
    "sink": "",
    "triage_verdict": "",
    "novelty": "unchecked",
    "dedup": {"status": "unchecked", "matches": [], "checked_at": ""},
    "proof": "not_started",
    "cve": "N/A",
    "cwe": "",
    "cvss": "",
    "framework_mappings": {},
    "negative_controls": "",
    "safety_notes": "",
    "reference_sources": "",
    "root_cause": "",
    "variant_analysis": "",
    "patch_diff": "",
    "evidence_kind": "",
    "queue_id": "",
    "queue_entry": "",
    "queue_evidence": {},
    "campaign_run": "",
    "campaign_gate": "",
    "campaign_module": "",
    "campaign_evidence": {},
    "exploitability": "",
    "disclosure_quality": "",
    "created_at": "",
    "notes": "",
    "history": [],
}


def _normalize_candidate(cand: dict[str, Any]) -> dict[str, Any]:
    normalized = {**DEFAULT_CANDIDATE, **(cand or {})}
    normalized["schema_version"] = int(normalized.get("schema_version") or CURRENT_CANDIDATE_SCHEMA_VERSION)
    if not isinstance(normalized.get("history"), list):
        normalized["history"] = []
    if not isinstance(normalized.get("dedup"), dict):
        normalized["dedup"] = DEFAULT_CANDIDATE["dedup"].copy()
    if not isinstance(normalized.get("framework_mappings"), dict):
        normalized["framework_mappings"] = {}
    if not isinstance(normalized.get("campaign_evidence"), dict):
        normalized["campaign_evidence"] = {}
    if not isinstance(normalized.get("queue_evidence"), dict):
        normalized["queue_evidence"] = {}
    return normalized


def load_candidates(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "candidates.yaml"
    data = load_yaml(path) if path.exists() else {"candidates": []}
    data = data or {"candidates": []}
    data.setdefault("schema_version", CURRENT_CANDIDATE_SCHEMA_VERSION)
    data["candidates"] = [_normalize_candidate(cand) for cand in data.get("candidates", [])]
    return data


def save_candidates(run_dir: Path, data: dict[str, Any]) -> None:
    dump_yaml(data, run_dir / "candidates.yaml")


def next_candidate_id(data: dict[str, Any]) -> str:
    max_id = 0
    for cand in data.get("candidates", []):
        raw = str(cand.get("id", "CAND-000")).removeprefix("CAND-")
        try:
            max_id = max(max_id, int(raw))
        except ValueError:
            pass
    return f"CAND-{max_id + 1:03d}"


def find_candidate(data: dict[str, Any], cand_id: str) -> dict[str, Any]:
    for cand in data.get("candidates", []):
        if cand.get("id") == cand_id:
            return cand
    raise SystemExit(f"candidate not found: {cand_id}")


def update_candidate_locked(run_dir: Path, cand_id: str, updater) -> dict[str, Any]:
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, cand_id)
        updater(cand)
        save_candidates(run_dir, data)
        return cand
