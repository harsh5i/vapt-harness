"""Submission ledger primitives: per-program rollups and the
candidate→submission enrichment helpers. Anything that reads from
`submissions.jsonl` or fills in candidate metadata before a write lives here.

Depends only on the leaf layers (core, atomic_io, validators) plus the stdlib.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_io import load_yaml
from core import HARNESS_VERSION, outcome_tuning_path
from validators import submission_positive


def submission_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_program: dict[str, dict[str, Any]] = {}
    for row in rows:
        program = str(row.get("program") or "<unknown>")
        bucket = by_program.setdefault(
            program,
            {
                "total": 0,
                "terminal": 0,
                "positive": 0,
                "duplicates": 0,
                "payout_total": 0.0,
                "payout_count": 0,
                "days_to_final_total": 0,
                "days_to_final_count": 0,
            },
        )
        bucket["total"] += 1
        final = str(row.get("final_status") or "")
        if final:
            bucket["terminal"] += 1
        if submission_positive(final):
            bucket["positive"] += 1
        if final == "duplicate":
            bucket["duplicates"] += 1
        if row.get("payout_value") is not None:
            bucket["payout_total"] += float(row.get("payout_value") or 0)
            bucket["payout_count"] += 1
        if row.get("days_to_final") is not None:
            bucket["days_to_final_total"] += int(row.get("days_to_final") or 0)
            bucket["days_to_final_count"] += 1
    for bucket in by_program.values():
        total = bucket["total"] or 1
        terminal = bucket["terminal"] or 1
        bucket["acceptance_rate"] = round(bucket["positive"] / terminal, 3)
        bucket["duplicate_rate"] = round(bucket["duplicates"] / terminal, 3)
        bucket["average_value"] = round(bucket["payout_total"] / (bucket["payout_count"] or 1), 2)
        bucket["average_days_to_final"] = round(bucket["days_to_final_total"] / (bucket["days_to_final_count"] or 1), 2)
        bucket["open"] = total - bucket["terminal"]
    return {"programs": by_program, "total_submissions": len(rows)}


def candidate_outcome_metadata(target: dict[str, Any], cand: dict[str, Any]) -> dict[str, Any]:
    queue_evidence = cand.get("queue_evidence") if isinstance(cand.get("queue_evidence"), dict) else {}
    return {
        "target_id": target.get("id") or "",
        "target_category": target.get("category") or [],
        "language": target.get("language") or [],
        "weakness": cand.get("weakness") or "",
        "cwe": cand.get("cwe") or "",
        "surface": cand.get("surface") or "",
        "sink": cand.get("sink") or "",
        "campaign_module": cand.get("campaign_module") or "",
        "evidence_kind": cand.get("evidence_kind") or "",
        "queue_type": queue_evidence.get("queue_type") or "",
    }


def enrich_submission_entry(entry: dict[str, Any], target: dict[str, Any], cand: dict[str, Any]) -> dict[str, Any]:
    enriched = {**entry, **candidate_outcome_metadata(target, cand)}
    enriched.setdefault("harness_version", HARNESS_VERSION)
    return enriched


def load_outcome_tuning() -> dict[str, Any]:
    path = outcome_tuning_path()
    if not path.exists():
        return {}
    return load_yaml(path) or {}
