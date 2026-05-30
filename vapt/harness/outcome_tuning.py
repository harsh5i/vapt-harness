"""Outcome-driven tuning: fold terminal submission outcomes and triage verdicts
into per-weakness/module/target score adjustments.

Honesty property this layer enforces: synthetic seed rows are excluded by
default and only move weights when include_synthetic is explicitly set.
Depends only on the leaf layers (core, atomic_io, validators) — no run state.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from atomic_io import read_jsonl
from core import HARNESS_VERSION, TRIAGE_VERDICTS, rel, step_outcomes_path, submissions_path
from validators import submission_positive


def _stat_bucket() -> dict[str, Any]:
    return {
        "total": 0,
        "terminal": 0,
        "positive": 0,
        "duplicates": 0,
        "negative": 0,
        "payout_total": 0.0,
        "payout_count": 0,
    }


def _add_outcome(bucket: dict[str, Any], row: dict[str, Any]) -> None:
    final = str(row.get("final_status") or "").lower()
    bucket["total"] += 1
    if final:
        bucket["terminal"] += 1
    if submission_positive(final):
        bucket["positive"] += 1
    elif final:
        bucket["negative"] += 1
    if final == "duplicate":
        bucket["duplicates"] += 1
    if row.get("payout_value") is not None:
        bucket["payout_total"] += float(row.get("payout_value") or 0)
        bucket["payout_count"] += 1


def _finalize_outcome_bucket(bucket: dict[str, Any]) -> dict[str, Any]:
    terminal = bucket["terminal"] or 1
    acceptance_rate = bucket["positive"] / terminal
    duplicate_rate = bucket["duplicates"] / terminal
    avg_payout = bucket["payout_total"] / (bucket["payout_count"] or 1)
    score_adjustment = round((acceptance_rate * 30) - (duplicate_rate * 18) + min(avg_payout / 500, 12), 2)
    if bucket["terminal"] < 2:
        score_adjustment = round(score_adjustment * 0.5, 2)
    return {
        **bucket,
        "acceptance_rate": round(acceptance_rate, 3),
        "duplicate_rate": round(duplicate_rate, 3),
        "average_payout": round(avg_payout, 2),
        "score_adjustment": score_adjustment,
    }


def _triage_tally(step_rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    tally: dict[str, dict[str, int]] = {}
    for row in step_rows:
        verdict = str(row.get("triage_verdict") or "")
        weakness = str(row.get("weakness") or "")
        if verdict not in TRIAGE_VERDICTS or not weakness:
            continue
        bucket = tally.setdefault(
            weakness, {"needs_proof": 0, "defended": 0, "false_positive": 0, "total": 0}
        )
        bucket[verdict] += 1
        bucket["total"] += 1
    return tally


def _triage_score_adjustment(bucket: dict[str, int]) -> float:
    # false_positive is the strongest negative signal (this weakness class
    # produced noise); defended is milder; needs_proof is a mild positive.
    raw = (
        bucket.get("needs_proof", 0) * 0.75
        + bucket.get("defended", 0) * -1.0
        + bucket.get("false_positive", 0) * -2.0
    )
    if bucket.get("total", 0) < 2:
        raw *= 0.5
    return round(max(-10.0, min(5.0, raw)), 2)


def outcome_tuning(
    rows: list[dict[str, Any]],
    include_synthetic: bool = False,
    step_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if step_rows is None:
        step_rows = read_jsonl(step_outcomes_path()) if step_outcomes_path().exists() else []
    modules: dict[str, dict[str, Any]] = {}
    evidence: dict[str, dict[str, Any]] = {}
    weaknesses: dict[str, dict[str, Any]] = {}
    targets: dict[str, dict[str, Any]] = {}
    eligible: list[dict[str, Any]] = []
    synthetic_count = 0
    for row in rows:
        if not row.get("final_status"):
            continue
        if row.get("synthetic"):
            synthetic_count += 1
            if not include_synthetic:
                continue
        eligible.append(row)
        for collection, key in (
            (modules, str(row.get("campaign_module") or "")),
            (evidence, str(row.get("evidence_kind") or "")),
            (weaknesses, str(row.get("cwe") or row.get("weakness") or "")),
            (targets, str(row.get("target_id") or "")),
        ):
            if not key:
                continue
            _add_outcome(collection.setdefault(key, _stat_bucket()), row)

    # Fold triage verdicts (Phase C) into weakness_adjustments: a weakness class
    # that keeps producing false_positive/defended verdicts gets scored down even
    # before any submission outcome exists for it.
    triage = _triage_tally(step_rows)
    weakness_adjustments: dict[str, Any] = {}
    for key in sorted(set(weaknesses) | set(triage)):
        bucket = _finalize_outcome_bucket(weaknesses.get(key, _stat_bucket()))
        tb = triage.get(key)
        if tb:
            adj = _triage_score_adjustment(tb)
            bucket["triage"] = tb
            bucket["triage_score_adjustment"] = adj
            bucket["score_adjustment"] = round(bucket["score_adjustment"] + adj, 2)
        weakness_adjustments[key] = bucket

    return {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "source": rel(submissions_path()),
        "triage_source": rel(step_outcomes_path()),
        "terminal_count": len(eligible),
        "triage_verdict_count": sum(b["total"] for b in triage.values()),
        "synthetic_excluded": synthetic_count if not include_synthetic else 0,
        "synthetic_included": synthetic_count if include_synthetic else 0,
        "module_adjustments": {key: _finalize_outcome_bucket(value) for key, value in sorted(modules.items())},
        "evidence_kind_adjustments": {key: _finalize_outcome_bucket(value) for key, value in sorted(evidence.items())},
        "weakness_adjustments": weakness_adjustments,
        "target_adjustments": {key: _finalize_outcome_bucket(value) for key, value in sorted(targets.items())},
    }
