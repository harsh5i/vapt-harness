"""Promotion + workflow gates: the invariants that stop a candidate from
advancing without the evidence each state requires.

Depends only on the leaf layers (core, atomic_io, validators) plus the stdlib.
Holds the promotion required-field set, the blocking-novelty set, the
campaign/queue runtime-evidence checks, and the per-state workflow ordering.
"""
from __future__ import annotations

import contextlib
from typing import Any

from atomic_io import load_yaml, read_json
from core import run_path
from validators import cvss3_base_score, exact_affected_version, substantive, validate_cwe


PROMOTION_REQUIRED_FIELDS = [
    "attacker_control",
    "entrypoint",
    "trust_boundary",
    "sink",
    "impact",
    "latest_affected",
]


PROMOTION_BLOCKING_NOVELTY = {"unchecked", "known-duplicate", "duplicate", "dedup-incomplete"}


def dedup_checked(cand: dict[str, Any]) -> bool:
    dedup = cand.get("dedup") if isinstance(cand.get("dedup"), dict) else {}
    return bool(dedup.get("checked_at")) and cand.get("novelty") not in {"", "unchecked", None}


def workflow_blockers(cand: dict[str, Any], target_status: str) -> list[str]:
    blockers = []
    if target_status in {"deduped", "promoted", "proved", "root_cause_recorded", "variant_searched", "patch_diffed", "report_ready", "submitted"}:
        if not dedup_checked(cand):
            blockers.append("dedup_not_checked")
    if target_status in {"promoted", "proved", "root_cause_recorded", "variant_searched", "patch_diffed", "report_ready", "submitted"}:
        ok, gate_blockers = promotion_findings(cand)
        if not ok:
            blockers.extend(f"gate:{item}" for item in gate_blockers)
    if target_status in {"proved", "root_cause_recorded", "variant_searched", "patch_diffed", "report_ready", "submitted"}:
        if cand.get("proof") != "passed":
            blockers.append("proof_not_passed")
    if target_status in {"root_cause_recorded", "variant_searched", "patch_diffed", "report_ready", "submitted"}:
        if not substantive(cand.get("root_cause")):
            blockers.append("root_cause_missing")
    if target_status in {"variant_searched", "patch_diffed", "report_ready", "submitted"}:
        if not substantive(cand.get("variant_analysis")):
            blockers.append("variant_analysis_missing")
    if target_status in {"patch_diffed", "report_ready", "submitted"}:
        if not substantive(cand.get("patch_diff")):
            blockers.append("patch_diff_missing")
    if target_status in {"report_ready", "submitted"}:
        if not substantive(cand.get("negative_controls")):
            blockers.append("negative_controls_missing")
        if str(cand.get("exploitability", "")).strip().upper().startswith(("L0", "L1", "L2")):
            blockers.append("exploitability_below_L3")
    return sorted(set(blockers))


def promotion_findings(cand: dict[str, Any]) -> tuple[bool, list[str]]:
    missing = []
    for field in PROMOTION_REQUIRED_FIELDS:
        if not substantive(cand.get(field)):
            missing.append(field)
    if not dedup_checked(cand):
        missing.append("dedup_not_checked")
    if cand.get("novelty") in PROMOTION_BLOCKING_NOVELTY:
        missing.append("novelty_not_duplicate_or_unchecked")
    latest_affected = cand.get("latest_affected", "")
    if str(latest_affected).lower() not in {"yes", "true", "affected"} and not exact_affected_version(latest_affected):
        missing.append("latest_release_not_confirmed")
    if not validate_cwe(str(cand.get("cwe", ""))):
        missing.append("invalid_cwe")
    score, err = cvss3_base_score(str(cand.get("cvss", "")))
    if score is None:
        missing.append(f"invalid_cvss:{err}")
    campaign_ok, campaign_blockers, _warnings = campaign_evidence_findings(cand)
    if not campaign_ok:
        missing.extend(campaign_blockers)
    queue_ok, queue_blockers, _queue_warnings = queue_evidence_findings(cand)
    if not queue_ok:
        missing.extend(queue_blockers)
    return not missing, missing


def candidate_requires_queue_gate(cand: dict[str, Any]) -> bool:
    evidence_kind = str(cand.get("evidence_kind") or "").strip()
    if "queue" in evidence_kind:
        return True
    if any(cand.get(key) for key in ("queue_id", "queue_entry")):
        return True
    queue_evidence = cand.get("queue_evidence")
    return isinstance(queue_evidence, dict) and bool(queue_evidence)


def queue_evidence_findings(cand: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    if not candidate_requires_queue_gate(cand):
        return True, [], []
    blockers = []
    warnings = []
    evidence = cand.get("queue_evidence") if isinstance(cand.get("queue_evidence"), dict) else {}
    queue_id = str(cand.get("queue_id") or evidence.get("queue_id") or "")
    queue_entry_raw = str(cand.get("queue_entry") or evidence.get("queue_entry") or "")
    if not queue_id:
        blockers.append("queue:id_missing")
    if not queue_entry_raw:
        blockers.append("queue:entry_missing")
    queue_entry_path_raw = run_path(queue_entry_raw) if queue_entry_raw else None
    entry = {}
    if queue_entry_path_raw and not queue_entry_path_raw.exists():
        blockers.append("queue:entry_artifact_missing")
    elif queue_entry_path_raw:
        with contextlib.suppress(Exception):
            entry = load_yaml(queue_entry_path_raw) or {}
        if not entry:
            blockers.append("queue:entry_artifact_invalid")
    if entry:
        if queue_id and str(entry.get("queue_id") or "") != queue_id:
            blockers.append("queue:id_entry_mismatch")
        status = str(entry.get("status") or "")
        if status != "converted":
            blockers.append(f"queue:not_converted:{status or 'unknown'}")
        if entry.get("candidate_id") and entry.get("candidate_id") != cand.get("id"):
            blockers.append("queue:candidate_id_mismatch")
        if not entry.get("candidate_id"):
            warnings.append("queue:entry_missing_candidate_id")
    if evidence.get("created_from_queue") is not True:
        warnings.append("queue:evidence_not_created_by_helper")
    return not blockers, sorted(set(blockers)), sorted(set(warnings))


def candidate_requires_campaign_gate(cand: dict[str, Any]) -> bool:
    evidence_kind = str(cand.get("evidence_kind") or "").strip()
    if evidence_kind in {"runtime_campaign", "campaign", "adapter_campaign"}:
        return True
    if any(cand.get(key) for key in ("campaign_run", "campaign_gate", "campaign_module")):
        return True
    campaign_evidence = cand.get("campaign_evidence")
    return isinstance(campaign_evidence, dict) and bool(campaign_evidence)


def campaign_evidence_findings(cand: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    if not candidate_requires_campaign_gate(cand):
        return True, [], []
    blockers = []
    warnings = []
    evidence = cand.get("campaign_evidence") if isinstance(cand.get("campaign_evidence"), dict) else {}
    campaign_start_raw = evidence.get("campaign_start")
    campaign_run_raw = cand.get("campaign_run") or evidence.get("campaign_run")
    campaign_gate_raw = cand.get("campaign_gate") or evidence.get("campaign_gate")
    campaign_module = str(cand.get("campaign_module") or evidence.get("campaign_module") or "")
    if not campaign_start_raw and evidence.get("created_in_campaign"):
        blockers.append("campaign:start_missing")
    if not campaign_run_raw:
        blockers.append("campaign:run_missing")
    if not campaign_gate_raw:
        blockers.append("campaign:gate_missing")
    if not campaign_module:
        blockers.append("campaign:module_missing")

    campaign_start_path = run_path(str(campaign_start_raw)) if campaign_start_raw else None
    campaign_run_path = run_path(str(campaign_run_raw)) if campaign_run_raw else None
    campaign_gate_path = run_path(str(campaign_gate_raw)) if campaign_gate_raw else None
    campaign_run = {}
    campaign_gate = {}
    if campaign_start_path and not campaign_start_path.exists():
        blockers.append("campaign:start_artifact_missing")
    elif campaign_start_path:
        with contextlib.suppress(Exception):
            campaign_start = read_json(campaign_start_path, {})
        if not campaign_start:
            blockers.append("campaign:start_artifact_invalid")
    if campaign_run_path and not campaign_run_path.exists():
        blockers.append("campaign:run_artifact_missing")
    elif campaign_run_path:
        with contextlib.suppress(Exception):
            campaign_run = read_json(campaign_run_path, {})
        if not campaign_run:
            blockers.append("campaign:run_artifact_invalid")
    if campaign_gate_path and not campaign_gate_path.exists():
        blockers.append("campaign:gate_artifact_missing")
    elif campaign_gate_path:
        with contextlib.suppress(Exception):
            campaign_gate = read_json(campaign_gate_path, {})
        if not campaign_gate:
            blockers.append("campaign:gate_artifact_invalid")
        elif campaign_gate.get("passed") is not True:
            blockers.append("campaign:gate_not_passed")

    if campaign_run and campaign_module:
        modules = campaign_run.get("modules") or []
        matching = [
            module
            for module in modules
            if campaign_module in {str(module.get("module_id") or ""), str(module.get("local_name") or "")}
        ]
        if not matching:
            blockers.append("campaign:module_not_in_campaign_run")
        elif not any(module.get("status") == "pass" for module in matching):
            blockers.append("campaign:module_not_passed")
    if campaign_run and campaign_gate:
        run_dir = str(campaign_run.get("out_dir") or "")
        gate_dir = str(campaign_gate.get("campaign_dir") or "")
        if run_dir and gate_dir and run_dir != gate_dir:
            blockers.append("campaign:gate_does_not_match_run_dir")
    if evidence.get("gate_passed") is False:
        blockers.append("campaign:linked_gate_failed")
    if evidence.get("gate_passed") is True and campaign_gate and campaign_gate.get("passed") is not True:
        blockers.append("campaign:linked_gate_state_stale")
    if not evidence.get("linked_at"):
        warnings.append("campaign:evidence_not_linked_by_helper")
    return not blockers, sorted(set(blockers)), sorted(set(warnings))
