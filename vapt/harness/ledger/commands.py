"""CLI handlers for the ledger / outcome-tuning surface.

The corpus rebuilder, the submission append + update + synthetic seeder, the
outcome-record write path, the submission listing/stats commands, the
outcome-tune writer, and the read-only weights-show diagnostic all live here.

The handlers are still registered through cli.py via the harness module's
namespace, so harness.py re-imports each one. The `_h` lookup below is the
same dual sys.modules pattern cli.py uses: it lets these handlers reach back
into harness for the few helpers that have not been extracted yet
(`load_run`, the synthetic-row classifiers).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import sys
import uuid
from typing import Any

from atomic_io import (
    dump_yaml,
    file_lock,
    read_jsonl,
    write_jsonl,
    write_text,
)
from core import (
    HARNESS_VERSION,
    ROOT,
    _parse_time,
    candidate_corpus_path,
    outcome_tuning_path,
    rel,
    run_path,
    step_outcomes_path,
    submissions_path,
)
from ledger.candidates import (
    find_candidate,
    load_candidates,
    update_candidate_locked,
)
from ledger.submissions import (
    enrich_submission_entry,
    load_outcome_tuning,
    submission_stats,
)
from outcome_tuning import outcome_tuning
from validators import submission_terminal


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def cmd_corpus_rebuild(args: argparse.Namespace) -> None:
    out_dir = ROOT / "vapt" / "harness" / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "candidates.jsonl"
    rows = []
    runs_root = ROOT / "vapt" / "engagements"
    for path in sorted(runs_root.glob("*/runs/*/*/candidates.yaml")):
        run_dir = path.parent
        with contextlib.suppress(Exception):
            state, target = _h.load_run(run_dir)
            data = load_candidates(run_dir)
            for cand in data.get("candidates", []):
                rows.append(
                    {
                        "target_id": target.get("id"),
                        "run_dir": rel(run_dir),
                        "run_id": state.get("run_id"),
                        "candidate": cand,
                    }
                )
    tmp = out.with_name(f"{out.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")
    os.replace(tmp, out)
    print(rel(out))


def cmd_submission_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    path = submissions_path()
    entry = {
        "submission_id": args.id,
        "platform": args.platform,
        "program": args.program or target.get("program") or target.get("id"),
        "candidate_run": rel(run_dir),
        "candidate_id": args.candidate_id,
        "submitted_at": dt.datetime.now().isoformat(timespec="seconds"),
        "title": args.title or cand.get("title", ""),
        "severity_claimed": args.severity or "",
        "cvss_claimed": args.cvss or cand.get("cvss", ""),
        "status_history": [
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "status": "submitted",
                "note": args.note or "",
            }
        ],
        "final_status": "",
        "payout_value": None,
        "payout_currency": None,
        "days_to_final": None,
        "lessons": [],
    }
    entry = enrich_submission_entry(entry, target, cand)
    with file_lock(path):
        rows = read_jsonl(path)
        if any(row.get("submission_id") == args.id for row in rows) and not args.force:
            raise SystemExit(f"submission already exists: {args.id}")
        rows = [row for row in rows if row.get("submission_id") != args.id]
        rows.append(entry)
        write_jsonl(path, rows)
    update_candidate_locked(
        run_dir,
        args.candidate_id,
        lambda updated: updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "submission:add",
                "submission_id": args.id,
                "platform": args.platform,
            }
        ),
    )
    print(rel(path))


def cmd_submission_update(args: argparse.Namespace) -> None:
    path = submissions_path()
    updated = False
    with file_lock(path):
        rows = read_jsonl(path)
        for row in rows:
            if row.get("submission_id") != args.submission_id:
                continue
            event = {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "status": args.status,
                "note": args.note or "",
            }
            row.setdefault("status_history", []).append(event)
            if submission_terminal(args.status):
                row["final_status"] = args.status
                submitted = _parse_time(row.get("submitted_at"))
                if submitted:
                    row["days_to_final"] = max(0, (dt.datetime.now() - submitted).days)
            if args.payout is not None:
                row["payout_value"] = args.payout
            if args.currency:
                row["payout_currency"] = args.currency
            if args.lesson:
                row.setdefault("lessons", []).append(args.lesson)
            updated = True
            break
        if not updated:
            raise SystemExit(f"submission not found: {args.submission_id}")
        write_jsonl(path, rows)
    print(rel(path))


def cmd_submission_seed_synthetic(args: argparse.Namespace) -> None:
    corpus_path = candidate_corpus_path()
    if not corpus_path.exists():
        raise SystemExit(f"candidate corpus missing: {rel(corpus_path)}")
    corpus_rows = read_jsonl(corpus_path)
    seeded: list[dict[str, Any]] = []
    now = dt.datetime.now().isoformat(timespec="seconds")
    for entry in corpus_rows:
        cand = entry.get("candidate") or {}
        target_id = entry.get("target_id") or ""
        candidate_id = cand.get("id") or ""
        if not target_id or not candidate_id:
            continue
        seed_key = f"{target_id}:{candidate_id}"
        status, payout = _h._synthetic_status_for(seed_key)
        module = _h._synthetic_module_for(cand)
        evidence_kind = _h._synthetic_evidence_kind(cand)
        row = {
            "submission_id": f"SYN-{target_id}-{candidate_id}",
            "platform": "synthetic",
            "program": target_id,
            "candidate_run": entry.get("run_dir") or "",
            "candidate_id": candidate_id,
            "submitted_at": cand.get("created_at") or now,
            "updated_at": now,
            "title": cand.get("title") or "",
            "severity_claimed": cand.get("cvss") or "medium",
            "severity_final": cand.get("cvss") or "medium",
            "cvss_claimed": cand.get("cvss") or "",
            "status_history": [
                {"at": cand.get("created_at") or now, "status": "submitted", "note": "synthetic seed"},
                {"at": now, "status": status, "note": "synthetic outcome assignment"},
            ],
            "final_status": status,
            "payout_value": payout,
            "payout_currency": "USD" if payout else None,
            "days_to_final": 14,
            "lessons": [f"Synthetic seed for {module} pattern"],
            "target_id": target_id,
            "target_category": [],
            "language": [],
            "weakness": cand.get("weakness") or "",
            "cwe": cand.get("cwe") or cand.get("weakness") or "",
            "surface": cand.get("surface") or "",
            "sink": cand.get("sink") or "",
            "campaign_module": module,
            "evidence_kind": evidence_kind,
            "queue_type": "",
            "harness_version": HARNESS_VERSION,
            "synthetic": True,
            "synthetic_source": rel(corpus_path),
        }
        seeded.append(row)
    path = submissions_path()
    with file_lock(path):
        existing = read_jsonl(path)
        if args.clear:
            existing = [row for row in existing if not row.get("synthetic")]
            seeded = []
        else:
            existing = [row for row in existing if not (row.get("synthetic") and row.get("submission_id", "").startswith("SYN-"))]
            existing.extend(seeded)
        write_jsonl(path, existing)
    payload = {
        "path": rel(path),
        "seeded": len(seeded),
        "cleared": bool(args.clear),
        "total_rows": len(existing),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"{rel(path)} seeded={len(seeded)} total={len(existing)}")


def cmd_outcome_record(args: argparse.Namespace) -> None:
    path = submissions_path()
    run_dir = run_path(args.run_dir) if args.run_dir else None
    target: dict[str, Any] = {}
    cand: dict[str, Any] = {}
    if run_dir:
        _, target = _h.load_run(run_dir)
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
    submission_id = args.submission_id or f"{(target.get('id') or 'outcome')}-{args.candidate_id}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"
    now = dt.datetime.now().isoformat(timespec="seconds")
    event = {"at": now, "status": args.status, "note": args.note or ""}
    with file_lock(path):
        rows = read_jsonl(path)
        matched = False
        updated_rows = []
        for row in rows:
            if row.get("submission_id") != submission_id:
                updated_rows.append(row)
                continue
            row.setdefault("status_history", []).append(event)
            row["final_status"] = args.status if submission_terminal(args.status) else row.get("final_status", "")
            row["updated_at"] = now
            if args.payout is not None:
                row["payout_value"] = args.payout
            if args.currency:
                row["payout_currency"] = args.currency
            if args.severity:
                row["severity_final"] = args.severity
            if args.lesson:
                row.setdefault("lessons", []).append(args.lesson)
            if target and cand:
                row = enrich_submission_entry(row, target, cand)
            matched = True
            updated_rows.append(row)
        if not matched:
            if not run_dir or not args.candidate_id:
                raise SystemExit("new outcome records require run_dir and candidate_id")
            row = {
                "submission_id": submission_id,
                "platform": args.platform or "",
                "program": args.program or target.get("program") or target.get("id"),
                "candidate_run": rel(run_dir),
                "candidate_id": args.candidate_id,
                "submitted_at": args.submitted_at or now,
                "updated_at": now,
                "title": args.title or cand.get("title", ""),
                "severity_claimed": args.severity_claimed or "",
                "severity_final": args.severity or "",
                "cvss_claimed": args.cvss or cand.get("cvss", ""),
                "status_history": [event],
                "final_status": args.status if submission_terminal(args.status) else "",
                "payout_value": args.payout,
                "payout_currency": args.currency,
                "days_to_final": None,
                "lessons": [args.lesson] if args.lesson else [],
            }
            submitted = _parse_time(row.get("submitted_at"))
            if submitted and row["final_status"]:
                row["days_to_final"] = max(0, (dt.datetime.now() - submitted).days)
            updated_rows.append(enrich_submission_entry(row, target, cand))
        write_jsonl(path, updated_rows)
    if run_dir and args.candidate_id:
        def mark_outcome(updated: dict[str, Any]) -> None:
            updated.setdefault("history", []).append(
                {
                    "at": now,
                    "event": "outcome-recorded",
                    "submission_id": submission_id,
                    "status": args.status,
                }
            )
            updated["submission_outcome"] = {
                "submission_id": submission_id,
                "status": args.status,
                "recorded_at": now,
            }

        update_candidate_locked(run_dir, args.candidate_id, mark_outcome)
    payload = {"submission_id": submission_id, "path": rel(path), "status": args.status}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(path))


def cmd_submissions_list(args: argparse.Namespace) -> None:
    rows = read_jsonl(submissions_path())
    if args.program:
        rows = [row for row in rows if str(row.get("program", "")).lower() == args.program.lower()]
    if args.final_only:
        rows = [row for row in rows if row.get("final_status")]
    if args.since:
        since = _parse_time(args.since)
        if since:
            rows = [row for row in rows if (_parse_time(row.get("submitted_at")) or dt.datetime.min) >= since]
    if args.json:
        print(json.dumps({"submissions": rows}, indent=2, sort_keys=False))
    else:
        for row in rows:
            print(
                f"{row.get('submission_id')} [{row.get('final_status') or 'open'}] "
                f"{row.get('program')} {row.get('candidate_id')} {row.get('title')}"
            )


def cmd_outcome_tune(args: argparse.Namespace) -> None:
    rows = read_jsonl(submissions_path())
    step_rows = read_jsonl(step_outcomes_path()) if step_outcomes_path().exists() else []
    if args.since:
        since = _parse_time(args.since)
        if since:
            rows = [row for row in rows if (_parse_time(row.get("updated_at") or row.get("submitted_at")) or dt.datetime.min) >= since]
            step_rows = [row for row in step_rows if (_parse_time(row.get("recorded_at")) or dt.datetime.min) >= since]
    include_synthetic = bool(getattr(args, "include_synthetic", False))
    tuning = outcome_tuning(rows, include_synthetic=include_synthetic, step_rows=step_rows)
    out = run_path(args.out) if args.out else outcome_tuning_path()
    dump_yaml(tuning, out)
    md_path = out.with_suffix(".md")
    lines = [
        "# Outcome Tuning",
        "",
        f"- Generated at: `{tuning['generated_at']}`",
        f"- Terminal outcomes: `{tuning['terminal_count']}`",
        f"- Triage verdicts folded: `{tuning.get('triage_verdict_count', 0)}`",
        f"- Synthetic excluded: `{tuning.get('synthetic_excluded', 0)}`",
        f"- Synthetic included: `{tuning.get('synthetic_included', 0)}`",
        "",
        "## Module Adjustments",
        "",
    ]
    for key, item in tuning["module_adjustments"].items():
        lines.append(
            f"- `{key}` adjustment=`{item['score_adjustment']}` acceptance=`{item['acceptance_rate']}` "
            f"duplicate=`{item['duplicate_rate']}` terminal=`{item['terminal']}`"
        )
    if not tuning["module_adjustments"]:
        lines.append("- No module-level terminal outcomes yet.")
    lines.extend(["", "## Weakness Adjustments", ""])
    for key, item in tuning["weakness_adjustments"].items():
        triage = item.get("triage")
        triage_note = ""
        if triage:
            triage_note = (
                f" triage(np={triage['needs_proof']},def={triage['defended']},"
                f"fp={triage['false_positive']},adj={item.get('triage_score_adjustment')})"
            )
        lines.append(
            f"- `{key}` adjustment=`{item['score_adjustment']}` acceptance=`{item['acceptance_rate']}` "
            f"duplicate=`{item['duplicate_rate']}` terminal=`{item['terminal']}`{triage_note}"
        )
    if not tuning["weakness_adjustments"]:
        lines.append("- No weakness-level terminal outcomes yet.")
    write_text(md_path, "\n".join(lines) + "\n")
    payload = {"tuning": rel(out), "report": rel(md_path), "terminal_count": tuning["terminal_count"]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(out))
        print(rel(md_path))


def cmd_weights_show(args: argparse.Namespace) -> None:
    """Show the current effective tuning weights and when they were last
    meaningfully updated. Read-only — does not recompute (use `outcome-tune`)."""
    path = outcome_tuning_path()
    tuning = load_outcome_tuning()
    if not tuning:
        payload = {
            "effective_weights": rel(path),
            "exists": False,
            "note": "no effective weights yet; run `outcome-tune`",
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=False))
        else:
            print("no effective weights yet; run `outcome-tune`")
        return

    weakness = tuning.get("weakness_adjustments") or {}
    module = tuning.get("module_adjustments") or {}
    nonzero_weakness = {
        k: v for k, v in weakness.items()
        if isinstance(v, dict) and v.get("score_adjustment")
    }
    nonzero_module = {
        k: v for k, v in module.items()
        if isinstance(v, dict) and v.get("score_adjustment")
    }
    payload = {
        "effective_weights": rel(path),
        "generated_at": tuning.get("generated_at"),
        "last_meaningful_update": tuning.get("generated_at"),
        "source": tuning.get("source"),
        "expected_source": rel(submissions_path()),
        "source_is_current": tuning.get("source") == rel(submissions_path()),
        "terminal_count": tuning.get("terminal_count", 0),
        "triage_verdict_count": tuning.get("triage_verdict_count", 0),
        "synthetic_excluded": tuning.get("synthetic_excluded", 0),
        "nonzero_weakness_adjustments": nonzero_weakness,
        "nonzero_module_adjustments": nonzero_module,
        "starved": int(tuning.get("terminal_count", 0)) == 0
        and int(tuning.get("triage_verdict_count", 0)) == 0,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
        return
    print(f"effective weights: {payload['effective_weights']}")
    print(f"last meaningful update: {payload['last_meaningful_update']}")
    print(
        f"terminal outcomes: {payload['terminal_count']}  "
        f"triage verdicts: {payload['triage_verdict_count']}  "
        f"synthetic excluded: {payload['synthetic_excluded']}"
    )
    if not payload["source_is_current"]:
        print(
            f"WARNING: weights computed from `{payload['source']}` "
            f"(current corpus is `{payload['expected_source']}`) — re-run outcome-tune"
        )
    if payload["starved"]:
        print("STARVED: no real terminal outcome or triage verdict has moved a weight yet")
    if nonzero_weakness:
        print("weakness adjustments:")
        for k, v in sorted(nonzero_weakness.items()):
            print(f"  {k}: score_adjustment={v.get('score_adjustment')}")
    if nonzero_module:
        print("module adjustments:")
        for k, v in sorted(nonzero_module.items()):
            print(f"  {k}: score_adjustment={v.get('score_adjustment')}")


def cmd_submissions_stats(args: argparse.Namespace) -> None:
    rows = read_jsonl(submissions_path())
    stats = submission_stats(rows)
    if args.json:
        print(json.dumps(stats, indent=2, sort_keys=True))
    else:
        for program, item in stats["programs"].items():
            print(
                f"{program}: total={item['total']} terminal={item['terminal']} "
                f"acceptance={item['acceptance_rate']} duplicate={item['duplicate_rate']} "
                f"avg_value={item['average_value']} avg_days={item['average_days_to_final']}"
            )
