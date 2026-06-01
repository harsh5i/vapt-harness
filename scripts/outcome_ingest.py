#!/usr/bin/env python3
"""Batch-ingest real bounty triage outcomes into the harness corpus.

The harness has one operational gap: the terminal-submission channel needs
real triage verdicts to flow before `outcome-tune` can move weights based on
anything other than the synthetic seed. Typing each `outcome-record`
invocation by hand after every triage update is friction. This script eats
a CSV or JSON the operator can paste / drop from their bug bounty platform
(or compose by hand) and dispatches into `cmd_outcome_record` per row, then
runs `cmd_outcome_tune` so the weights move in one batch.

Input formats:

  --csv FILE     CSV with a header row. Columns map to outcome-record flags
                 by name. Any row that omits a required field is reported
                 and skipped (the rest still run).
  --json FILE    JSON file containing a single list of row dicts.

Required fields per row:

  Either:  submission_id + status                (updates an existing row)
  Or:      run_dir + candidate_id + status       (creates a new row)

Optional fields (recognized everywhere):

  platform program title submitted_at severity_claimed severity
  cvss payout currency lesson note

Status vocabulary (lowercase enforced):

  Terminal (folds into outcome-tune):
    triaged duplicate n_a not_applicable resolved paid accepted valid
    informative rejected out_of_scope
  In-progress (recorded but not terminal):
    needs_proof defended false_positive   # plus any string operator wants

Flags:

  --dry-run      Validate the input + print what would happen. No writes.
  --no-tune      Skip the trailing `outcome-tune` call (default: tune).
  --quiet        Suppress per-row output; only print the summary.

Exit code: 0 if all rows were dispatched cleanly, 2 if any row failed
validation, 3 if `outcome-tune` itself raised.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS_DIR = REPO_ROOT / "vapt" / "harness"
sys.path.insert(0, str(HARNESS_DIR))

import argparse as _argparse  # noqa: E402  (re-import for clarity below)

# Importing the harness package by name gives us cmd_outcome_record and
# cmd_outcome_tune through the same shim the CLI uses.
import harness as _h  # noqa: E402


TERMINAL_STATUSES = frozenset({
    "triaged", "duplicate", "n_a", "not_applicable", "resolved", "paid",
    "accepted", "valid", "informative", "rejected", "out_of_scope",
})
KNOWN_IN_PROGRESS = frozenset({
    "needs_proof", "defended", "false_positive", "new", "submitted", "open",
})
ALL_KNOWN_STATUSES = TERMINAL_STATUSES | KNOWN_IN_PROGRESS

# CSV column -> outcome-record flag (the canonical names match the flags
# directly, but the operator's export may carry slightly different headers,
# so we accept a small alias table out of the box).
COLUMN_ALIASES = {
    "id": "submission_id",
    "report_id": "submission_id",
    "candidate": "candidate_id",
    "run": "run_dir",
    "verdict": "status",
    "state": "status",
    "outcome": "status",
    "bounty": "payout",
    "amount": "payout",
    "money": "payout",
}

OPTIONAL_FIELDS = (
    "platform", "program", "title", "submitted_at", "severity_claimed",
    "severity", "cvss", "payout", "currency", "lesson", "note",
)


def _normalize_row(row: dict) -> dict:
    """Lowercase keys, apply alias map, drop empties, strip strings."""
    out: dict = {}
    for raw_key, raw_val in row.items():
        if raw_key is None:
            continue
        key = str(raw_key).strip().lower().replace("-", "_").replace(" ", "_")
        key = COLUMN_ALIASES.get(key, key)
        if raw_val is None:
            continue
        val = raw_val.strip() if isinstance(raw_val, str) else raw_val
        if val == "":
            continue
        out[key] = val
    return out


def _validate(row: dict, lineno: int) -> list[str]:
    errs: list[str] = []
    status = str(row.get("status", "")).lower()
    if not status:
        errs.append(f"row {lineno}: missing 'status'")
    elif status not in ALL_KNOWN_STATUSES:
        errs.append(
            f"row {lineno}: unknown status '{status}'. Known: "
            f"{', '.join(sorted(ALL_KNOWN_STATUSES))}"
        )
    has_sub = bool(row.get("submission_id"))
    has_new = bool(row.get("run_dir")) and bool(row.get("candidate_id"))
    if not has_sub and not has_new:
        errs.append(
            f"row {lineno}: needs either 'submission_id' (to update an "
            f"existing row) or both 'run_dir' and 'candidate_id' (to "
            f"create one)"
        )
    return errs


def _to_namespace(row: dict) -> argparse.Namespace:
    """Build the exact Namespace cmd_outcome_record expects, with defaults
    matching the CLI parser so missing flags don't blow up.
    """
    payout = row.get("payout")
    if isinstance(payout, str):
        try:
            payout = float(payout)
        except ValueError:
            payout = None
    return argparse.Namespace(
        submission_id=row.get("submission_id"),
        run_dir=row.get("run_dir"),
        candidate_id=row.get("candidate_id"),
        status=str(row["status"]).lower(),
        platform=row.get("platform"),
        program=row.get("program"),
        title=row.get("title"),
        submitted_at=row.get("submitted_at"),
        severity_claimed=row.get("severity_claimed"),
        severity=row.get("severity"),
        cvss=row.get("cvss"),
        payout=payout,
        currency=row.get("currency"),
        lesson=row.get("lesson"),
        note=row.get("note"),
        json=False,
    )


def _load_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return [dict(r) for r in reader]


def _load_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"--json expected a list, got {type(data).__name__}")
    return data


def _run_one(row: dict) -> str:
    """Invoke cmd_outcome_record on a single row. Captures stdout so the
    runner can decide what to surface (per-row vs summary-only).
    """
    ns = _to_namespace(row)
    buf = io.StringIO()
    with redirect_stdout(buf):
        _h.cmd_outcome_record(ns)
    return buf.getvalue().strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--csv", type=Path, help="CSV file (header row required)")
    src.add_argument("--json", dest="json_path", type=Path, help="JSON file: list of row dicts")
    parser.add_argument("--dry-run", action="store_true", help="validate + report; no writes")
    parser.add_argument("--no-tune", action="store_true", help="skip the trailing outcome-tune call")
    parser.add_argument("--quiet", action="store_true", help="suppress per-row output")
    args = parser.parse_args(argv)

    rows_in = _load_csv(args.csv) if args.csv else _load_json(args.json_path)
    if not rows_in:
        print("no rows in input", file=sys.stderr)
        return 2

    rows: list[dict] = []
    errors: list[str] = []
    for i, raw in enumerate(rows_in, start=2):  # 2 = first data row after CSV header
        norm = _normalize_row(raw)
        errs = _validate(norm, i)
        if errs:
            errors.extend(errs)
            continue
        rows.append(norm)

    if errors:
        for e in errors:
            print(f"ERR: {e}", file=sys.stderr)
        if not rows:
            print("no valid rows; aborting", file=sys.stderr)
            return 2

    if args.dry_run:
        print(f"[dry-run] {len(rows)} valid row(s), {len(errors)} skipped")
        for r in rows:
            sid = r.get("submission_id") or f"{r.get('candidate_id')} @ {r.get('run_dir')}"
            print(f"  - {sid} -> {r['status']}")
        return 0 if not errors else 2

    written = 0
    failed: list[tuple[dict, Exception]] = []
    for r in rows:
        try:
            line = _run_one(r)
            written += 1
            if not args.quiet and line:
                print(line)
        except SystemExit as exc:
            failed.append((r, exc))
            print(f"FAIL: {r.get('submission_id') or r.get('candidate_id')}: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            failed.append((r, exc))
            print(f"FAIL: {r.get('submission_id') or r.get('candidate_id')}: {exc}", file=sys.stderr)

    print(
        f"\nrecorded={written} failed={len(failed)} "
        f"skipped_validation={len(errors)}"
    )

    if not args.no_tune and written:
        print("\n-- outcome-tune --")
        tune_ns = argparse.Namespace(
            since=None, out=None, include_synthetic=False, json=False,
        )
        try:
            _h.cmd_outcome_tune(tune_ns)
        except SystemExit as exc:
            print(f"outcome-tune raised: {exc}", file=sys.stderr)
            return 3

    return 0 if not failed and not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
