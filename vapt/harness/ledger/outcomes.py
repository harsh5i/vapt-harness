"""Step-outcome ledger: append-only writer for the per-step record stream that
feeds outcome-tuning.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from atomic_io import file_lock
from core import step_outcomes_path


def _append_step_outcome(row: dict[str, Any]) -> str:
    path = step_outcomes_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    outcome_id = row.get("outcome_id") or (
        f"SO-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    )
    row["outcome_id"] = outcome_id
    row.setdefault("recorded_at", dt.datetime.now().isoformat(timespec="seconds"))
    with file_lock(path):
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return outcome_id
