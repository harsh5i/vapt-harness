"""Foundation layer: repo-root anchor, version/constants, path resolution.

Bottom of the harness dependency graph — depends only on the stdlib. ROOT is
computed the same way harness.py computes it (this module sits in the same
vapt/harness/ directory), so every ROOT-relative path resolves identically.
Extracted leaf modules import from here instead of reaching back into harness.
"""
from __future__ import annotations

import contextlib
import datetime as dt
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VAPT_LOCAL_BIN = ROOT / ".vapt-bin"
VAPT_VENV_BIN = ROOT / ".venv-vapt" / "bin"
CURRENT_CANDIDATE_SCHEMA_VERSION = 2
HARNESS_VERSION = "0.4.1-phase4-hardening"
TRIAGE_VERDICTS = {"needs_proof", "defended", "false_positive"}


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def run_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def source_path(target: dict[str, Any]) -> Path:
    raw = target.get("source_path") or target.get("repo_path")
    if not raw:
        raise SystemExit("target profile requires source_path")
    return run_path(raw)


def now_id() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")


def step_outcomes_path() -> Path:
    return ROOT / "vapt" / "harness" / "corpus" / "step_outcomes.jsonl"


def submissions_path() -> Path:
    return ROOT / "vapt" / "harness" / "corpus" / "submissions.jsonl"


def candidate_corpus_path() -> Path:
    return ROOT / "vapt" / "harness" / "corpus" / "candidates.jsonl"


def outcome_tuning_path() -> Path:
    return ROOT / "vapt" / "harness" / "corpus" / "outcome_tuning.yaml"


def _parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    with contextlib.suppress(ValueError):
        return dt.datetime.fromisoformat(str(value))
    return None
