"""Pure-validator tests for the outcome-ingest helper.

The script's full execution path needs an initialized run directory and a
candidate ledger, which is covered by the operator acceptance commands in
STATUS.md. Here we exercise the parts that need to survive on their own:

- the column-alias / normalization layer (so a paste from a bug bounty
  platform with header variations like `id`, `Report ID`, `verdict`
  still routes into the right outcome-record flag);
- the row validator (so dry-run gives the operator accurate go/no-go
  signal before any writes hit submissions.jsonl);
- the to-namespace conversion (so cmd_outcome_record receives the exact
  attribute set its argparse parser would provide).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import outcome_ingest as oi  # noqa: E402


def test_normalize_row_lowercases_and_strips() -> None:
    out = oi._normalize_row({" Submission ID ": " S-1 ", "Status": "Triaged"})
    assert out == {"submission_id": "S-1", "status": "Triaged"}


def test_normalize_row_applies_aliases() -> None:
    raw = {
        "id": "S-1",
        "verdict": "duplicate",
        "bounty": "250",
        "Run": "vapt/engagements/x/runs/x/2026",
        "candidate": "CAND-001",
    }
    out = oi._normalize_row(raw)
    assert out["submission_id"] == "S-1"
    assert out["status"] == "duplicate"
    assert out["payout"] == "250"
    assert out["run_dir"] == "vapt/engagements/x/runs/x/2026"
    assert out["candidate_id"] == "CAND-001"


def test_normalize_row_drops_empty_strings() -> None:
    out = oi._normalize_row({"submission_id": "S-1", "note": ""})
    assert "note" not in out


@pytest.mark.parametrize(
    "row,expect_errs",
    [
        ({"status": "triaged"}, 1),  # missing both submission_id and (run_dir+candidate_id)
        ({"submission_id": "S-1"}, 1),  # missing status
        ({"submission_id": "S-1", "status": "garbage"}, 1),  # unknown status
        ({"submission_id": "S-1", "status": "triaged"}, 0),  # update path
        ({"run_dir": "r", "candidate_id": "C", "status": "duplicate"}, 0),  # create path
    ],
)
def test_validate(row, expect_errs) -> None:
    assert len(oi._validate(row, lineno=2)) == expect_errs


def test_validate_lists_known_statuses_on_unknown() -> None:
    errs = oi._validate({"submission_id": "S-1", "status": "weirdvalue"}, 2)
    msg = "\n".join(errs)
    assert "weirdvalue" in msg
    assert "duplicate" in msg  # one of the known terminal statuses


def test_to_namespace_carries_required_outcome_record_fields() -> None:
    """The CLI parser sets these attributes; cmd_outcome_record reads them
    unconditionally, so the converter must always populate them (with None
    when the row omits the value).
    """
    ns = oi._to_namespace({"submission_id": "S-1", "status": "Triaged"})
    for attr in (
        "submission_id", "run_dir", "candidate_id", "status",
        "platform", "program", "title", "submitted_at",
        "severity_claimed", "severity", "cvss", "payout", "currency",
        "lesson", "note", "json",
    ):
        assert hasattr(ns, attr), f"namespace missing {attr}"
    assert ns.status == "triaged"  # always lowercased
    assert ns.json is False


def test_to_namespace_parses_payout_as_float() -> None:
    ns = oi._to_namespace({"submission_id": "S-1", "status": "paid", "payout": "250.5"})
    assert ns.payout == 250.5


def test_to_namespace_drops_unparseable_payout() -> None:
    ns = oi._to_namespace({"submission_id": "S-1", "status": "paid", "payout": "later"})
    assert ns.payout is None


def test_known_statuses_cover_validator_terminal_set() -> None:
    """Drift guard: if validators.submission_terminal grows new entries the
    ingest validator should accept them too (otherwise dry-run lies about
    what cmd_outcome_record will actually do).
    """
    sys.path.insert(0, str(REPO_ROOT / "vapt" / "harness"))
    from validators import submission_terminal  # noqa: E402

    canonical = {
        "triaged", "duplicate", "n_a", "not_applicable", "resolved", "paid",
        "accepted", "valid", "informative", "rejected", "out_of_scope",
    }
    for status in canonical:
        assert submission_terminal(status), f"validators dropped {status}"
        assert status in oi.TERMINAL_STATUSES, f"ingest TERMINAL_STATUSES missed {status}"
