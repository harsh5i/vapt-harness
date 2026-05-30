"""Outcome-tuning loop: synthetic exclusion + triage-verdict folding.

These guard the learning loop's core honesty property — synthetic seed data must
never move production weights unless explicitly requested."""


def _terminal_row(cwe="CWE-918", status="paid", payout=500.0, synthetic=False):
    row = {
        "submission_id": f"S-{cwe}-{status}",
        "final_status": status,
        "cwe": cwe,
        "weakness": cwe,
        "target_id": "demo",
        "campaign_module": "ssrf_callback",
        "evidence_kind": "reproducer_verified",
        "payout_value": payout,
    }
    if synthetic:
        row["synthetic"] = True
    return row


def _triage_step(cwe="CWE-918", verdict="needs_proof"):
    return {"weakness": cwe, "triage_verdict": verdict}


def test_synthetic_excluded_by_default(h):
    rows = [_terminal_row(synthetic=True)]
    out = h.outcome_tuning(rows, step_rows=[])
    assert out["terminal_count"] == 0
    assert out["synthetic_excluded"] == 1
    assert out["weakness_adjustments"] == {}


def test_synthetic_included_when_requested(h):
    rows = [_terminal_row(synthetic=True)]
    out = h.outcome_tuning(rows, include_synthetic=True, step_rows=[])
    assert out["terminal_count"] == 1
    assert out["synthetic_included"] == 1
    assert "CWE-918" in out["weakness_adjustments"]


def test_real_terminal_row_counts(h):
    rows = [_terminal_row(synthetic=False)]
    out = h.outcome_tuning(rows, step_rows=[])
    assert out["terminal_count"] == 1
    assert out["synthetic_excluded"] == 0
    assert "CWE-918" in out["weakness_adjustments"]


def test_non_terminal_row_ignored(h):
    rows = [{"submission_id": "x", "final_status": "", "cwe": "CWE-79", "weakness": "CWE-79"}]
    out = h.outcome_tuning(rows, step_rows=[])
    assert out["terminal_count"] == 0


def test_triage_verdict_folds_into_weakness_adjustment(h):
    out = h.outcome_tuning([], step_rows=[_triage_step()])
    assert out["triage_verdict_count"] == 1
    adj = out["weakness_adjustments"]["CWE-918"]
    # single needs_proof: raw 0.75, halved (<2 samples) -> 0.38
    assert adj["score_adjustment"] == 0.38
    assert adj["triage"]["needs_proof"] == 1


def test_triage_false_positive_is_strong_negative(h):
    out = h.outcome_tuning([], step_rows=[_triage_step(verdict="false_positive")])
    adj = out["weakness_adjustments"]["CWE-918"]
    assert adj["score_adjustment"] < 0


def test_triage_score_adjustment_math(h):
    # two false_positive: raw -4.0, not halved (>=2 samples)
    bucket = {"needs_proof": 0, "defended": 0, "false_positive": 2, "total": 2}
    assert h._triage_score_adjustment(bucket) == -4.0


def test_triage_score_adjustment_clamped(h):
    bucket = {"needs_proof": 100, "defended": 0, "false_positive": 0, "total": 100}
    assert h._triage_score_adjustment(bucket) == 5.0  # clamp ceiling


def test_synthetic_excluded_but_triage_still_folds(h):
    # synthetic terminal excluded, yet a real triage verdict still moves the weight
    out = h.outcome_tuning([_terminal_row(synthetic=True)], step_rows=[_triage_step()])
    assert out["terminal_count"] == 0
    assert out["synthetic_excluded"] == 1
    assert out["weakness_adjustments"]["CWE-918"]["score_adjustment"] == 0.38
