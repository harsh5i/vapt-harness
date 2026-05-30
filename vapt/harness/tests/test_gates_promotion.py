"""Promotion + workflow gates: the invariants that stop a candidate from
advancing without the evidence each state requires."""
import pytest


def _promotable():
    """A candidate that passes promotion_findings cleanly. Tests knock out one
    field at a time to prove each blocker fires."""
    return {
        "id": "C1",
        "attacker_control": "attacker-supplied hostname in oneboxed URL",
        "entrypoint": "SSRFResolver.resolve via onebox fetch",
        "trust_boundary": "external URL crosses into outbound HTTP client",
        "sink": "SSRFResolver::SSRFDetector.ip_allowed?",
        "impact": "reaches internal 127.0.0.1 services",
        "latest_affected": "v3.4.0",
        "cwe": "CWE-918",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "novelty": "no-known-duplicate",
        "dedup": {"checked_at": "2026-05-30T00:00:00", "status": "no-known-duplicate"},
    }


def _report_ready():
    cand = _promotable()
    cand.update(
        {
            "proof": "passed",
            "root_cause": "PRIVATE_IPV6_RANGES omits the NAT64 well-known prefix",
            "variant_analysis": "sibling avatar-from-URL surface shares the filter",
            "patch_diff": "adds 64:ff9b::/96 and 2002::/16 to the blocklist",
            "negative_controls": "IPv4-mapped ::ffff:7f00:1 is correctly blocked",
            "exploitability": "L3",
        }
    )
    return cand


def test_clean_candidate_passes_promotion(h):
    ok, blockers = h.promotion_findings(_promotable())
    assert ok is True, blockers
    assert blockers == []


def test_cannot_promote_without_dedup(h):
    cand = _promotable()
    cand["dedup"] = {}
    cand["novelty"] = "unchecked"
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert "dedup_not_checked" in blockers


def test_cannot_promote_with_duplicate_novelty(h):
    cand = _promotable()
    cand["novelty"] = "known-duplicate"
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert "novelty_not_duplicate_or_unchecked" in blockers


@pytest.mark.parametrize(
    "field", ["attacker_control", "entrypoint", "trust_boundary", "sink", "impact"]
)
def test_each_required_field_blocks_promotion(h, field):
    cand = _promotable()
    cand[field] = ""
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert field in blockers


def test_bare_number_cvss_blocks_promotion(h):
    cand = _promotable()
    cand["cvss"] = "5.3"
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert any(b.startswith("invalid_cvss") for b in blockers)


def test_non_exact_latest_affected_blocks_promotion(h):
    cand = _promotable()
    cand["latest_affected"] = "unchecked"
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert "latest_release_not_confirmed" in blockers


def test_invalid_cwe_blocks_promotion(h):
    cand = _promotable()
    cand["cwe"] = "918"
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert "invalid_cwe" in blockers


# --- workflow_blockers: state ordering --------------------------------------


def test_workflow_blockers_dedup_required_before_promoted(h):
    cand = _promotable()
    cand["dedup"] = {}
    cand["novelty"] = "unchecked"
    assert "dedup_not_checked" in h.workflow_blockers(cand, "promoted")


def test_report_ready_requires_negative_controls(h):
    cand = _report_ready()
    cand["negative_controls"] = ""
    assert "negative_controls_missing" in h.workflow_blockers(cand, "report_ready")


def test_report_ready_requires_proof_passed(h):
    cand = _report_ready()
    cand["proof"] = "not_started"
    assert "proof_not_passed" in h.workflow_blockers(cand, "report_ready")


def test_report_ready_rejects_low_exploitability(h):
    cand = _report_ready()
    cand["exploitability"] = "L1-theoretical"
    assert "exploitability_below_L3" in h.workflow_blockers(cand, "report_ready")


def test_report_ready_requires_root_cause_and_variant_and_patch(h):
    cand = _report_ready()
    cand["root_cause"] = ""
    cand["variant_analysis"] = ""
    cand["patch_diff"] = ""
    blockers = h.workflow_blockers(cand, "report_ready")
    assert "root_cause_missing" in blockers
    assert "variant_analysis_missing" in blockers
    assert "patch_diff_missing" in blockers


def test_fully_clean_candidate_is_report_ready(h):
    assert h.workflow_blockers(_report_ready(), "report_ready") == []
