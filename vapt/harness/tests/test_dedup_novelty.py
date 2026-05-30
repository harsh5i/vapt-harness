"""Dedup novelty gate. The load-bearing invariant: an OSV lookup that could not
actually run (offline / cache-only miss) must NOT be recorded as
no-known-duplicate — it degrades to dedup-incomplete, which blocks promotion."""
import argparse

import pytest


def _dedup_args(run_dir, **over):
    base = dict(
        run_dir=str(run_dir),
        candidate_id="C1",
        check_osv=False,
        regression=False,
        status=None,
        reference=None,
        notes="",
        osv_cache_only=False,
        osv_fresh_only=False,
        osv_timeout=5,
        osv_ecosystem=None,
        osv_package=None,
        osv_version=None,
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_dedup_checked_requires_timestamp_and_novelty(h):
    assert h.dedup_checked({}) is False
    assert h.dedup_checked({"dedup": {"checked_at": "t"}, "novelty": "unchecked"}) is False
    assert h.dedup_checked({"dedup": {"checked_at": "t"}, "novelty": "no-known-duplicate"}) is True


def test_dedup_checked_false_without_dedup_dict(h):
    assert h.dedup_checked({"novelty": "no-known-duplicate"}) is False


def test_offline_osv_cache_only_does_not_fake_novelty(h, make_run):
    # candidate has no CVE/GHSA and target declares no OSV package, so a
    # cache-only run performs no real lookup -> must degrade, not claim novelty.
    run_dir = make_run([{"id": "C1", "title": "SSRF filter gap", "weakness": "CWE-918"}])
    h.cmd_dedup(_dedup_args(run_dir, check_osv=True, osv_cache_only=True))
    cand = h.load_candidates(run_dir)["candidates"][0]
    assert cand["novelty"] == "dedup-incomplete"
    assert cand["novelty"] in h.PROMOTION_BLOCKING_NOVELTY


def test_dedup_incomplete_blocks_promotion(h, make_run):
    run_dir = make_run([{"id": "C1", "title": "x", "weakness": "CWE-918"}])
    h.cmd_dedup(_dedup_args(run_dir, check_osv=True, osv_cache_only=True))
    cand = h.load_candidates(run_dir)["candidates"][0]
    # dedup_checked is satisfied (it ran), but novelty is a blocking value
    ok, blockers = h.promotion_findings(cand)
    assert ok is False
    assert "novelty_not_duplicate_or_unchecked" in blockers


def test_known_duplicate_detected_from_target_list(h, make_run):
    target = {"id": "demo", "name": "demo", "repo_url": "", "known_duplicates": ["cve-2021-1234"]}
    run_dir = make_run(
        [{"id": "C1", "title": "bug", "cve": "CVE-2021-1234"}],
        target=target,
    )
    with pytest.raises(SystemExit) as exc:  # duplicate_seen -> exit 3
        h.cmd_dedup(_dedup_args(run_dir))
    assert exc.value.code == 3
    cand = h.load_candidates(run_dir)["candidates"][0]
    assert cand["novelty"] == "known-duplicate"


def test_no_known_duplicate_when_clean(h, make_run):
    run_dir = make_run([{"id": "C1", "title": "novel finding", "weakness": "CWE-918"}])
    h.cmd_dedup(_dedup_args(run_dir))  # no osv, no known dup -> clean
    cand = h.load_candidates(run_dir)["candidates"][0]
    assert cand["novelty"] == "no-known-duplicate"
    assert h.dedup_checked(cand) is True
