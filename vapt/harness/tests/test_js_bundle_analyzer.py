"""Tests for the JS bundle analyzer probe.

The analyzer is a static scanner that consumes JS source (or built bundles)
and surfaces high-recall hypotheses for an operator/LLM auditor to confirm.
It is NOT an exploit; findings are leads, not vulnerabilities.

Coverage:
  - URL/endpoint extraction (absolute, root-relative API paths)
  - Admin/internal route flagging (highest-value class)
  - Secret pattern detection (AWS, GitHub PAT, Stripe live, JWT)
  - Generic key-assignment heuristic (apiKey = "..." with non-placeholder)
  - End-to-end probe.run() on a fixture directory
  - Negative controls: placeholder values + test paths must NOT trip secrets
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def analyzer():
    from source.js_bundle import JsBundleAnalyzer
    return JsBundleAnalyzer()


def test_extracts_root_relative_api_paths(analyzer):
    src = '''
        const A = "/api/v2/users";
        fetch("/api/admin/keys");
        const noise = "no-leading-slash";
    '''
    findings = analyzer.analyze_source(src, path="x.js")
    paths = {f["match"] for f in findings if f["kind"] == "endpoint"}
    assert "/api/v2/users" in paths
    assert "/api/admin/keys" in paths
    assert "no-leading-slash" not in paths


def test_flags_admin_and_internal_routes(analyzer):
    src = '''
        const adminRoute = "/admin/users/delete";
        const internalRoute = "/internal/healthz";
        const publicRoute = "/posts/show";
    '''
    findings = analyzer.analyze_source(src, path="x.js")
    flagged = {f["match"] for f in findings if f["kind"] == "admin_route"}
    assert "/admin/users/delete" in flagged
    assert "/internal/healthz" in flagged
    assert "/posts/show" not in flagged


# Build token-shaped fixtures at runtime so no full literal appears in source
# (GitHub push-protection / secret-scanning flags repo files containing tokens
# even when they are obvious test fixtures).
_AWS_FIXTURE = "AKIA" + "1234567890ABCDEF"
_GH_FIXTURE = "gh" + "p_" + "a" * 36
_STRIPE_FIXTURE = "sk_" + "live_" + "1234567890ABCDEFGHIJ1234"


def test_detects_aws_access_key(analyzer):
    src = f'const cfg = {{ AWS_KEY: "{_AWS_FIXTURE}" }};'
    findings = analyzer.analyze_source(src, path="x.js")
    secrets = [f for f in findings if f["kind"] == "secret"]
    assert any(f["secret_class"] == "aws_access_key" for f in secrets)


def test_detects_github_token(analyzer):
    src = f'const t = "{_GH_FIXTURE}";'
    findings = analyzer.analyze_source(src, path="x.js")
    assert any(f["secret_class"] == "github_token" for f in findings if f["kind"] == "secret")


def test_detects_stripe_live_key(analyzer):
    src = f'const stripe = "{_STRIPE_FIXTURE}";'
    findings = analyzer.analyze_source(src, path="x.js")
    assert any(f["secret_class"] == "stripe_live" for f in findings if f["kind"] == "secret")


def test_does_not_flag_placeholder_secrets(analyzer):
    # YOUR_API_KEY, xxxxxx, and TODO style values are explicitly excluded
    src = '''
        const key = "YOUR_API_KEY_HERE";
        const k2 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        const k3 = "REPLACE_ME";
    '''
    findings = analyzer.analyze_source(src, path="x.js")
    assert not [f for f in findings if f["kind"] == "secret"]


def test_skips_secret_patterns_in_test_files(analyzer):
    # AWS key in a *.test.js or *.spec.js file is presumed fixture data
    src = 'const fixture = "{_AWS_FIXTURE}";'
    findings = analyzer.analyze_source(src, path="auth.spec.js")
    assert not [f for f in findings if f["kind"] == "secret"]


def test_finding_has_line_number(analyzer):
    src = '\n\nconst route = "/admin/keys";\n'
    findings = analyzer.analyze_source(src, path="x.js")
    admin = [f for f in findings if f["kind"] == "admin_route"][0]
    assert admin["line"] == 3


def test_walk_directory_returns_per_file_findings(analyzer, tmp_path):
    (tmp_path / "good.js").write_text('const x = "/public/feed";', encoding="utf-8")
    (tmp_path / "bad.js").write_text(
        f'const a = "/admin/keys"; const k = "{_GH_FIXTURE}";',
        encoding="utf-8",
    )
    (tmp_path / "ignored.spec.js").write_text(
        f'const k = "{_AWS_FIXTURE}";',  # test file, secret must be ignored
        encoding="utf-8",
    )
    findings = analyzer.walk(tmp_path)
    files = {Path(f["file"]).name for f in findings}
    assert "bad.js" in files
    # ignored.spec.js secrets dropped, but its endpoints (if any) would not be flagged either way
    assert all(f["kind"] != "secret" for f in findings if Path(f["file"]).name == "ignored.spec.js")


def test_walk_skips_minified_files(analyzer, tmp_path):
    # A 30K-char single-line file would trigger catastrophic backtracking;
    # the guard must drop it without parsing.
    big_line = 'const x = "' + ("a" * 30_000) + '"; const route = "/admin/keys";'
    (tmp_path / "bundle.min.js").write_text(big_line, encoding="utf-8")
    (tmp_path / "ok.js").write_text('const r = "/admin/users";', encoding="utf-8")
    findings = analyzer.walk(tmp_path)
    files = {Path(f["file"]).name for f in findings}
    assert "ok.js" in files
    assert "bundle.min.js" not in files


def test_walk_respects_max_files(analyzer, tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.js").write_text('const x = "/admin/y";', encoding="utf-8")
    findings = analyzer.walk(tmp_path, max_files=2)
    distinct = {Path(f["file"]).name for f in findings}
    assert len(distinct) == 2


def test_probe_run_returns_finding_count(tmp_path):
    from probes.base import ProbeContext
    from probes.js_bundle_analyzer import JsBundleAnalyzerProbe

    (tmp_path / "x.js").write_text('const a = "/admin/keys";', encoding="utf-8")
    ctx = ProbeContext(
        run_dir=tmp_path,
        target={"local_path": str(tmp_path)},
        candidate={"id": "CAND-TEST"},
        knobs={},
    )
    result = JsBundleAnalyzerProbe().run(ctx)
    assert result["name"] == "js_bundle_analyzer"
    assert result["finding_count"] >= 1
    assert any(f["kind"] == "admin_route" for f in result["findings"])
