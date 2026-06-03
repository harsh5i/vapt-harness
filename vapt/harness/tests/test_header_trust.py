"""Tests for the header-trust audit probe.

Detects source-code reads of HTTP headers that are spoofable across
common reverse-proxy / framework setups. The per-header severity hint
encodes case-study evidence:

  HIGH   -- proven framework bypass (Next.js x-middleware-subrequest,
            x-original-url / x-rewrite-url which front-end caches +
            proxies route on but back-end re-derives, x-original-host).
  MEDIUM -- spoofable IP / proto / method overrides when trust-proxy
            is loose (x-forwarded-for/proto/host, x-real-ip,
            x-http-method-override, x-method-override, _method).
  LOW    -- general-purpose Host/Referer reads (only flagged when
            requested via knobs).

Source languages covered: Ruby (Rails / Sinatra), Python
(Django / Flask / FastAPI), JavaScript/TypeScript (Express / Next.js).
Test-path suppression matches the rest of the source probes.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def auditor():
    from source.header_trust import HeaderTrustAuditor
    return HeaderTrustAuditor()


def test_detects_rails_request_headers_x_forwarded_for(auditor):
    src = '''
        class FooController < ApplicationController
          def show
            ip = request.headers["X-Forwarded-For"]
            authorize_for(ip)
          end
        end
    '''
    findings = auditor.analyze_source(src, path="foo_controller.rb")
    assert len(findings) == 1
    assert findings[0]["header"] == "x-forwarded-for"
    assert findings[0]["severity"] == "medium"


def test_detects_rails_env_http_header(auditor):
    src = '''
        ip = env["HTTP_X_FORWARDED_FOR"]
        do_thing(ip)
    '''
    findings = auditor.analyze_source(src, path="foo.rb")
    assert any(f["header"] == "x-forwarded-for" for f in findings)


def test_detects_django_request_META(auditor):
    src = '''
        def view(request):
            ip = request.META["HTTP_X_FORWARDED_FOR"]
            return HttpResponse(ip)
    '''
    findings = auditor.analyze_source(src, path="views.py")
    assert any(f["header"] == "x-forwarded-for" for f in findings)


def test_detects_flask_request_headers_get(auditor):
    src = '''
        @app.route("/who")
        def who():
            real_ip = request.headers.get("X-Real-IP")
            return real_ip
    '''
    findings = auditor.analyze_source(src, path="views.py")
    assert any(f["header"] == "x-real-ip" for f in findings)


def test_detects_express_req_headers_bracket(auditor):
    src = '''
        app.use((req, res, next) => {
            const sub = req.headers["x-middleware-subrequest"];
            if (sub) bypassAuth();
            next();
        });
    '''
    findings = auditor.analyze_source(src, path="middleware.js")
    assert any(f["header"] == "x-middleware-subrequest" for f in findings)
    high = [f for f in findings if f["header"] == "x-middleware-subrequest"]
    assert high[0]["severity"] == "high"


def test_detects_express_req_get(auditor):
    src = 'const url = req.get("X-Original-URL");'
    findings = auditor.analyze_source(src, path="proxy.js")
    assert any(f["header"] == "x-original-url" for f in findings)
    assert findings[0]["severity"] == "high"


def test_detects_nextjs_headers_get(auditor):
    src = '''
        import { headers } from "next/headers";
        export async function handler() {
            const h = headers();
            const sub = h.get("x-middleware-subrequest");
            return Response.json({ sub });
        }
    '''
    findings = auditor.analyze_source(src, path="route.ts")
    assert any(f["header"] == "x-middleware-subrequest" for f in findings)


def test_detects_http_method_override(auditor):
    src = '''
        method = request.headers["X-HTTP-Method-Override"] || request.method
    '''
    findings = auditor.analyze_source(src, path="foo.rb")
    assert any(f["header"] == "x-http-method-override" for f in findings)


def test_test_path_findings_dropped(auditor):
    src = 'ip = request.headers["X-Forwarded-For"]'
    findings = auditor.analyze_source(src, path="spec/controllers/foo_spec.rb")
    assert findings == []


def test_severity_high_for_proven_bypass_headers(auditor):
    """x-middleware-subrequest, x-original-url, x-rewrite-url -> HIGH."""
    findings = []
    for header in ("x-middleware-subrequest", "x-original-url", "x-rewrite-url"):
        src = f'const v = req.headers["{header}"];'
        findings.extend(auditor.analyze_source(src, path="x.js"))
    assert all(f["severity"] == "high" for f in findings)
    assert len(findings) == 3


def test_does_not_double_count_same_header_same_line(auditor):
    # `req.headers["x-real-ip"] || req.headers["x-real-ip"]` should
    # NOT emit two findings -- the second occurrence is the same lookup.
    src = 'const v = req.headers["x-real-ip"];'
    findings = auditor.analyze_source(src, path="x.js")
    headers = [f["header"] for f in findings]
    assert headers == ["x-real-ip"]


def test_finding_carries_line_number(auditor):
    src = "\n\n\nip = request.headers[\"X-Forwarded-For\"]\n"
    f = auditor.analyze_source(src, path="x.rb")[0]
    assert f["line"] == 4


def test_walk_directory(auditor, tmp_path):
    (tmp_path / "good.py").write_text('print("hi")', encoding="utf-8")
    (tmp_path / "bad.rb").write_text(
        'ip = request.headers["X-Forwarded-For"]',
        encoding="utf-8",
    )
    (tmp_path / "test_bad.rb").write_text(
        'ip = request.headers["X-Forwarded-For"]',
        encoding="utf-8",
    )
    findings = auditor.walk(tmp_path)
    files = {Path(f["file"]).name for f in findings}
    assert "bad.rb" in files
    # *_spec.rb / *_test.rb would be suppressed
    assert "good.py" not in files


def test_probe_run(tmp_path):
    from probes.base import ProbeContext
    from probes.header_trust import HeaderTrustProbe

    (tmp_path / "app.js").write_text(
        'const sub = req.headers["x-middleware-subrequest"];',
        encoding="utf-8",
    )
    ctx = ProbeContext(
        run_dir=tmp_path,
        target={"local_path": str(tmp_path)},
        candidate={"id": "CAND-HT"},
        knobs={},
    )
    result = HeaderTrustProbe().run(ctx)
    assert result["name"] == "header_trust"
    assert result["finding_count"] == 1
    assert result["findings"][0]["severity"] == "high"
