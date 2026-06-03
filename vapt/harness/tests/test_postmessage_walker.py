"""Tests for the postMessage origin-check walker.

Per the Frans Rosén case study (`knowledge/case_studies/postmessage_origin.md`):
a `window.addEventListener("message", handler)` whose body does not perform a
strict-equality check on `event.origin` is a candidate for cross-origin
exploitation.

Classification:
  - ``strong_origin_check``  -> ``event.origin === "..."`` / ``=== someVar``
  - ``weak_origin_check``    -> indexOf / includes / endsWith / startsWith /
                                regex / startsWith on origin (substring
                                checks pass attacker-chosen subdomains)
  - ``no_origin_check``      -> handler body never references `.origin`

Only the bottom two are emitted as findings; the strong-checked handlers
are filtered out as the well-formed case.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def walker():
    from source.postmessage import PostMessageWalker
    return PostMessageWalker()


def test_strict_equality_origin_check_is_clean(walker):
    src = '''
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.example.com") return;
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert findings == []


def test_handler_without_origin_reference_is_flagged(walker):
    src = '''
        window.addEventListener("message", function(event) {
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "no_origin_check"


def test_handler_using_indexOf_is_weak(walker):
    src = '''
        window.addEventListener("message", function(event) {
            if (event.origin.indexOf("trusted.com") === -1) return;
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "weak_origin_check"
    assert "indexOf" in findings[0]["evidence"]


def test_handler_using_endsWith_is_weak(walker):
    src = '''
        addEventListener("message", (event) => {
            if (!event.origin.endsWith(".example.com")) return;
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "weak_origin_check"


def test_handler_using_regex_on_origin_is_weak(walker):
    src = '''
        window.addEventListener("message", function(event) {
            if (!/example\\.com/.test(event.origin)) return;
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "weak_origin_check"


def test_arrow_function_handler_supported(walker):
    src = '''
        window.addEventListener("message", (e) => {
            handleData(e.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "no_origin_check"


def test_multiple_handlers_each_classified(walker):
    src = '''
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://safe") return;
            doSafe(event.data);
        });
        window.addEventListener("message", function(event) {
            doUnsafe(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "no_origin_check"
    assert findings[0]["line"] >= 5  # second handler is on a later line


def test_finding_carries_handler_snippet(walker):
    src = '\n\nwindow.addEventListener("message", function(event) {\n    sendBack(event.data);\n});\n'
    findings = walker.analyze_source(src, path="x.js")
    f = findings[0]
    assert f["line"] == 3
    assert "addEventListener" in f["snippet"]
    assert "sendBack" in f["snippet"]


def test_test_path_findings_dropped(walker):
    src = '''
        window.addEventListener("message", function(event) {
            doThing(event.data);
        });
    '''
    findings = walker.analyze_source(src, path="postmessage.test.js")
    assert findings == []


def test_named_handler_with_strict_check_is_clean(walker):
    # Common Discourse pattern: handler is a named function exported
    # elsewhere in the file, and validates origin against an array of
    # trusted origins via Array.prototype.includes (strict equality).
    src = '''
        const TRUSTED = ["https://a.example.com", "https://b.example.com"];

        export function handleEmbedMessage(event) {
            if (!TRUSTED.includes(event.origin)) return;
            doThing(event.data);
        }

        target.addEventListener("message", handleEmbedMessage);
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert findings == []


def test_named_handler_with_no_check_is_flagged(walker):
    src = '''
        export function handleEmbedMessage(event) {
            doThing(event.data);
        }
        target.addEventListener("message", handleEmbedMessage);
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert len(findings) == 1
    assert findings[0]["kind"] == "no_origin_check"


def test_serviceworker_receiver_is_suppressed(walker):
    # ServiceWorker messages are same-origin; not a cross-origin attack
    # surface even when the handler ignores .origin.
    src = '''
        navigator.serviceWorker.addEventListener("message", (event) => {
            router.transitionTo(event.data.url);
        });
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert findings == []


def test_messagechannel_port_receiver_is_suppressed(walker):
    src = '''
        messageChannel.port1.onmessage = () => { callback(); };
    '''
    findings = walker.analyze_source(src, path="x.js")
    assert findings == []


def test_named_receiver_worker_is_suppressed(walker):
    src = 'myWorker.onmessage = (e) => { handle(e.data); };'
    findings = walker.analyze_source(src, path="x.js")
    assert findings == []


def test_walk_directory(walker, tmp_path):
    (tmp_path / "ok.js").write_text(
        'window.addEventListener("message", function(e){ if (e.origin !== "x") return; });',
        encoding="utf-8",
    )
    (tmp_path / "bad.js").write_text(
        'window.addEventListener("message", function(e){ handle(e.data); });',
        encoding="utf-8",
    )
    findings = walker.walk(tmp_path)
    files = {Path(f["file"]).name for f in findings}
    assert "bad.js" in files
    assert "ok.js" not in files


def test_probe_run_returns_findings(tmp_path):
    from probes.base import ProbeContext
    from probes.postmessage_origin import PostMessageOriginProbe

    (tmp_path / "x.js").write_text(
        'window.addEventListener("message", function(e){ run(e.data); });',
        encoding="utf-8",
    )
    ctx = ProbeContext(
        run_dir=tmp_path,
        target={"local_path": str(tmp_path)},
        candidate={"id": "CAND-TEST"},
        knobs={},
    )
    result = PostMessageOriginProbe().run(ctx)
    assert result["name"] == "postmessage_origin"
    assert result["finding_count"] == 1
    assert result["findings"][0]["kind"] == "no_origin_check"
