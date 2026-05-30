"""Unit tests for the fail-closed scope + ROE authorization gate."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gates.authorization import (  # noqa: E402
    AuthorizationError,
    authorize,
    evaluate,
)


IN_SCOPE = {"id": "demo", "scope_hosts": ["example.com"], "active_scan_allowed": False}
IN_SCOPE_ACTIVE = {"id": "demo", "scope_hosts": ["example.com"], "active_scan_allowed": True}


def test_passive_scanner_in_scope_allowed():
    assert evaluate(IN_SCOPE, "https://example.com/path", "screenshot")["decision"] == "allow"


def test_active_scanner_requires_roe():
    rec = evaluate(IN_SCOPE, "https://example.com", "zap-full")
    assert rec["decision"] == "deny"
    assert "active_scan_allowed" in rec["reason"]


def test_active_scanner_with_roe_allowed():
    assert evaluate(IN_SCOPE_ACTIVE, "https://example.com", "zap-full")["decision"] == "allow"


def test_out_of_scope_host_denied():
    rec = evaluate(IN_SCOPE_ACTIVE, "https://evil.com", "zap-full")
    assert rec["decision"] == "deny"
    assert "not in declared scope_hosts" in rec["reason"]


def test_no_scope_declared_fails_closed():
    rec = evaluate({"id": "x"}, "https://example.com", "sqlmap")
    assert rec["decision"] == "deny"
    assert "no scope_hosts" in rec["reason"]


def test_subdomain_matches_parent_scope():
    assert evaluate(IN_SCOPE_ACTIVE, "https://api.example.com", "zap-baseline")["decision"] == "allow"


def test_explicit_denylist_takes_precedence():
    target = {
        "id": "x",
        "scope_hosts": ["example.com"],
        "out_of_scope_hosts": ["admin.example.com"],
        "active_scan_allowed": True,
    }
    rec = evaluate(target, "https://admin.example.com", "zap-full")
    assert rec["decision"] == "deny"
    assert "out_of_scope_hosts" in rec["reason"]


def test_wildcard_scope_pattern():
    target = {"id": "x", "scope_hosts": ["*.example.com"], "active_scan_allowed": True}
    assert evaluate(target, "https://a.example.com", "zap-full")["decision"] == "allow"
    assert evaluate(target, "https://example.com", "zap-full")["decision"] == "allow"


def test_unparseable_host_denied():
    rec = evaluate(IN_SCOPE_ACTIVE, "", "zap-full")
    assert rec["decision"] == "deny"
    assert "no host" in rec["reason"]


def test_static_scanner_not_treated_as_active():
    # a non-listed scanner name is passive: in-scope is enough, no ROE needed
    assert evaluate(IN_SCOPE, "https://example.com", "semgrep")["decision"] == "allow"


def test_authorize_raises_and_writes_deny_record(tmp_path):
    with pytest.raises(AuthorizationError):
        authorize(tmp_path, IN_SCOPE, "https://example.com", "zap-full")
    records = list((tmp_path / "logs" / "authorizations").glob("*.json"))
    assert len(records) == 1
    rec = json.loads(records[0].read_text())
    assert rec["decision"] == "deny"


def test_authorize_allows_and_writes_allow_record(tmp_path):
    rec = authorize(tmp_path, IN_SCOPE_ACTIVE, "https://example.com", "zap-full")
    assert rec["decision"] == "allow"
    records = list((tmp_path / "logs" / "authorizations").glob("*_allow.json"))
    assert len(records) == 1


def test_host_parsing_without_scheme():
    assert evaluate(IN_SCOPE_ACTIVE, "example.com:8443", "zap-full")["decision"] == "allow"
