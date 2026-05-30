"""Fail-closed scope + ROE authorization for network-touching scans.

Self-contained (stdlib only) so it is unit-testable in isolation and safe to
import before the monolith is decomposed. The harness calls `authorize()` at the
top of every scanner command; `evaluate()` is the pure decision function tests
target directly.

Target-profile fields consumed (all optional, absence fails closed):
  scope_hosts:          list of hostnames/domains scanning is permitted against
  out_of_scope_hosts:   explicit deny list (takes precedence over scope_hosts)
  active_scan_allowed:  bool; required true for active scanners (ZAP, sqlmap)
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Scanners that actively send attack traffic. Require active_scan_allowed: true.
ACTIVE_SCANNERS = frozenset({"zap-baseline", "zap-full", "sqlmap"})


class AuthorizationError(Exception):
    """Raised when a scan is refused. Carries the structured refusal record."""

    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record
        super().__init__(record.get("reason", "authorization denied"))


def _host_of(target_url: str | None) -> str | None:
    if not target_url:
        return None
    raw = target_url if "://" in target_url else f"//{target_url}"
    host = (urlparse(raw).hostname or "").strip().lower()
    return host or None


def _norm(patterns: Any) -> list[str]:
    return [str(p).strip().lower() for p in (patterns or []) if str(p).strip()]


def _host_matches(host: str, patterns: list[str]) -> bool:
    """Exact host, parent-domain suffix, or explicit wildcard (*.example.com)."""
    for pat in patterns:
        if pat.startswith("*."):
            base = pat[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == pat or host.endswith("." + pat):
            return True
    return False


def evaluate(target: dict[str, Any], target_url: str | None, scanner: str) -> dict[str, Any]:
    """Pure scope/ROE decision. Returns a record dict; never raises, never I/O."""
    active = scanner in ACTIVE_SCANNERS
    host = _host_of(target_url)
    record: dict[str, Any] = {
        "ts": dt.datetime.now().isoformat(timespec="seconds"),
        "scanner": scanner,
        "active": active,
        "target_id": target.get("id"),
        "target_url": target_url,
        "host": host,
        "decision": "deny",
        "reason": None,
    }

    scope_hosts = _norm(target.get("scope_hosts"))
    deny_hosts = _norm(target.get("out_of_scope_hosts"))

    if host is None:
        record["reason"] = "no host could be parsed from target_url"
        return record
    if not scope_hosts:
        record["reason"] = (
            "target profile declares no scope_hosts; network scanning refused (fail-closed)"
        )
        return record
    if _host_matches(host, deny_hosts):
        record["reason"] = f"host '{host}' matches out_of_scope_hosts"
        return record
    if not _host_matches(host, scope_hosts):
        record["reason"] = f"host '{host}' is not in declared scope_hosts"
        return record
    if active and not bool(target.get("active_scan_allowed", False)):
        record["reason"] = (
            f"active scanner '{scanner}' requires active_scan_allowed: true in the target profile"
        )
        return record

    record["decision"] = "allow"
    record["reason"] = "in scope" + (" and active scanning permitted" if active else "")
    return record


def write_record(run_dir: Path, record: dict[str, Any]) -> Path:
    """Persist a pre/post authorization record under the run's logs."""
    log_dir = Path(run_dir) / "logs" / "authorizations"
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_ts = str(record.get("ts", "")).replace(":", "").replace("-", "")
    path = log_dir / f"{safe_ts}_{record['scanner']}_{record['decision']}.json"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path


def authorize(run_dir: Path, target: dict[str, Any], target_url: str | None, scanner: str) -> dict[str, Any]:
    """Evaluate, persist the pre-exec record, and raise on deny (fail-closed)."""
    record = evaluate(target, target_url, scanner)
    write_record(run_dir, record)
    if record["decision"] != "allow":
        raise AuthorizationError(record)
    return record
