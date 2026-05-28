"""Autonomous target discovery.

Sweeps the GHSA database for recent high-severity advisories, compares
the affected packages against the current set of watched targets under
`vapt/bug_bounties/*/targets/*.yaml`, and proposes new candidate targets
to a discovery queue at `vapt/harness/queue/discovery/`.

Each proposal is a JSON file named
`prop_<ghsa_id>_<package_safe>.json`. Operators promote proposals into
real watches via `harness discovery-claim`, which then call the existing
`watch-add` plumbing.

No proposal becomes a campaign until an operator claims it. The
substrate refuses to bypass this gate.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib import error, request


GHSA_BROWSE_URL = "https://api.github.com/advisories"
DISCOVERY_QUEUE_DIRNAME = "discovery"
HARNESS_VERSION_TAG = "phase5-move4"


_VERSION_TOKEN_RE = re.compile(r"[<>=!~]+\s*[\dvV][\w.\-]*")


def _ghsa_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "local-vapt-harness-discovery/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_recent_advisories(
    *,
    severity_floor: str = "high",
    since_days: int = 7,
    per_page: int = 30,
    max_pages: int = 4,
    token: str | None = None,
    timeout: int = 20,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Page through GitHub Security Advisories API.

    Returns (advisories, errors). Errors are non-fatal per-page failures.
    """
    if severity_floor not in {"low", "medium", "moderate", "high", "critical"}:
        raise ValueError(f"unknown severity_floor: {severity_floor}")
    severity_floor = "medium" if severity_floor == "moderate" else severity_floor
    since_cutoff = dt.datetime.utcnow() - dt.timedelta(days=since_days)
    headers = _ghsa_headers(token)
    out: list[dict[str, Any]] = []
    errors_seen: list[str] = []
    for page in range(1, max_pages + 1):
        url = (
            f"{GHSA_BROWSE_URL}?severity={severity_floor}"
            f"&sort=published&direction=desc"
            f"&per_page={per_page}"
            f"&page={page}"
        )
        req = request.Request(url, headers=headers)
        try:
            with request.urlopen(req, timeout=timeout) as response:
                rows = json.loads(response.read().decode("utf-8"))
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            errors_seen.append(f"page {page}: {exc}")
            break
        if not isinstance(rows, list) or not rows:
            break
        page_kept = 0
        oldest_kept = None
        for row in rows:
            published_str = row.get("published_at") or row.get("updated_at") or ""
            try:
                published_dt = dt.datetime.strptime(published_str.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
            except (TypeError, ValueError):
                continue
            if published_dt < since_cutoff:
                continue
            out.append(row)
            page_kept += 1
            oldest_kept = published_dt if oldest_kept is None else min(oldest_kept, published_dt)
        if page_kept == 0:
            break
        if oldest_kept is not None and oldest_kept < since_cutoff:
            break
        if len(rows) < per_page:
            break
    return out, errors_seen


def watched_packages(target_profiles: Iterable[Path]) -> set[tuple[str, str]]:
    """Return {(ecosystem_lower, package_lower)} for everything already watched."""
    import yaml  # type: ignore

    watched: set[tuple[str, str]] = set()
    for path in target_profiles:
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            continue
        ecosystem = str(data.get("osv_ecosystem") or "").lower()
        package = str(data.get("osv_package") or "").lower()
        if ecosystem and package:
            watched.add((ecosystem, package))
        for watch in data.get("watch", []) or []:
            if not isinstance(watch, dict):
                continue
            e = str(watch.get("ecosystem") or "").lower()
            p = str(watch.get("package") or "").lower()
            if e and p:
                watched.add((e, p))
    return watched


def advisory_packages(advisory: dict[str, Any]) -> list[tuple[str, str, str | None]]:
    """Extract (ecosystem, package, vulnerable_version_range) tuples."""
    out: list[tuple[str, str, str | None]] = []
    for vuln in advisory.get("vulnerabilities") or []:
        pkg = (vuln or {}).get("package") or {}
        ecosystem = str(pkg.get("ecosystem") or "").lower()
        name = str(pkg.get("name") or "").lower()
        if not ecosystem or not name:
            continue
        ranges = str(vuln.get("vulnerable_version_range") or "")
        out.append((ecosystem, name, ranges or None))
    return out


def _package_safe_slug(ecosystem: str, package: str) -> str:
    return f"{ecosystem}_{re.sub(r'[^a-z0-9._-]+', '_', package.lower())}"


def propose_targets(
    advisories: list[dict[str, Any]],
    watched: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Compute proposals: advisories that touch packages we don't watch."""
    proposals: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()
    for adv in advisories:
        ghsa_id = adv.get("ghsa_id") or adv.get("id") or ""
        severity = (adv.get("severity") or "").lower()
        published = adv.get("published_at") or adv.get("updated_at") or ""
        summary = adv.get("summary") or ""
        cves = [
            (i or {}).get("value")
            for i in (adv.get("identifiers") or [])
            if (i or {}).get("type") == "CVE"
        ]
        html_url = adv.get("html_url") or ""
        for ecosystem, package, version_range in advisory_packages(adv):
            if (ecosystem, package) in watched:
                continue
            key = (ghsa_id, ecosystem, package)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            proposals.append(
                {
                    "ghsa_id": ghsa_id,
                    "cves": [c for c in cves if c],
                    "severity": severity,
                    "published": published,
                    "ecosystem": ecosystem,
                    "package": package,
                    "vulnerable_range": version_range,
                    "summary": summary,
                    "html_url": html_url,
                    "proposal_slug": f"prop_{ghsa_id}_{_package_safe_slug(ecosystem, package)}.json",
                    "source": "auto-discovery",
                    "harness_version": HARNESS_VERSION_TAG,
                }
            )
    return proposals


def write_proposals(proposals: list[dict[str, Any]], queue_dir: Path) -> tuple[int, int]:
    """Persist new proposals into queue_dir/discovery. Returns (written, skipped_existing)."""
    target = queue_dir / DISCOVERY_QUEUE_DIRNAME
    target.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    for prop in proposals:
        slug = prop["proposal_slug"]
        path = target / slug
        if path.exists():
            skipped += 1
            continue
        prop_to_write = {**prop, "first_seen_at": dt.datetime.now().isoformat(timespec="seconds"), "status": "open"}
        path.write_text(json.dumps(prop_to_write, indent=2, sort_keys=False) + "\n")
        written += 1
    return written, skipped


def list_proposals(queue_dir: Path, include_claimed: bool = False) -> list[dict[str, Any]]:
    target = queue_dir / DISCOVERY_QUEUE_DIRNAME
    if not target.exists():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(target.glob("prop_*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not include_claimed and data.get("status") != "open":
            continue
        data["_path"] = str(path)
        out.append(data)
    return out


def claim_proposal(queue_dir: Path, slug: str, *, claimed_by: str, decision: str = "claim", note: str = "") -> dict[str, Any]:
    target = queue_dir / DISCOVERY_QUEUE_DIRNAME / slug
    if not target.exists():
        raise FileNotFoundError(str(target))
    data = json.loads(target.read_text())
    if data.get("status") != "open":
        raise RuntimeError(f"proposal already {data.get('status')}")
    data["status"] = "claimed" if decision == "claim" else decision
    data["claimed_by"] = claimed_by
    data["claimed_at"] = dt.datetime.now().isoformat(timespec="seconds")
    if note:
        data.setdefault("notes", []).append(note)
    target.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    return data
