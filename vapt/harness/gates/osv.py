"""OSV.dev cache + dedup gate: SQLite-backed package/vuln cache, cache-aware
queries with stale-on-failure semantics, and the dedup evidence writer.

The cache-only mode is the critical novelty-gate honesty rule: an offline
cache miss must NOT silently report no-known-duplicate. `_osv_dedup` records
an explicit error in that path so the gate refuses to claim novelty.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib import error, request

from atomic_io import write_json, write_text
from core import ROOT, _parse_time, rel


OSV_CACHE_FRESH_HOURS = 168  # 7 days; entries past this prefer fresh fetch but accept stale on failure


COMMON_VARIANT_TERMS = {
    "with",
    "from",
    "that",
    "this",
    "when",
    "where",
    "into",
    "over",
    "under",
    "using",
    "users",
    "user",
    "value",
    "values",
    "custom",
    "profile",
    "attribute",
    "attributes",
    "candidate",
    "issue",
    "bug",
    "leak",
    "bypass",
}


def _http_json(method: str, url: str, payload: dict[str, Any] | None, timeout: int) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "local-vapt-harness/1"}
    req = request.Request(url, data=body, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def osv_cache_path() -> Path:
    return ROOT / "vapt" / "harness" / "cache" / "osv.sqlite"


def _osv_cache_connect() -> sqlite3.Connection:
    path = osv_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS osv_package (
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (ecosystem, package, version)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS osv_vuln (
            vuln_id TEXT PRIMARY KEY,
            fetched_at TEXT NOT NULL,
            payload TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _osv_cache_age_hours(fetched_at: str) -> float | None:
    when = _parse_time(fetched_at)
    if not when:
        return None
    return max(0.0, (dt.datetime.now() - when).total_seconds() / 3600.0)


def _osv_cache_lookup_package(ecosystem: str, package: str, version: str) -> tuple[dict[str, Any] | None, float | None]:
    if not ecosystem or not package:
        return None, None
    with contextlib.closing(_osv_cache_connect()) as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM osv_package WHERE ecosystem=? AND package=? AND version=?",
            (ecosystem, package, version or ""),
        ).fetchone()
    if not row:
        return None, None
    try:
        payload = json.loads(row[1])
    except json.JSONDecodeError:
        return None, None
    return payload, _osv_cache_age_hours(row[0])


def _osv_cache_store_package(ecosystem: str, package: str, version: str, payload: dict[str, Any]) -> None:
    with contextlib.closing(_osv_cache_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO osv_package(ecosystem, package, version, fetched_at, payload) VALUES (?,?,?,?,?)",
            (ecosystem, package, version or "", dt.datetime.now().isoformat(timespec="seconds"), json.dumps(payload)),
        )
        conn.commit()


def _osv_cache_lookup_vuln(vuln_id: str) -> tuple[dict[str, Any] | None, float | None]:
    if not vuln_id:
        return None, None
    with contextlib.closing(_osv_cache_connect()) as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM osv_vuln WHERE vuln_id=?",
            (vuln_id.upper(),),
        ).fetchone()
    if not row:
        return None, None
    try:
        payload = json.loads(row[1])
    except json.JSONDecodeError:
        return None, None
    return payload, _osv_cache_age_hours(row[0])


def _osv_cache_store_vuln(vuln_id: str, payload: dict[str, Any]) -> None:
    with contextlib.closing(_osv_cache_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO osv_vuln(vuln_id, fetched_at, payload) VALUES (?,?,?)",
            (vuln_id.upper(), dt.datetime.now().isoformat(timespec="seconds"), json.dumps(payload)),
        )
        conn.commit()


def _osv_package_query(target: dict[str, Any], args: argparse.Namespace) -> dict[str, Any] | None:
    ecosystem = args.osv_ecosystem or target.get("osv_ecosystem")
    package = args.osv_package or target.get("osv_package")
    version = args.osv_version or target.get("version") or target.get("release") or ""
    if not ecosystem or not package:
        return None
    cached, age_h = _osv_cache_lookup_package(ecosystem, package, str(version))
    fresh_only = bool(getattr(args, "osv_fresh_only", False))
    cache_only = bool(getattr(args, "osv_cache_only", False))
    if cached is not None and not fresh_only and (cache_only or (age_h is not None and age_h < OSV_CACHE_FRESH_HOURS)):
        cached.setdefault("_cache", {})
        cached["_cache"] = {"hit": True, "age_hours": age_h, "stale": False, "source": "cache"}
        return cached
    if cache_only:
        return None
    payload: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": package}}
    if version:
        payload["version"] = str(version)
    try:
        result = _http_json("POST", "https://api.osv.dev/v1/query", payload, args.osv_timeout)
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        if cached is not None:
            cached["_cache"] = {"hit": True, "age_hours": age_h, "stale": True, "source": "cache", "network_error": str(exc)}
            return cached
        raise
    _osv_cache_store_package(ecosystem, package, str(version), result)
    result["_cache"] = {"hit": False, "age_hours": 0.0, "stale": False, "source": "network"}
    return result


def _osv_vuln_query(vuln_id: str, timeout: int, *, cache_only: bool = False, fresh_only: bool = False) -> dict[str, Any] | None:
    clean = str(vuln_id or "").strip()
    if not re.fullmatch(r"(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)", clean, flags=re.IGNORECASE):
        return None
    cached, age_h = _osv_cache_lookup_vuln(clean)
    if cached is not None and not fresh_only and (cache_only or (age_h is not None and age_h < OSV_CACHE_FRESH_HOURS)):
        cached["_cache"] = {"hit": True, "age_hours": age_h, "stale": False, "source": "cache"}
        return cached
    if cache_only:
        return None
    try:
        result = _http_json("GET", f"https://api.osv.dev/v1/vulns/{clean}", None, timeout)
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        if cached is not None:
            cached["_cache"] = {"hit": True, "age_hours": age_h, "stale": True, "source": "cache", "network_error": str(exc)}
            return cached
        raise
    _osv_cache_store_vuln(clean, result)
    result["_cache"] = {"hit": False, "age_hours": 0.0, "stale": False, "source": "network"}
    return result


def _osv_dedup(args: argparse.Namespace, target: dict[str, Any], cand: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    out_dir = run_dir / "evidence" / "dedup"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{cand['id']}_{stamp}_osv"
    cache_only = bool(getattr(args, "osv_cache_only", False))
    fresh_only = bool(getattr(args, "osv_fresh_only", False))
    cache_meta: dict[str, Any] = {"cache_only": cache_only, "fresh_only": fresh_only, "hits": 0, "misses": 0, "stale_hits": 0, "max_age_hours": 0.0}
    result: dict[str, Any] = {
        "checked_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source": "osv.dev",
        "package_query": None,
        "id_queries": [],
        "errors": [],
        "exact_alias_matches": [],
        "possible_text_matches": [],
        "cache": cache_meta,
    }

    def _record_cache(payload: dict[str, Any] | None) -> None:
        meta = (payload or {}).get("_cache") if payload else None
        if not meta:
            cache_meta["misses"] += 1
            return
        cache_meta["hits"] += 1
        if meta.get("stale"):
            cache_meta["stale_hits"] += 1
        age = meta.get("age_hours")
        if isinstance(age, (int, float)) and age > cache_meta["max_age_hours"]:
            cache_meta["max_age_hours"] = float(age)

    try:
        pkg = _osv_package_query(target, args)
        result["package_query"] = pkg
        _record_cache(pkg)
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        result["errors"].append(f"package_query: {exc}")
        cache_meta["misses"] += 1

    ids = set(re.findall(r"(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", " ".join(str(cand.get(key, "")) for key in ("cve", "notes", "title")), flags=re.IGNORECASE))
    for vuln_id in sorted(ids):
        try:
            vuln = _osv_vuln_query(vuln_id, args.osv_timeout, cache_only=cache_only, fresh_only=fresh_only)
            if vuln:
                result["id_queries"].append(vuln)
                result["exact_alias_matches"].append(vuln_id.upper())
                _record_cache(vuln)
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            result["errors"].append(f"{vuln_id}: {exc}")
            cache_meta["misses"] += 1

    text_terms = {
        term.lower()
        for term in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]{5,}",
            " ".join(str(cand.get(key, "")) for key in ("title", "weakness", "sink", "root_cause")),
        )
        if term.lower() not in COMMON_VARIANT_TERMS
    }
    vulns = (result.get("package_query") or {}).get("vulns", []) if result.get("package_query") else []
    for vuln in vulns:
        haystack = " ".join(
            str(vuln.get(key, ""))
            for key in ("id", "summary", "details")
        ).lower()
        aliases = [str(item).upper() for item in vuln.get("aliases", [])]
        if any(alias in ids for alias in aliases):
            result["exact_alias_matches"].extend(aliases)
        matched_terms = sorted(term for term in text_terms if term in haystack)
        if len(matched_terms) >= 2:
            result["possible_text_matches"].append(
                {
                    "id": vuln.get("id"),
                    "aliases": aliases,
                    "matched_terms": matched_terms[:10],
                    "summary": vuln.get("summary", ""),
                }
            )

    if cache_only and cache_meta["hits"] == 0 and not result["errors"]:
        result["errors"].append("cache_only:no_cache_entry — refusing to claim no-known-duplicate without a real lookup")
    write_json(base.with_suffix(".json"), result)
    cache_summary = (
        f"hits={cache_meta['hits']} misses={cache_meta['misses']} "
        f"stale={cache_meta['stale_hits']} max_age_h={cache_meta['max_age_hours']:.1f} "
        f"mode={'cache_only' if cache_only else ('fresh_only' if fresh_only else 'cache_then_network')}"
    )
    md = [
        f"# OSV Dedup Evidence: {cand['id']}",
        "",
        f"- Source: `osv.dev`",
        f"- Package query used: `{bool(result.get('package_query'))}`",
        f"- Exact alias matches: `{', '.join(sorted(set(result['exact_alias_matches']))) or 'none'}`",
        f"- Possible text matches: `{len(result['possible_text_matches'])}`",
        f"- Errors: `{'; '.join(result['errors']) or 'none'}`",
        f"- Cache: `{cache_summary}`",
        "",
        f"Raw JSON: `{rel(base.with_suffix('.json'))}`",
        "",
    ]
    for match in result["possible_text_matches"][:20]:
        md.extend(
            [
                f"## `{match.get('id')}`",
                "",
                f"- Aliases: `{', '.join(match.get('aliases', []))}`",
                f"- Terms: `{', '.join(match.get('matched_terms', []))}`",
                f"- Summary: {match.get('summary', '')}",
                "",
            ]
        )
    write_text(base.with_suffix(".md"), "\n".join(md))
    result["artifact"] = rel(base.with_suffix(".md"))
    return result
