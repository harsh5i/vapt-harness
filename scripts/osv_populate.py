"""Populate the local OSV cache for the npm deps discovered under a target.

Uses OSV.dev's batch endpoint (`/v1/querybatch`, up to 1000 deps per
request). Network-required; intended to be run before
`js_dep_audit` against a fresh engagement so the offline cache is warm.

Usage:
    python3 scripts/osv_populate.py <target_root> [<target_root> ...]
        [--ecosystem npm] [--chunk 500] [--db <path>]

Stores results in the same SQLite cache `gates/osv.py` already uses
(`vapt/harness/cache/osv.sqlite`). Idempotent: re-runs upsert per
(ecosystem, package, version).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path
from urllib import error, request

# Make `source.js_deps` importable regardless of where the script is run from.
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent / "vapt" / "harness"
sys.path.insert(0, str(HARNESS))

from source.js_deps import LockfileParser  # noqa: E402


def fetch_batch(queries: list[dict], *, timeout: int) -> list[dict]:
    payload = {"queries": queries}
    req = request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "local-vapt-harness/1"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()).get("results") or []


def upsert(conn: sqlite3.Connection, ecosystem: str, name: str, version: str, payload: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO osv_package(ecosystem,package,version,fetched_at,payload) VALUES (?,?,?,?,?)",
        (ecosystem, name, version, dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), json.dumps(payload)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="One or more target source roots to scan for lockfiles")
    parser.add_argument("--ecosystem", default="npm", help="OSV ecosystem (default: npm)")
    parser.add_argument("--chunk", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--db", default=str(HARNESS / "cache" / "osv.sqlite"))
    args = parser.parse_args()

    # Discover unique (name, version) pairs across all roots.
    pairs: set[tuple[str, str]] = set()
    for root in args.roots:
        for dep in LockfileParser().discover(Path(root)):
            pairs.add((dep.name, dep.version))
    items = sorted(pairs)
    if not items:
        print("No deps discovered. Nothing to do.")
        return 0

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS osv_package (
            ecosystem TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL,
            fetched_at TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY (ecosystem, package, version)
        )
        """
    )

    total_vuln_ids = 0
    for start in range(0, len(items), args.chunk):
        batch = items[start:start + args.chunk]
        queries = [{"package": {"ecosystem": args.ecosystem, "name": n}, "version": v} for n, v in batch]
        try:
            results = fetch_batch(queries, timeout=args.timeout)
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            print(f"batch {start}: ERROR {exc}", file=sys.stderr)
            continue
        for (n, v), r in zip(batch, results):
            vulns = r.get("vulns") or []
            payload = {"vulns": [{"id": x.get("id")} for x in vulns if x.get("id")]}
            total_vuln_ids += len(payload["vulns"])
            upsert(conn, args.ecosystem, n, v, payload)
        conn.commit()
        print(f"batch {start}: {len(batch)} queried, running vuln total {total_vuln_ids}")

    print(f"Done. {total_vuln_ids} vuln IDs across {len(items)} unique deps. Cache: {db_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
