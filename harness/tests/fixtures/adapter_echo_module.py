#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--module-id", required=True)
    parser.add_argument("--local-name", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    result = {
        "module": args.local_name,
        "started_at": now,
        "finished_at": now,
        "verdict": "no_findings",
        "check_count": 1,
        "finding_candidates": [],
        "checks": [
            {
                "name": "fixture_positive_control",
                "expectation": "allow",
                "expectation_passed": True,
                "recorded_at": now,
            }
        ],
        "mutation_coverage": {
            "module_id": args.module_id,
            "local_name": args.local_name,
            "families": [
                {
                    "id": "role_cross_product",
                    "title": "Role Cross-Product",
                    "variants_executed": [
                        "viewer_to_owner_object",
                        "viewer_to_peer_object",
                        "editor_to_foreign_object",
                        "admin_to_foreign_org",
                        "anonymous_to_private_object",
                    ],
                    "variants_skipped": [],
                }
            ],
            "summary": {
                "variants_planned": 5,
                "variants_executed": 5,
                "variants_skipped": 0,
            },
        },
    }
    (out_dir / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text("# Fixture Module\n\n- Verdict: `no_findings`\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
