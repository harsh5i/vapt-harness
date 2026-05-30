#!/usr/bin/env python3
"""Pre-commit guard: refuse staged files under vapt/engagements/<id>/.

Run as a pre-commit hook (see .pre-commit-config.yaml). Receives staged
paths as argv and returns non-zero if any path falls under a per-target
engagement directory. The only paths under vapt/engagements/ that are
permitted to enter the repo are the .gitkeep marker and any future shared
files at the engagements/ root itself.

Why: vapt/engagements/<id>/ holds real bug-bounty target data (advisory
clones, run evidence, PoCs, reports) that must never leave the operator
machine. `.gitignore` already excludes those paths, but `git add -f` or a
renamed subtree can bypass the ignore. This hook is the second line of
defense and is fail-closed.
"""
from __future__ import annotations

import re
import sys

# vapt/engagements/<anything>/<rest> — anything per-target stays local.
ENGAGEMENT_RE = re.compile(r"^vapt/engagements/[^/]+/.+")

# Paths under engagements/ that are explicitly allowed to be tracked.
ALLOWLIST = {
    "vapt/engagements/.gitkeep",
}


def main(argv: list[str]) -> int:
    blocked = []
    for path in argv[1:]:
        path = path.strip()
        if not path:
            continue
        if path in ALLOWLIST:
            continue
        if ENGAGEMENT_RE.match(path):
            blocked.append(path)
    if blocked:
        print("ERROR: engagement target data must stay local. Blocked staged paths:")
        for path in blocked:
            print(f"  {path}")
        print(
            "\nIf this is a captive fixture, move it under "
            "vapt/harness/fixtures/. If it is genuinely shared scaffolding, "
            "add the exact path to ALLOWLIST in scripts/check_engagement_paths.py."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
