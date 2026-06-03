"""JS bundle / source static analyzer.

Static, no-auth-needed surface extractor for JavaScript source or built
bundles. Surfaces three classes of leads for an operator/LLM auditor to
confirm; the analyzer does NOT decide exploitability.

Finding kinds:
  - ``endpoint``:    root-relative ``/api/...`` URL constant.
  - ``admin_route``: string literal containing ``/admin/`` or ``/internal/``
                     (highest-EV class; admin reachable from a client bundle
                     means the route is either client-gated only or
                     reachable from an unprivileged user agent).
  - ``secret``:      high-confidence pattern for a known credential format
                     (AWS / GitHub PAT / Stripe live / JWT). Generic
                     ``apiKey = "..."`` heuristics are intentionally NOT
                     included here -- noise > signal at scale.

Negative controls (built in, on by design):
  - Placeholder values (``YOUR_*``, ``REPLACE_ME``, ``xxxx...``, ``...``)
    are dropped before secret findings are emitted.
  - Files matching ``*.spec.js`` / ``*.test.js`` / ``__tests__/*`` /
    ``fixtures/*`` are presumed to carry fixture credentials; secret
    findings from those paths are suppressed (endpoints and admin routes
    still surface).
"""
from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Iterable

# --- regex catalogue -------------------------------------------------------

# String literals: separate patterns per quote type, "unrolled loop" form
# `[^X\\]*(?:\\.[^X\\]*)*` -- non-backtracking and safe on adversarial input.
# Backtick template literals lose their `${...}` interpolations.
_STR_SINGLE = re.compile(r"'(?P<body>[^'\\\n]*(?:\\.[^'\\\n]*)*)'")
_STR_DOUBLE = re.compile(r'"(?P<body>[^"\\\n]*(?:\\.[^"\\\n]*)*)"')
_STR_BACKTICK = re.compile(r"`(?P<body>[^`\\]*(?:\\.[^`\\]*)*)`", re.DOTALL)
_STRING_LITERALS = (_STR_SINGLE, _STR_DOUBLE, _STR_BACKTICK)

# Root-relative API path. We require /api/ to keep precision; bare /foo
# strings are too noisy across an Ember/Rails codebase.
_API_PATH_RE = re.compile(r"^/api/[A-Za-z0-9_\-./{}:]+$")

# Admin / internal route.
_ADMIN_ROUTE_RE = re.compile(r"^/(?:admin|internal|_internal|_private)/[A-Za-z0-9_\-./{}:]*$")

# High-confidence secret signatures.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"^AKIA[0-9A-Z]{16}$")),
    ("github_token", re.compile(r"^gh[pousr]_[A-Za-z0-9]{36,251}$")),
    ("stripe_live", re.compile(r"^sk_live_[A-Za-z0-9]{16,99}$")),
    ("stripe_test", re.compile(r"^sk_test_[A-Za-z0-9]{16,99}$")),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")),
    ("slack_token", re.compile(r"^xox[abprs]-[A-Za-z0-9\-]{10,}$")),
    ("google_api_key", re.compile(r"^AIza[0-9A-Za-z\-_]{35}$")),
]

# Placeholder detection: any literal matching these is dropped from secret findings.
_PLACEHOLDER_HINTS = (
    "your_", "your-", "replace", "example", "todo", "xxxx",
    "placeholder", "fixme", "changeme",
)

# File-path hints that mean "this is test/fixture code, secrets do not count".
_TEST_PATH_HINTS = (
    ".spec.js", ".test.js", ".spec.ts", ".test.ts",
    "/__tests__/", "/__mocks__/", "/fixtures/", "/test/", "/tests/",
    "/spec/", "/cypress/",
)


def _is_test_path(path: str) -> bool:
    lowered = path.lower().replace(os.sep, "/")
    return any(h in lowered for h in _TEST_PATH_HINTS)


def _is_placeholder(body: str) -> bool:
    low = body.lower()
    return any(h in low for h in _PLACEHOLDER_HINTS)


def _line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


# --- analyzer --------------------------------------------------------------

@dataclasses.dataclass
class JsBundleAnalyzer:
    """Static scanner. Stateless; reusable across files."""

    # Cap individual-file size to avoid soak on accidentally bundled megabytes.
    max_file_bytes: int = 5 * 1024 * 1024
    # Files whose longest line exceeds this are presumed minified bundles --
    # skipped because the string-literal regex catastrophically backtracks on
    # 100KB single-line inputs. Minified bundles need a separate code path.
    max_line_chars: int = 20_000

    def analyze_source(self, src: str, path: str = "<memory>") -> list[dict]:
        findings: list[dict] = []
        is_test = _is_test_path(path)

        matches = []
        for pattern in _STRING_LITERALS:
            for m in pattern.finditer(src):
                matches.append((m.start("body"), m.group("body")))
        # Process in source order for deterministic line numbers; duplicates
        # at the same offset would mean overlapping quote types (impossible).
        matches.sort()

        for offset, body in matches:
            if not body:
                continue
            line = _line_of(src, offset)

            # Order matters: admin route check beats generic /api/ since
            # /api/admin/... should surface as admin_route, not endpoint.
            if _ADMIN_ROUTE_RE.match(body):
                findings.append({
                    "kind": "admin_route",
                    "match": body,
                    "file": path,
                    "line": line,
                })
                continue

            if "/admin/" in body and body.startswith("/api/"):
                # /api/admin/... -> emit both admin_route (high-value)
                # AND endpoint (the path is still a discoverable endpoint).
                findings.append({
                    "kind": "admin_route",
                    "match": body,
                    "file": path,
                    "line": line,
                })
                # fall through to endpoint emission below

            if _API_PATH_RE.match(body):
                findings.append({
                    "kind": "endpoint",
                    "match": body,
                    "file": path,
                    "line": line,
                })
                continue

            if not is_test:
                for sclass, pattern in _SECRET_PATTERNS:
                    if pattern.match(body) and not _is_placeholder(body):
                        findings.append({
                            "kind": "secret",
                            "secret_class": sclass,
                            "match": body,
                            "file": path,
                            "line": line,
                        })
                        break

        return findings

    def walk(
        self,
        root: Path,
        *,
        max_files: int | None = None,
        extensions: Iterable[str] = (".js", ".mjs", ".cjs", ".ts", ".tsx"),
    ) -> list[dict]:
        root = Path(root)
        out: list[dict] = []
        seen = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in extensions:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.max_file_bytes:
                continue
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Minification guard: long-line files are bundles; regex would hang.
            if src and max(len(line) for line in src.splitlines() or [""]) > self.max_line_chars:
                continue
            out.extend(self.analyze_source(src, path=str(path)))
            seen += 1
            if max_files is not None and seen >= max_files:
                break
        return out
