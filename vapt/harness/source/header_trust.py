"""Header-trust audit.

Static scanner that flags source-code reads of HTTP headers that are
spoofable across common reverse-proxy / framework setups. The
per-header severity hint encodes case-study evidence
(`knowledge/case_studies/`):

  HIGH    -- proven framework bypass headers
              (Next.js x-middleware-subrequest case study;
               IIS / ASP.NET x-original-url / x-rewrite-url;
               internal-routing x-internal-* and x-original-host).
  MEDIUM  -- spoofable IP / proto / method overrides under loose
              trust-proxy configuration
              (x-forwarded-for/proto/host, x-real-ip,
               x-http-method-override, x-method-override, _method,
               x-cluster-client-ip, true-client-ip,
               x-azure-clientip, cf-connecting-ip).

The scanner emits a finding per (file, line, header). It does not
decide whether the read sits on an authz path -- that is the
operator's triage step (cross-reference with the framework's
controller/middleware layout).

Source languages covered: Ruby (Rails / Sinatra), Python (Django /
Flask / FastAPI), JavaScript / TypeScript (Express / Next.js /
generic Node).
"""
from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Iterable

# Header registry: lowercase canonical name -> severity.
_HEADER_REGISTRY: dict[str, str] = {
    # HIGH: documented framework bypasses.
    "x-middleware-subrequest": "high",
    "x-original-url": "high",
    "x-rewrite-url": "high",
    "x-original-host": "high",
    "x-forwarded-host": "high",  # SSRF / URL-confusion vector
    "x-forwarded-server": "high",
    "x-original-request-method": "high",
    "x-internal-token": "high",
    "x-internal-request": "high",
    "x-internal-secret": "high",
    "x-tenant-id": "high",  # multi-tenant boundary header
    "x-account-id": "high",
    "x-impersonate-user": "high",
    "x-impersonated-user": "high",
    "x-on-behalf-of": "high",
    # MEDIUM: spoofable when trust-proxy is loose.
    "x-forwarded-for": "medium",
    "x-forwarded-proto": "medium",
    "x-real-ip": "medium",
    "x-cluster-client-ip": "medium",
    "true-client-ip": "medium",
    "cf-connecting-ip": "medium",
    "x-azure-clientip": "medium",
    "x-azure-socketip": "medium",
    "x-http-method-override": "medium",
    "x-method-override": "medium",
    "_method": "medium",
    "x-forwarded-user": "medium",
    "x-forwarded-email": "medium",
    "x-remote-user": "medium",
    "x-remote-ip": "medium",
}


# --- patterns -------------------------------------------------------------

# Ruby: `request.headers["X-..."]`, `request.headers['X-...']`,
#       `request.headers[:x_...]`, `request.env["HTTP_X_..."]`,
#       `env["HTTP_X_..."]`.
_RUBY_HEADER_BRACKET_RE = re.compile(
    r"""(?:request\.)?(?:headers|env)\s*\[\s*(['"])(?P<name>[^'"]+)\1\s*\]"""
)
_RUBY_HEADER_SYMBOL_RE = re.compile(
    r"""(?:request\.)?(?:headers|env)\s*\[\s*:(?P<name>[A-Za-z_][\w]*)\s*\]"""
)

# Python: `request.headers["..."]`, `request.headers.get("...")`,
#         `request.META["HTTP_..."]`, `request.environ["HTTP_..."]`,
#         `headers.get("...")` (Starlette / FastAPI / Next.js JS routes too).
_PY_HEADER_BRACKET_RE = re.compile(
    r"""(?:request\.)?(?:headers|META|environ|scope\['headers'\])\s*(?:\.get\s*\(|\[\s*)\s*(['"])(?P<name>[^'"]+)\1"""
)

# JS/TS: `req.headers["x-..."]`, `req.headers['x-...']`,
#        `req.get("X-...")`, `headers().get("x-...")`,
#        `request.headers.get("x-...")`, `event.headers["X-..."]`.
_JS_HEADER_BRACKET_RE = re.compile(
    r"""(?:req|request|ctx|event|context|headers\(\)|headers|h)\s*(?:\.headers)?\s*(?:\[\s*|\.get\s*\(\s*)(['"`])(?P<name>[^'"`]+)\1"""
)

_PATTERNS_BY_EXT: dict[str, tuple[re.Pattern[str], ...]] = {
    ".rb": (_RUBY_HEADER_BRACKET_RE, _RUBY_HEADER_SYMBOL_RE),
    ".py": (_PY_HEADER_BRACKET_RE,),
    ".js": (_JS_HEADER_BRACKET_RE,),
    ".mjs": (_JS_HEADER_BRACKET_RE,),
    ".cjs": (_JS_HEADER_BRACKET_RE,),
    ".ts": (_JS_HEADER_BRACKET_RE,),
    ".tsx": (_JS_HEADER_BRACKET_RE,),
}


_TEST_PATH_HINTS = (
    "_spec.rb", "_test.rb", "/spec/", "/test/", "/tests/",
    ".spec.js", ".test.js", ".spec.ts", ".test.ts",
    "/__tests__/", "/__mocks__/", "/fixtures/", "/cypress/",
    "_test.py", "_tests.py",
)


def _is_test_path(path: str) -> bool:
    lowered = path.lower().replace(os.sep, "/")
    # Filename-prefix `test_` is a Python test convention. Apply it on the
    # basename only -- substring match would (mis)flag pytest's own tmp dirs
    # such as `pytest-of-USER/test_walk_directory0/bad.rb`.
    base = lowered.rsplit("/", 1)[-1]
    if base.startswith("test_"):
        return True
    return any(hint in lowered for hint in _TEST_PATH_HINTS)


def _normalize_header_name(raw: str) -> str:
    """Map any of `X-Forwarded-For` / `HTTP_X_FORWARDED_FOR` /
    `x_forwarded_for` / `xForwardedFor` to canonical `x-forwarded-for`.
    """
    name = raw.strip().lower()
    if name.startswith("http_"):
        name = name[len("http_"):]
    name = name.replace("_", "-")
    return name


def _line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


# --- auditor --------------------------------------------------------------

@dataclasses.dataclass
class HeaderTrustAuditor:
    """Per-file scanner. Stateless; reusable."""

    max_file_bytes: int = 5 * 1024 * 1024

    def analyze_source(self, src: str, path: str = "<memory>") -> list[dict]:
        if _is_test_path(path):
            return []
        ext = Path(path).suffix.lower()
        patterns = _PATTERNS_BY_EXT.get(ext)
        if not patterns:
            # Default: try every pattern. Useful for unknown extensions.
            patterns = tuple(set(p for plist in _PATTERNS_BY_EXT.values() for p in plist))

        seen: set[tuple[int, str]] = set()
        findings: list[dict] = []
        for pattern in patterns:
            for m in pattern.finditer(src):
                raw = m.group("name")
                canonical = _normalize_header_name(raw)
                severity = _HEADER_REGISTRY.get(canonical)
                if severity is None:
                    continue
                line = _line_of(src, m.start("name"))
                key = (line, canonical)
                if key in seen:
                    continue
                seen.add(key)
                line_start = src.rfind("\n", 0, m.start()) + 1
                line_end = src.find("\n", m.end())
                if line_end == -1:
                    line_end = len(src)
                findings.append({
                    "header": canonical,
                    "severity": severity,
                    "file": path,
                    "line": line,
                    "snippet": src[line_start:line_end].strip(),
                })
        return findings

    def walk(
        self,
        root: Path,
        *,
        max_files: int | None = None,
        extensions: Iterable[str] = (".rb", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx"),
    ) -> list[dict]:
        root = Path(root)
        out: list[dict] = []
        seen = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in extensions:
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
            out.extend(self.analyze_source(src, path=str(path)))
            seen += 1
            if max_files is not None and seen >= max_files:
                break
        return out
