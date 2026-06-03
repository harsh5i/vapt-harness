"""postMessage handler walker.

Static scanner that locates ``addEventListener("message", handler)`` and
``window.onmessage = ...`` registrations, captures the handler body, and
classifies the origin check inside it.

Two emitted classes:
  - ``no_origin_check``   -- body never references ``.origin`` (or
                             ``event.origin`` / ``e.origin`` / ``msg.origin``)
  - ``weak_origin_check`` -- body uses a substring / suffix / prefix /
                             regex check on origin (indexOf, includes,
                             endsWith, startsWith, .test, .match)

Strict-equality checks (``=== "https://..."`` / ``!== someVar``) are
considered well-formed and NOT emitted.

The walker is regex+brace-balance based, not a full JS AST. The case
study (Frans Rosén) found these with grep + manual review; precision
loss from skipping a full parser is acceptable for a high-recall probe.

Test-path suppression matches the JS bundle analyzer's filter
(*.spec.*, *.test.*, /__tests__/, /__mocks__/, /fixtures/, /test/,
/spec/, /cypress/).
"""
from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Iterable

# `addEventListener("message", ...)` -- capture the receiver if any so we
# can suppress same-origin channels (ServiceWorker, MessageChannel ports,
# Workers, BroadcastChannel) that look textually identical but are not a
# cross-origin attack surface.
_LISTENER_RE = re.compile(
    r"""
    (?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*)?
    addEventListener\s*\(\s*['"]message['"]\s*,
    """,
    re.VERBOSE,
)

# `onmessage = function(...) { ... }` -- same receiver capture.
_ONMESSAGE_RE = re.compile(
    r"""
    (?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*)?
    onmessage\s*=\s*
    """,
    re.VERBOSE,
)

# Receivers that are same-origin postMessage channels, never cross-origin.
# Match by suffix substring: ``navigator.serviceWorker`` covers
# ``navigator.serviceWorker.addEventListener(...)``; ``port1`` and ``port2``
# cover MessageChannel ports; ``worker`` covers ``new Worker(...).onmessage``.
_SAME_ORIGIN_RECEIVER_HINTS = (
    "navigator.serviceworker",
    "serviceworker.",
    "port1.",
    "port2.",
    "messagechannel.",
    "broadcastchannel.",
    ".worker.",
    "worker.",
)


def _is_same_origin_channel(receiver: str | None) -> bool:
    if not receiver:
        return False
    norm = receiver.lower().replace(" ", "")
    return any(hint in norm for hint in _SAME_ORIGIN_RECEIVER_HINTS)

# Weak-pattern signatures applied to the handler body.
_WEAK_PATTERNS = [
    ("indexOf", re.compile(r"\.origin\s*\)?\s*\.\s*indexOf\b")),
    ("indexOf-rhs", re.compile(r"\.\s*indexOf\s*\(\s*[^)]*\.origin")),
    ("includes", re.compile(r"\.origin\s*\)?\s*\.\s*includes\b")),
    ("endsWith", re.compile(r"\.origin\s*\)?\s*\.\s*endsWith\b")),
    ("startsWith", re.compile(r"\.origin\s*\)?\s*\.\s*startsWith\b")),
    ("regex-test", re.compile(r"\.test\s*\(\s*[^)]*\.origin")),
    ("regex-match", re.compile(r"\.origin\s*\)?\s*\.\s*match\b")),
    ("string-search", re.compile(r"\.origin\s*\)?\s*\.\s*search\b")),
]

# Strong-equality signatures.
# 1. `event.origin === "..."`, `event.origin !== someVar`, etc.
_STRONG_PATTERN = re.compile(r"\.origin\s*(?:!==|===|!=|==)")
# 2. `TRUSTED_ARRAY.includes(event.origin)` -- Array.prototype.includes
#    is strict-equality element match (different from String.prototype.includes
#    which is a substring check; the latter is captured by the WEAK pattern
#    `.origin.includes(...)` because there `.origin` is the receiver).
_STRONG_ARRAY_INCLUDES = re.compile(r"\.\s*includes\s*\(\s*[^)]*\.origin\s*[,)]")
# 3. `arr.indexOf(event.origin) !== -1` / `>= 0` -- same logic.
_STRONG_ARRAY_INDEXOF = re.compile(
    r"\.\s*indexOf\s*\(\s*[^)]*\.origin\s*\)\s*(?:!==\s*-1|!=\s*-1|>=\s*0|>\s*-1)"
)

# A bare `.origin` reference anywhere -- used to distinguish
# `no_origin_check` from `weak_origin_check`.
_ORIGIN_REF = re.compile(r"\.origin\b")

_TEST_PATH_HINTS = (
    ".spec.js", ".test.js", ".spec.ts", ".test.ts",
    "/__tests__/", "/__mocks__/", "/fixtures/", "/test/", "/tests/",
    "/spec/", "/cypress/",
)


def _is_test_path(path: str) -> bool:
    lowered = path.lower().replace(os.sep, "/")
    return any(h in lowered for h in _TEST_PATH_HINTS)


def _line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _resolve_named_handler(src: str, identifier: str, *, max_body_chars: int = 8000) -> str | None:
    """Find the body of ``function identifier(...)`` or ``const identifier = (...) => {...}`` in src.

    Returns the body text (best-effort, brace-balanced) or None if no
    definition is found. Used when ``addEventListener("message", foo)``
    passes a named handler reference instead of an inline lambda.
    """
    patterns = [
        re.compile(rf"\bfunction\s+{re.escape(identifier)}\s*\("),
        re.compile(rf"\b(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*(?:async\s+)?(?:function\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
        re.compile(rf"\bexport\s+(?:default\s+)?function\s+{re.escape(identifier)}\s*\("),
    ]
    for pattern in patterns:
        m = pattern.search(src)
        if m:
            body, _end = _extract_handler_body(src, m.end(), max_body_chars=max_body_chars)
            return body
    return None


def _extract_handler_body(src: str, start_offset: int, *, max_body_chars: int = 8000) -> tuple[str, int]:
    """Walk from start_offset to find the first balanced `{ ... }` block.

    Returns (body_text, end_offset). If no balanced block is found within
    ``max_body_chars`` we return everything we walked, so analysis can
    still proceed on a best-effort basis.
    """
    n = len(src)
    i = start_offset
    # Skip to first `{`. We tolerate `=> expr` arrow shorthand by capping at
    # the next `)` for the addEventListener call -- but those handlers are
    # rare in practice; default path is `{ ... }`.
    end_cap = min(n, start_offset + max_body_chars)
    while i < end_cap and src[i] != "{":
        if src[i] == ";":
            return src[start_offset:i], i
        i += 1
    if i >= end_cap:
        return src[start_offset:end_cap], end_cap
    depth = 0
    body_start = i
    while i < n and i < start_offset + max_body_chars:
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[body_start:i + 1], i + 1
        i += 1
    return src[body_start:i], i


def _classify(body: str) -> tuple[str, str | None]:
    """Return (kind, matched_pattern_name).

    kind is one of: ``strong``, ``weak``, ``none``.
    matched_pattern_name is set only for ``weak`` (the specific signature).

    Order matters: a body containing both ``arr.includes(event.origin)``
    (strong) and a stray ``event.origin.indexOf(...)`` later (weak) is
    classified by whichever check is positionally first in the body --
    the strong checks below short-circuit on first match.
    """
    if (
        _STRONG_PATTERN.search(body)
        or _STRONG_ARRAY_INCLUDES.search(body)
        or _STRONG_ARRAY_INDEXOF.search(body)
    ):
        return "strong", None
    for name, pattern in _WEAK_PATTERNS:
        if pattern.search(body):
            return "weak", name
    if _ORIGIN_REF.search(body):
        # `.origin` referenced but not in any recognised check pattern.
        # Treat as weak so the operator looks at it. False-positive rate
        # acceptable; recall matters more than precision here.
        return "weak", "origin-referenced-not-checked"
    return "none", None


@dataclasses.dataclass
class PostMessageWalker:
    max_file_bytes: int = 5 * 1024 * 1024
    max_line_chars: int = 20_000

    def analyze_source(self, src: str, path: str = "<memory>") -> list[dict]:
        if _is_test_path(path):
            return []
        findings: list[dict] = []
        seen_offsets: set[int] = set()

        for pattern in (_LISTENER_RE, _ONMESSAGE_RE):
            for m in pattern.finditer(src):
                start = m.end()
                if start in seen_offsets:
                    continue
                seen_offsets.add(start)
                receiver = m.group("receiver") if "receiver" in m.groupdict() else None
                if _is_same_origin_channel(receiver):
                    continue
                body, _end = _extract_handler_body(src, start)
                # If body is empty / has no `{`, the second arg is likely a
                # named function reference. Resolve it within the same file.
                if "{" not in body:
                    ident_match = _IDENT_RE.search(body)
                    if ident_match:
                        resolved = _resolve_named_handler(src, ident_match.group(0))
                        if resolved is not None:
                            body = resolved
                kind, weak_name = _classify(body)
                if kind == "strong":
                    continue
                line = _line_of(src, m.start())
                # Snippet: the line containing addEventListener through the
                # first ~6 lines of body.
                snippet_end = src.find("\n", _end if _end > start else start + 200)
                snippet = src[m.start():snippet_end if snippet_end != -1 else start + 400]
                findings.append({
                    "kind": "no_origin_check" if kind == "none" else "weak_origin_check",
                    "file": path,
                    "line": line,
                    "evidence": weak_name or "no .origin reference in handler body",
                    "snippet": snippet.strip(),
                })
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
            if src and max(len(line) for line in src.splitlines() or [""]) > self.max_line_chars:
                continue
            out.extend(self.analyze_source(src, path=str(path)))
            seen += 1
            if max_files is not None and seen >= max_files:
                break
        return out
