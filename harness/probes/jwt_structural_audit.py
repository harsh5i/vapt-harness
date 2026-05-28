"""JWT structural audit probe (Move 3).

Walks all JWT-shaped strings discovered in:
- the candidate's `proof_artifact` text (request/response captures)
- the candidate's `notes` and `evidence_excerpts`
- any auxiliary files declared in `ctx.knobs["jwt_paths"]`

Local-only. No network. Uses `tools.jwt.decode_local` to surface
structural risks: alg=none, kid path injection, external key URLs (jku/x5u),
and missing standard claims (sub, exp).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from probes.base import Probe, ProbeContext, ProbeResult


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _decoder():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools.jwt import decode_local
    return decode_local


class JwtStructuralAudit(Probe):
    name = "jwt_structural_audit"
    vuln_class = "auth"
    description = "Extract JWTs from candidate text and report structural risks (alg=none, kid injection, jku/x5u, missing exp/sub)."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        decode = _decoder()
        sources: list[tuple[str, str]] = []
        for key in ("proof_artifact", "notes", "evidence_excerpts", "title"):
            text = str(ctx.candidate.get(key, "") or "")
            if text:
                sources.append((key, text))
        for path in ctx.knobs.get("jwt_paths", []) or []:
            try:
                sources.append((f"file:{path}", Path(path).read_text(errors="replace")))
            except OSError:
                continue
        seen: set[str] = set()
        findings: list[dict[str, Any]] = []
        for label, text in sources:
            for token in _JWT_RE.findall(text):
                if token in seen:
                    continue
                seen.add(token)
                decoded = decode(token)
                risks = list(decoded.get("risks") or [])
                payload = decoded.get("payload") or {}
                if isinstance(payload, dict):
                    if "exp" not in payload:
                        risks.append("payload missing 'exp' (no expiry)")
                    if "sub" not in payload and "aud" not in payload:
                        risks.append("payload missing 'sub' and 'aud' (no principal)")
                if risks:
                    findings.append(
                        {
                            "source": label,
                            "token_prefix": token[:24] + "...",
                            "alg": (decoded.get("header") or {}).get("alg"),
                            "kid": (decoded.get("header") or {}).get("kid"),
                            "risks": risks,
                        }
                    )
        return ProbeResult({
            "name": self.name,
            "scanned_sources": [label for label, _ in sources],
            "token_count": len(seen),
            "finding_count": len(findings),
            "findings": findings,
        })
