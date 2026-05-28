from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class ParserCanonicalizationProbe(Probe):
    name = "parser_canonicalization"
    vuln_class = "parser_canonicalization"
    description = "Checks parser/canonicalization candidates for checked-vs-sink representation evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(str(cand.get(k, "")) for k in ("title", "surface", "sink", "root_cause", "impact")).lower()
        missing = []
        if not any(term in text for term in ("parse", "decode", "canonical", "normalize", "path", "traversal", "archive")):
            missing.append("parser/canonicalization boundary not clear")
        if not cand.get("negative_controls"):
            missing.append("benign normalized control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture checked representation, sink representation, benign control, and malicious differential input.",
            }
        )
