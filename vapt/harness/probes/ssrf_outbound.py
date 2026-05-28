from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class SSRFOutboundProbe(Probe):
    name = "ssrf_outbound"
    vuln_class = "ssrf_outbound"
    description = "Checks SSRF candidates for attacker-controlled URL source, outbound sink, and safe captive evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(str(cand.get(k, "")) for k in ("title", "surface", "sink", "entrypoint", "attacker_control")).lower()
        missing = []
        if not any(term in text for term in ("url", "host", "webhook", "registry", "http", "request")):
            missing.append("attacker-controlled outbound URL/host source not clear")
        if not any(term in text for term in ("requests", "http", "fetch", "axios", "urlopen", "client")):
            missing.append("outbound request sink not clear")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        if not cand.get("safety_notes"):
            missing.append("safe captive listener / no third-party scanning note missing")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Use a captive listener and record redirect/reserved-IP controls within ROE.",
            }
        )
