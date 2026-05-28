from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class SerializationRCEProbe(Probe):
    name = "serialization_rce"
    vuln_class = "serialization_rce"
    description = "Validates that a serialization candidate demonstrates trust bypass, not generic unsafe loading."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(str(cand.get(k, "")) for k in ("title", "surface", "sink", "root_cause", "impact")).lower()
        missing = []
        if not any(term in text for term in ("pickle", "deserialize", "serialization", "load", "trusted", "allowlist")):
            missing.append("candidate does not identify serialization/trust mechanism")
        if not cand.get("negative_controls"):
            missing.append("benign load or denied-trust negative control missing")
        if "bypass" not in text and "trusted" not in text and "allowlist" not in text:
            missing.append("trust mechanism bypass is not stated")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Prove latest-version trust bypass with benign load and malicious load controls.",
            }
        )
