from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class IDORDiffProbe(Probe):
    name = "idor_diff"
    vuln_class = "idor_diff"
    description = "Checks IDOR candidates for same-object differential access evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(term in text for term in ("idor", "authorization", "authz", "permission", "access control")):
            missing.append("authorization boundary is not explicit")
        if not any(term in text for term in ("object", "resource", "tenant", "team", "channel", "owner", "user id", "file id")):
            missing.append("protected object identifier is not explicit")
        if not any(term in controls for term in ("owner", "authorized", "forbidden", "denied", "404", "403")):
            missing.append("owner-vs-non-owner negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture authorized owner response, unauthorized peer response, and the exact object identifier reused across both requests.",
            }
        )
