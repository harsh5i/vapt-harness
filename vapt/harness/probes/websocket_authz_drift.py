from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class WebsocketAuthzDriftProbe(Probe):
    name = "websocket_authz_drift"
    vuln_class = "websocket_authz"
    description = "Checks that a realtime event proof includes denied REST/API control and receiver evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        missing = []
        if "websocket" not in " ".join(str(cand.get(k, "")) for k in ("surface", "sink", "title")).lower():
            missing.append("candidate does not explicitly reference websocket/realtime surface")
        if not cand.get("negative_controls"):
            missing.append("negative_controls missing")
        if "rest" not in str(cand.get("negative_controls", "")).lower() and "api" not in str(cand.get("negative_controls", "")).lower():
            missing.append("negative_controls should include denied REST/API read")
        if not cand.get("proof") == "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Add denied REST/API control, receiver websocket evidence, and payload comparison.",
            }
        )
