from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class UnauthSecretConfigProbe(Probe):
    name = "unauth_secret_config"
    vuln_class = "unauth_secret_config"
    description = "Checks missing-auth config/secret exposure candidates for route, DTO, and redaction evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in (
                "title",
                "surface",
                "sink",
                "entrypoint",
                "attacker_control",
                "root_cause",
                "impact",
            )
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []

        if not any(term in text for term in ("unauth", "missing auth", "no auth", "authentication", "anonymous")):
            missing.append("unauthenticated or missing-auth boundary is not explicit")
        if not any(term in text for term in ("config", "settings", "runtime", "environment", "secret", "token", "api key")):
            missing.append("secret/config response surface is not explicit")
        if not any(term in text for term in ("dto", "response", "serialize", "model", "json", "schema")):
            missing.append("response serialization or DTO sink is not explicit")
        if not any(term in text for term in ("api key", "token", "credential", "secret", "bearer", "password")):
            missing.append("concrete secret class is not explicit")
        if not any(term in controls for term in ("redact", "masked", "admin", "401", "403", "negative", "protected")):
            missing.append("redacted/protected/admin-gated negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")

        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture unauthenticated response, authenticated/admin control, redacted endpoint control, and exact serialized secret-bearing fields.",
            }
        )
