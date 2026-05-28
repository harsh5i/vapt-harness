from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class QueueJobSecretLeakProbe(Probe):
    name = "queue_job_secret_leak"
    vuln_class = "queue_job_secret_leak"
    description = "Checks queue/job APIs for credential-bearing state returned without ownership filtering or redaction."

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
                "trust_boundary",
                "root_cause",
                "impact",
                "exploitability",
            )
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []

        if not any(term in text for term in ("queue", "job", "task", "worker", "download")):
            missing.append("queue/job state surface is not explicit")
        if not any(term in text for term in ("token", "api key", "secret", "credential", "bearer")):
            missing.append("secret-bearing field is not explicit")
        if not any(term in text for term in ("serialize", "response", "list", "get", "model_dump", "json")):
            missing.append("response serialization path is not explicit")
        if not any(term in text for term in ("owner", "ownership", "cross-user", "global", "user filtering", "unscoped")):
            missing.append("ownership/filtering failure is not explicit")
        if not any(term in text for term in ("regular user", "non-admin", "low-priv", "authenticated", "unauth")):
            missing.append("attacker privilege level is not explicit")
        if not any(term in controls for term in ("admin", "redact", "owner", "negative", "filter", "scoped")):
            missing.append("negative controls for admin-only routes/redaction/ownership missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")

        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Reproduce with two users against a live service and prove the leaked credential grants access to private model/data resources.",
            }
        )
