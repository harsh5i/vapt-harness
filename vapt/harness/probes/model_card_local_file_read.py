from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class ModelCardLocalFileReadProbe(Probe):
    name = "model_card_local_file_read"
    vuln_class = "model_card_local_file_read"
    description = "Checks model-card/template candidates for local file read through rendering or metadata expansion."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(term in text for term in ("model card", "card", "markdown", "yaml", "template", "metadata")):
            missing.append("model-card/template rendering boundary is not explicit")
        if not any(term in text for term in ("local file", "file read", "path", "include", "open(", "read")):
            missing.append("local file read sink is not explicit")
        if not any(term in controls for term in ("missing file", "benign template", "safe path", "denied", "negative")):
            missing.append("benign template or denied-file negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture benign card rendering, malicious metadata/template rendering, exact file-read sink, and denied/missing-file control.",
            }
        )
