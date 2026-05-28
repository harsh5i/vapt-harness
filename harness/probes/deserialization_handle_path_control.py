from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class DeserializationHandlePathControlProbe(Probe):
    name = "deserialization_handle_path_control"
    vuln_class = "deserialization_handle_path_control"
    description = (
        "Checks whether attacker-controlled object handles can become filesystem paths for deserialization/model loads."
    )

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
                "variant_analysis",
            )
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []

        if not any(term in text for term in ("workflow", "graph", "api", "request", "job", "handle", "object id")):
            missing.append("attacker-controlled handle/API surface is not explicit")
        if not any(term in text for term in ("name", "handle", "id", "key", "path", "filename")):
            missing.append("attacker-controlled object name/handle field is not explicit")
        if not any(term in text for term in ("absolute path", "path traversal", "../", "safe root", "canonical")):
            missing.append("path control/canonicalization failure is not explicit")
        if not any(
            term in text
            for term in ("deserialize", "deserialization", "pickle", "torch.load", "load model", "model load")
        ):
            missing.append("deserialization/model-load sink is not explicit")
        if not any(term in text for term in ("write", "upload", "download", "plant", "attacker file", "attacker-controlled file")):
            missing.append("attacker-controlled file placement primitive is not explicit")
        if not any(term in text for term in ("rce", "code execution", "file read", "secret", "credential", "model data")):
            missing.append("security impact beyond parser error is not explicit")
        if not any(term in controls for term in ("weights_only", "safe", "allowlist", "negative", "missing file", "scan")):
            missing.append("negative controls for safe deserialization/scanning/missing file behavior are missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")

        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Prove a full chain from attacker file placement to the deserializer, then verify whether current "
                    "safe-load defaults or malware scanning block code execution."
                ),
            }
        )
