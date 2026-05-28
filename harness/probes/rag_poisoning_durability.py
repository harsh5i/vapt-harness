from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class RAGPoisoningDurabilityProbe(Probe):
    name = "rag_poisoning_durability"
    vuln_class = "rag_poisoning_durability"
    description = "Checks RAG poisoning candidates for persistence, retrieval, and downstream impact evidence."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(term in text for term in ("rag", "retrieval", "embedding", "vector", "index")):
            missing.append("retrieval/index boundary is not explicit")
        if not any(term in text for term in ("poison", "persist", "durable", "stored", "re-index", "reindex")):
            missing.append("durable poisoning path is not explicit")
        if not any(term in text for term in ("exfil", "tool", "file", "credential", "write", "privilege", "unauthorized")):
            missing.append("concrete downstream impact is not explicit")
        if not any(term in controls for term in ("clean index", "benign", "before poison", "after removal", "negative")):
            missing.append("clean-index or benign-document negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture clean-index behavior, poisoned ingestion, retrieval hit, persistence across reload/reindex, and the downstream unauthorized effect.",
            }
        )
