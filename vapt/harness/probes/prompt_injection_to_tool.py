from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class PromptInjectionToToolProbe(Probe):
    name = "prompt_injection_to_tool"
    vuln_class = "prompt_injection_chain"
    description = "Checks prompt-injection candidates for concrete downstream tool impact."

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(str(cand.get(k, "")) for k in ("title", "surface", "sink", "impact", "root_cause")).lower()
        missing = []
        if "prompt" not in text and "agent" not in text and "tool" not in text:
            missing.append("AI prompt/agent/tool boundary not clear")
        if not any(term in text for term in ("file", "write", "read", "exfil", "execute", "privilege", "tool")):
            missing.append("concrete downstream impact not clear")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        if not cand.get("negative_controls"):
            missing.append("benign prompt/tool negative control missing")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Capture benign prompt, malicious prompt, tool invocation log, and unauthorized effect.",
            }
        )
