from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class WorkflowNodeLocalFileReadProbe(Probe):
    name = "workflow_node_local_file_read"
    vuln_class = "workflow_node_local_file_read"
    description = "Checks user-submitted workflow/node candidates for server-local file read plus output exfiltration."

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

        if not any(term in text for term in ("workflow", "graph", "node", "invocation", "pipeline")):
            missing.append("user-submitted workflow/node execution surface is not explicit")
        if not any(term in text for term in ("regular user", "non-admin", "low-priv", "authenticated", "unauth")):
            missing.append("attacker privilege level is not explicit")
        if not any(term in text for term in ("file_path", "path", "local file", "filesystem", "absolute path")):
            missing.append("attacker-controlled local path source is not explicit")
        if not any(term in text for term in ("open(", "file read", "read local", "read file", "filesystem read")):
            missing.append("server-side file-read sink is not explicit")
        if not any(term in text for term in ("result", "output", "response", "queue item", "exfil", "serialize")):
            missing.append("output exfiltration path is not explicit")
        if not any(term in text for term in ("allow", "deny", "default", "enabled", "allowlist", "denylist")):
            missing.append("node enablement/default allow-deny behavior is not explicit")
        if not any(term in controls for term in ("deny", "missing file", "owner", "sanitize", "utf-8", "negative", "binary")):
            missing.append("negative controls for node denial/output ownership/file constraints missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")

        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Reproduce with a live workflow submission and result fetch, then verify a sensitive file class reachable in default deployment.",
            }
        )
