from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class RelativeFileWriteToCodeLoadProbe(Probe):
    name = "relative_file_write_to_code_load"
    vuln_class = "relative_file_write_to_code_load"
    description = "Checks relative file-write candidates for a concrete executable-load or restart/reload chain."

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
                "exploitability",
            )
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []

        if not any(term in text for term in ("relative", "cwd", "current working directory", "working directory")):
            missing.append("relative/cwd write boundary is not explicit")
        if not any(term in text for term in ("file write", "write", "download", "upload", "create file", "plant")):
            missing.append("attacker-controlled file write primitive is not explicit")
        if not any(term in text for term in ("import", "load", "reload", "startup", "plugin", "extension", "custom node", "code execution", "rce")):
            missing.append("executable-load path is not explicit")
        if not any(term in text for term in ("regular user", "low-priv", "authenticated", "non-admin", "unauth")):
            missing.append("attacker privilege level is not explicit")
        if not any(term in controls for term in ("absolute", "..", "existing", "admin", "negative", "clobber", "containment")):
            missing.append("path-validation or clobber negative controls missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")

        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": "Prove the exact runtime cwd, configured executable-load directory, attacker-created file path, and restart/reload/import event that executes it.",
            }
        )
