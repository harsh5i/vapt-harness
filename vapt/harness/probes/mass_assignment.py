"""Mass-assignment probe.

Doctrine-check gate. Future active-scanner work:

- For every user-scoped PATCH / PUT endpoint, replay the request with
  extra fields drawn from a privilege-relevant set:
  `role`, `is_admin`, `account_type`, `owner`, `tenant`, `verified`,
  `email_verified`, `subscription`, `permissions`, framework-specific
  internal fields.
- Diff the response and the resulting object state.
- Score higher when the target stack exposes ORM auto-binding (Rails
  `permit`, Django ModelForm, ActiveRecord, Sequelize, Mongoose).
- Cross-reference against `knowledge/case_studies/web_hackers_vs_auto.md`
  for auto-industry account-takeover pattern.
"""
from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class MassAssignmentProbe(Probe):
    name = "mass_assignment"
    vuln_class = "mass_assignment"
    description = (
        "Checks mass-assignment candidates for explicit privilege field, "
        "user-scoped endpoint, and diffable response evidence."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(t in text for t in ("patch", "put", "post", "update", "profile", "settings", "account")):
            missing.append("user-scoped write endpoint not explicit")
        if not any(t in text for t in ("role", "is_admin", "permission", "owner", "tenant", "verified", "account_type", "subscription")):
            missing.append("privilege-relevant field under test not named")
        if not any(t in text for t in ("orm", "permit", "model", "binding", "params", "strong_parameters", "modelform", "sequelize", "mongoose")):
            missing.append("auto-binding mechanism / framework path not described")
        if not any(t in controls for t in ("before", "after", "diff", "rejected", "filtered")):
            missing.append("response/state diff control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Replay the user-scoped PATCH/PUT with the extra privilege "
                    "field added. Capture pre-call and post-call object state "
                    "via authoritative read endpoint. Show the diff."
                ),
            }
        )
