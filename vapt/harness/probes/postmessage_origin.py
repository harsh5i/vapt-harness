"""postMessage origin-check probe.

Doctrine-check gate. Future active-scanner work:

- Static: parse JS bundles for every
  `addEventListener("message", handler)` and `window.onmessage = ...`.
  Inspect handler body for origin check pattern.
- Flag: missing origin check; substring / prefix / suffix match instead
  of full-equality (`===`); regex with unescaped dot; allowlist
  containing wildcard subdomain; `event.origin` not referenced.
- Dynamic (Playwright): inject hook before page load, dump every
  registered handler's source + observed origin checks.
- Cross-reference against
  `knowledge/case_studies/postmessage_origin.md` (Frans Rosén pattern).
"""
from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class PostMessageOriginProbe(Probe):
    name = "postmessage_origin"
    vuln_class = "postmessage_origin"
    description = (
        "Checks postMessage candidates for explicit handler, origin-check "
        "pattern under test, and crossable boundary."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(t in text for t in ("postmessage", "addeventlistener", "onmessage", "window.message")):
            missing.append("postMessage handler not explicit")
        if not any(t in text for t in ("origin", "source", "event.origin", "event.source", "targetorigin")):
            missing.append("origin check pattern under test not described")
        if not any(t in text for t in ("substring", "regex", "prefix", "suffix", "wildcard", "missing", "absent", "no check", "indexof", "endswith", "startswith")):
            missing.append("specific bypass pattern (substring/regex/missing) not identified")
        if not any(t in controls for t in ("benign", "rejected", "ignored", "expected origin")):
            missing.append("benign-origin negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Capture the handler source (bundle path + line), the "
                    "exact origin-check pattern, an attacker-origin message "
                    "demonstrating the bypass, and a benign-origin control."
                ),
            }
        )
