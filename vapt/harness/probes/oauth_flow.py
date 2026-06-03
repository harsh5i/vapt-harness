"""OAuth flow probe.

Doctrine-check gate. Future active-scanner work:

- Enumerate authorization endpoint with varied combinations of
  `response_mode`, `redirect_uri`, `state`, `prompt`, `nonce`.
- Capture where tokens / authorization codes land (URL fragment, query,
  form_post, web_message, postMessage).
- Flag any redirect_uri permissive matching, response_mode=form_post on
  attacker-influenced origin, prompt=none on cross-origin redirect, or
  state-parameter omission.
- Cross-reference against the case study: see
  `knowledge/case_studies/portswigger_top10_2024.md` (#1 #3).
"""
from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class OAuthFlowProbe(Probe):
    name = "oauth_flow"
    vuln_class = "oauth_flow"
    description = (
        "Checks OAuth-flow candidates for explicit authorization endpoint, "
        "redirect_uri / response_mode evidence, and a captured non-happy path."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(t in text for t in ("oauth", "oidc", "authorization", "authorize", "token endpoint")):
            missing.append("OAuth / OIDC flow surface not explicit")
        if not any(t in text for t in ("redirect_uri", "response_mode", "state", "prompt", "nonce")):
            missing.append("non-happy-path parameter under test not named")
        if not any(t in text for t in ("token", "code", "id_token", "access_token")):
            missing.append("artifact landing (token/code) not described")
        if not any(t in controls for t in ("expected", "denied", "valid", "rejected", "happy path")):
            missing.append("happy-path negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Capture authorize-endpoint request with the varied parameter, "
                    "the resulting redirect / form_post target, and where the token "
                    "ends up. Include the happy-path control for diff."
                ),
            }
        )
