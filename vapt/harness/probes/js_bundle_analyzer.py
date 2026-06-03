"""JS bundle analyzer probe.

Doctrine-check gate. Future active-scanner work:

- Discover JS bundle / source-map artifacts under target origin.
- Parse with esprima / acorn / a regex sweep for: string literals
  matching URL/path patterns, key patterns (`/^A[K]IA/`, `/sk_live_/`),
  hidden API route maps, JSON config blobs, GraphQL schema fragments.
- Output: hidden-endpoint inventory + secret-candidate list with
  bundle file + line/column citations.
- Cross-reference against
  `knowledge/case_studies/web_hackers_vs_auto.md` — auto-industry
  team's primary recon technique was JS bundle URL enumeration.
"""
from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class JSBundleAnalyzerProbe(Probe):
    name = "js_bundle_analyzer"
    vuln_class = "js_bundle_surface"
    description = (
        "Checks JS-bundle-derived candidates for explicit bundle source, "
        "extracted artifact, and reachable endpoint or live secret."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        artifacts = str(cand.get("artifacts", "")).lower()
        missing = []
        if not any(t in text for t in ("bundle", "webpack", "vite", "rollup", "source map", "js", "javascript", "chunk")):
            missing.append("bundle source not explicit")
        if not any(t in text for t in ("endpoint", "route", "url", "api", "key", "secret", "token", "config")):
            missing.append("extracted artifact type not described")
        if not any(t in artifacts for t in ("bundle", "js", ".map", "chunk")) and not any(t in text for t in ("citation", "line", "column", "file")):
            missing.append("bundle file + position citation missing")
        if not any(t in text for t in ("reachable", "live", "200", "responded", "valid", "loaded")):
            missing.append("reachability / liveness evidence not captured")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Capture bundle file path + line citation for the extracted "
                    "URL / secret, plus a live-fetch / API-call confirming it "
                    "responds. Strip false-positive lookalikes."
                ),
            }
        )
