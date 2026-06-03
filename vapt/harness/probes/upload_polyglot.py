"""Upload-endpoint polyglot probe.

Doctrine-check gate. Future active-scanner work:

- Discover every multipart-accepting endpoint. Classify auth-requirement
  (pre-auth gets highest priority).
- For each, submit polyglot payloads: image-with-EXIF-shell,
  GIF/PNG-with-trailing-archive, SVG-with-XML-XXE, DJVU/JBIG2-with-CVE,
  ZIP-with-zip-slip path, OOXML/ODF-with-formula.
- Watch OOB collaborator (DNS + HTTP) for callbacks from server-side
  parsing libraries (ExifTool, ImageMagick, libreoffice, ffmpeg, java
  XML, unzipper).
- Cross-reference against
  `knowledge/case_studies/gitlab_exiftool_djvu.md` (CVE-2021-22205).
"""
from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class UploadPolyglotProbe(Probe):
    name = "upload_polyglot"
    vuln_class = "upload_polyglot"
    description = (
        "Checks upload-derived candidates for endpoint auth class, parser "
        "library identification, polyglot payload, and OOB callback evidence."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        cand = ctx.candidate
        text = " ".join(
            str(cand.get(k, ""))
            for k in ("title", "surface", "sink", "entrypoint", "attacker_control", "root_cause", "impact")
        ).lower()
        controls = str(cand.get("negative_controls", "")).lower()
        missing = []
        if not any(t in text for t in ("upload", "multipart", "form-data", "attachment", "image", "file", "avatar", "media")):
            missing.append("upload endpoint not explicit")
        if not any(t in text for t in ("pre-auth", "post-auth", "auth", "anonymous", "session", "cookie", "token")):
            missing.append("endpoint auth-requirement class not stated")
        if not any(t in text for t in ("exiftool", "imagemagick", "libreoffice", "ffmpeg", "unzipper", "xml", "djvu", "jbig2", "svg", "polyglot")):
            missing.append("parser library / payload kind not identified")
        if not any(t in text for t in ("oob", "callback", "collaborator", "dns", "burpcollab", "interactsh", "out-of-band")) and not any(t in text for t in ("rce", "ssrf", "file write", "xxe")):
            missing.append("OOB callback or concrete primitive evidence missing")
        if not any(t in controls for t in ("benign", "accepted", "rejected", "expected")):
            missing.append("benign-upload negative control missing")
        if cand.get("proof") != "passed":
            missing.append("proof has not passed")
        return ProbeResult(
            {
                "probe": self.name,
                "candidate_id": cand.get("id"),
                "passed": not missing,
                "missing": missing,
                "recommended_next": (
                    "Capture endpoint + auth class, server-side parser library "
                    "identification, the polyglot payload bytes, and the OOB "
                    "DNS/HTTP callback (or other concrete primitive). Include "
                    "a benign upload control."
                ),
            }
        )
