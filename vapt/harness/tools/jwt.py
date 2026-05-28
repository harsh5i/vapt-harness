"""JWT inspection wrapper.

Capabilities (scaffold, expanded in follow-up):

- decode: parse header + payload, surface alg, kid, jku, x5u.
- none_alg_probe: produce token with alg=none, return for caller to test.
- weak_key_probe: brute-force against a small wordlist when allowed.

Container image: `ticarpi/jwt_tool:latest` for the full toolkit.
Local: in-process via PyJWT if installed.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from .container import docker_run_argv

JWT_IMAGE = "ticarpi/jwt_tool:latest"


def _b64url_decode(segment: str) -> bytes:
    pad = -len(segment) % 4
    return base64.urlsafe_b64decode(segment + "=" * pad)


def decode_local(token: str) -> dict[str, Any]:
    """Decode without verifying. Surfaces structural risk markers."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"valid_shape": False, "error": "not three-part JWS"}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        return {"valid_shape": False, "error": f"decode: {exc}"}
    risks: list[str] = []
    if str(header.get("alg", "")).lower() == "none":
        risks.append("alg=none accepted by some libs")
    if header.get("jku") or header.get("x5u"):
        risks.append("external key URL declared; verify allowlist")
    if header.get("kid") and any(ch in str(header.get("kid")) for ch in "/.\\"):
        risks.append("kid contains path characters; check for kid injection")
    return {
        "valid_shape": True,
        "header": header,
        "payload": payload,
        "risks": risks,
        "segments": len(parts),
    }


def inspect_argv(
    runtime: str,
    *,
    token: str,
    out_dir: Path,
    network: str = "none",
) -> list[str]:
    return docker_run_argv(
        runtime,
        JWT_IMAGE,
        mounts=[(out_dir.resolve(), "/data", "rw")],
        network=network,
        tool_args=["-M", "at", "-t", token],
    )
