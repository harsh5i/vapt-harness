"""sqlmap wrapper.

Container image: `paoloo/sqlmap:latest` (community-maintained mirror) or
local pip install. Always runs with `--batch --random-agent` to avoid
prompts; caller adds parametrized URL or request file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .container import docker_run_argv

SQLMAP_IMAGE = "paoloo/sqlmap:latest"


def scan_argv(
    runtime: str,
    *,
    target_url: str | None = None,
    request_file: Path | None = None,
    out_dir: Path,
    extra_args: list[str] | None = None,
    network: str = "bridge",
) -> list[str]:
    if not target_url and not request_file:
        raise ValueError("sqlmap.scan_argv requires target_url or request_file")
    tool_args = ["--batch", "--random-agent", "--output-dir=/data"]
    if target_url:
        tool_args += ["-u", target_url]
    mounts: list[tuple[Path, str, str]] = [(out_dir.resolve(), "/data", "rw")]
    if request_file:
        mounts.append((request_file.resolve().parent, "/req", "ro"))
        tool_args += ["-r", f"/req/{request_file.name}"]
    if extra_args:
        tool_args += list(extra_args)
    return docker_run_argv(
        runtime,
        SQLMAP_IMAGE,
        mounts=mounts,
        network=network,
        tool_args=tool_args,
    )


_LOG_INJECTION_RE = re.compile(
    r"sqlmap identified the following injection point\(s\)|---\s*\nParameter:",
    re.MULTILINE,
)


def parse_log(log_path: Path) -> dict[str, Any]:
    """Best-effort parse of sqlmap stdout/log into a normalized finding."""
    if not log_path.exists():
        return {"injection_found": False, "error": "log missing"}
    text = log_path.read_text(errors="replace")
    injection_blocks = re.findall(
        r"Parameter: ([^\n]+)\n((?:    [^\n]+\n)+)",
        text,
    )
    findings: list[dict[str, Any]] = []
    for param, body in injection_blocks:
        types = re.findall(r"Type: ([^\n]+)", body)
        titles = re.findall(r"Title: ([^\n]+)", body)
        findings.append(
            {
                "parameter": param.strip(),
                "types": [t.strip() for t in types],
                "titles": [t.strip() for t in titles],
            }
        )
    return {
        "injection_found": bool(findings) or bool(_LOG_INJECTION_RE.search(text)),
        "findings": findings,
    }
