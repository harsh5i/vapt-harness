"""OWASP ZAP wrapper.

Supports two modes:

- baseline: passive crawl + alerts. Network: needs egress to target host only.
- full-scan: active scan. Same network constraint. Slower, more invasive.

Container image: `ghcr.io/zaproxy/zaproxy:stable`. The legacy
`owasp/zap2docker-stable` image still works but is deprecated upstream.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .container import docker_run_argv

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def baseline_argv(
    runtime: str,
    *,
    target_url: str,
    out_dir: Path,
    report_name: str = "zap-baseline.json",
    extra_zap_args: list[str] | None = None,
    network: str = "bridge",
) -> list[str]:
    """Build argv for `zap-baseline.py -t <url> -J <report>` in container.

    out_dir is mounted at /zap/wrk inside the container so JSON/HTML reports
    land on the host evidence pipeline.
    """
    tool_args = ["zap-baseline.py", "-t", target_url, "-J", report_name]
    if extra_zap_args:
        tool_args += list(extra_zap_args)
    return docker_run_argv(
        runtime,
        ZAP_IMAGE,
        mounts=[(out_dir.resolve(), "/zap/wrk", "rw")],
        network=network,
        workdir="/zap/wrk",
        tool_args=tool_args,
    )


def full_scan_argv(
    runtime: str,
    *,
    target_url: str,
    out_dir: Path,
    report_name: str = "zap-full.json",
    extra_zap_args: list[str] | None = None,
    network: str = "bridge",
) -> list[str]:
    tool_args = ["zap-full-scan.py", "-t", target_url, "-J", report_name]
    if extra_zap_args:
        tool_args += list(extra_zap_args)
    return docker_run_argv(
        runtime,
        ZAP_IMAGE,
        mounts=[(out_dir.resolve(), "/zap/wrk", "rw")],
        network=network,
        workdir="/zap/wrk",
        tool_args=tool_args,
    )


def parse_baseline_report(report_path: Path) -> dict[str, Any]:
    """Parse ZAP JSON report into a normalized finding list."""
    import json

    if not report_path.exists():
        return {"alerts": [], "site_count": 0, "error": "report missing"}
    try:
        raw = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        return {"alerts": [], "site_count": 0, "error": f"bad json: {exc}"}
    alerts: list[dict[str, Any]] = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append(
                {
                    "name": alert.get("name"),
                    "risk": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"),
                    "instances": len(alert.get("instances", [])),
                    "cwe": alert.get("cweid"),
                    "wasc": alert.get("wascid"),
                    "url_samples": [i.get("uri") for i in alert.get("instances", [])[:5]],
                }
            )
    return {"alerts": alerts, "site_count": len(raw.get("site", []))}
