"""Visual evidence capture via Playwright.

Used for candidates that need a screenshot of vulnerable UI (auth bypass
landing page, exposed admin panel, leaked data render).

Container image: `mcr.microsoft.com/playwright/python:v1.45.0-jammy`.
Local fallback: `playwright` Python package if installed in .venv-vapt.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .container import docker_run_argv

PLAYWRIGHT_IMAGE = "mcr.microsoft.com/playwright/python:v1.45.0-jammy"

CAPTURE_SCRIPT = """
import sys, json
from playwright.sync_api import sync_playwright

url = sys.argv[1]
out = sys.argv[2]
wait_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(wait_ms)
    page.screenshot(path=out, full_page=True)
    title = page.title()
    browser.close()
print(json.dumps({"url": url, "out": out, "title": title}))
"""


def write_capture_script(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "capture.py"
    path.write_text(CAPTURE_SCRIPT)
    return path


def capture_argv(
    runtime: str,
    *,
    target_url: str,
    out_dir: Path,
    script_path: Path,
    image_name: str = "screenshot.png",
    wait_ms: int = 2000,
    network: str = "bridge",
) -> list[str]:
    return docker_run_argv(
        runtime,
        PLAYWRIGHT_IMAGE,
        mounts=[
            (out_dir.resolve(), "/work", "rw"),
            (script_path.resolve().parent, "/scripts", "ro"),
        ],
        network=network,
        workdir="/work",
        entrypoint="python",
        tool_args=[f"/scripts/{script_path.name}", target_url, f"/work/{image_name}", str(wait_ms)],
    )
