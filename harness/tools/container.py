"""Shared container-invocation helpers for tool wrappers.

The harness already has `container_runtime()` and `find_tool()` in harness.py.
This module composes argv lists for tool containers in a consistent way so
each wrapper module stays focused on its tool's flags.

Policy:

- Active scanners (ZAP active, sqlmap) need network access to the declared
  target host(s). They MUST NOT have unrestricted egress. Today's container
  invocations pass through `--network <user-supplied>` and the caller is
  responsible for choosing a constrained network. A proper per-target
  allowlist is a Move 3 follow-up.
- Passive tools (JWT inspect, screenshot of allowed URL) get
  `--network bridge` or `--network none` as appropriate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def docker_run_argv(
    runtime: str,
    image: str,
    *,
    mounts: list[tuple[Path, str, str]] | None = None,
    network: str = "bridge",
    workdir: str | None = None,
    user: str | None = None,
    entrypoint: str | None = None,
    extra_flags: list[str] | None = None,
    tool_args: list[str] | None = None,
) -> list[str]:
    """Compose a container run argv.

    mounts: list of (host_path, container_path, mode) where mode in {ro, rw}.
    """
    argv: list[str] = [runtime, "run", "--rm", "--network", network]
    if workdir:
        argv += ["--workdir", workdir]
    if user:
        argv += ["--user", user]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    for host, container, mode in mounts or []:
        if mode not in {"ro", "rw"}:
            raise ValueError(f"mount mode must be ro|rw: {mode}")
        argv += ["-v", f"{host}:{container}:{mode}"]
    if extra_flags:
        argv += list(extra_flags)
    argv += [image]
    if tool_args:
        argv += list(tool_args)
    return argv


def capability_report(tool: str, runtime: str | None, local_bin: str | None, image: str) -> dict[str, Any]:
    """Describe what's available for this tool. Used by capability assessment."""
    mode = "container" if runtime else ("local" if local_bin else "unavailable")
    return {
        "tool": tool,
        "mode": mode,
        "runtime": runtime or "",
        "local_bin": local_bin or "",
        "container_image": image,
        "available": mode != "unavailable",
    }
