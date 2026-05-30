"""Tool runtime layer: container/local discovery, sandboxed exec, capped-output
materialization, and the missing-tool refuse path. The cmd_scan_* handlers in
harness.py drive their actual subprocesses through this module.

The capped-output rule and the refuse-missing-tool rule are load-bearing:
- run_tool_scan caps every captured stream so a runaway scanner cannot exhaust
  disk via .out / .err files.
- refuse_missing_tool writes a structured JSON refusal record and exits 2 —
  never silently skipping a scanner because a binary is absent.

Depends only on the leaf layers (core, atomic_io) plus the stdlib.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import importlib
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from atomic_io import write_json, write_text
from core import ROOT, VAPT_LOCAL_BIN, VAPT_VENV_BIN, rel


def container_runtime() -> str | None:
    for runtime in ("docker", "podman"):
        found = shutil.which(runtime)
        if found:
            return found
    return None


def macos_sandbox_exec() -> str | None:
    if sys.platform != "darwin":
        return None
    return shutil.which("sandbox-exec")


def find_tool(tool_name: str) -> str | None:
    for local_dir in (VAPT_LOCAL_BIN, VAPT_VENV_BIN):
        local = local_dir / tool_name
        if local.exists() and os.access(local, os.X_OK):
            return str(local)
    path = os.environ.get("PATH", "")
    prefixed_path = os.pathsep.join([str(VAPT_LOCAL_BIN), str(VAPT_VENV_BIN), path])
    found = shutil.which(tool_name, path=prefixed_path)
    if found:
        return found
    return None


def tool_env(tool_name: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(
        [str(VAPT_LOCAL_BIN), str(VAPT_VENV_BIN), env.get("PATH", "")]
    )
    if tool_name in {"nuclei", "subfinder", "katana", "naabu", "httpx", "tlsx", "semgrep"}:
        home = ROOT / ".vapt-home"
        home.mkdir(parents=True, exist_ok=True)
        env["HOME"] = str(home)
    if tool_name == "semgrep":
        env.setdefault("SEMGREP_SEND_METRICS", "off")
        env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
        try:
            import certifi  # type: ignore

            ca_bundle = certifi.where()
            env.setdefault("SSL_CERT_FILE", ca_bundle)
            env.setdefault("REQUESTS_CA_BUNDLE", ca_bundle)
        except Exception:
            pass
    return env


def tool_scan_base(run_dir: Path, tool_name: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = run_dir / "tool_scans" / tool_name
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{tool_name}_{stamp}"


def refuse_missing_tool(base: Path, tool_name: str, install_hint: str = "") -> None:
    result = {
        "status": "refused",
        "reason": f"{tool_name} not found in PATH",
        "tool": tool_name,
        "install_hint": install_hint,
        "at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    write_json(base.with_suffix(".missing.json"), result)
    print(rel(base.with_suffix(".missing.json")))
    raise SystemExit(2)


def materialize_capped_file(raw_path: Path, text_path: Path, max_output_chars: int) -> bool:
    truncated = False
    written = 0
    with raw_path.open("rb") as src_fh, text_path.open("wb") as dst_fh:
        while True:
            chunk = src_fh.read(65536)
            if not chunk:
                break
            remaining = max_output_chars - written
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                dst_fh.write(chunk[:remaining])
                written += remaining
                truncated = True
                break
            dst_fh.write(chunk)
            written += len(chunk)
        if truncated or src_fh.read(1):
            dst_fh.write(b"\n[truncated]\n")
            truncated = True
    return truncated


def run_tool_scan(
    argv: list[str],
    cwd: Path,
    base: Path,
    timeout: int,
    max_output_chars: int = 300000,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    raw_out = base.with_suffix(".out.raw")
    raw_err = base.with_suffix(".err.raw")
    timed_out = False
    try:
        with raw_out.open("wb") as out_fh, raw_err.open("wb") as err_fh:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                env=env,
                text=False,
                stdout=out_fh,
                stderr=err_fh,
                start_new_session=True,
            )
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
                returncode = 124
    except FileNotFoundError as exc:
        raw_out.write_bytes(b"")
        raw_err.write_bytes(str(exc).encode("utf-8"))
        returncode = 127

    stdout_truncated = materialize_capped_file(raw_out, base.with_suffix(".out"), max_output_chars)
    stderr_truncated = materialize_capped_file(raw_err, base.with_suffix(".err"), max_output_chars)
    record = {
        "argv": argv,
        "cwd": str(cwd),
        "timeout_seconds": timeout,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout": rel(base.with_suffix(".out")),
        "stderr": rel(base.with_suffix(".err")),
        "stdout_raw": rel(raw_out),
        "stderr_raw": rel(raw_err),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "status": rel(base.with_suffix(".status")),
        "command_record": rel(base.with_suffix(".cmd.json")),
    }
    write_json(base.with_suffix(".cmd.json"), record)
    write_text(base.with_suffix(".status"), str(returncode) + "\n")
    write_json(base.with_suffix(".summary.json"), record)
    return record


def _ensure_runtime_or_local(tool_name: str, local_binary_name: str | None, base: Path, install_hint: str) -> tuple[str | None, str | None]:
    """Return (container_runtime_path, local_bin_path) or refuse."""
    runtime = container_runtime()
    local_bin = find_tool(local_binary_name) if local_binary_name else None
    if not runtime and not local_bin:
        refuse_missing_tool(base, tool_name, install_hint)
    return runtime, local_bin


def _load_tool_module(name: str) -> Any:
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    return importlib.import_module(f"tools.{name}")
