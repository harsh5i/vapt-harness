from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any


@dataclasses.dataclass
class ProbeContext:
    run_dir: Path
    target: dict[str, Any]
    candidate: dict[str, Any]
    knobs: dict[str, Any]

    @property
    def candidate_id(self) -> str:
        return str(self.candidate.get("id", "CAND-UNKNOWN"))

    @property
    def evidence_dir(self) -> Path:
        path = self.run_dir / "evidence" / self.candidate_id
        path.mkdir(parents=True, exist_ok=True)
        return path


class ProbeResult(dict):
    pass


class Probe:
    name = "base"
    vuln_class = "generic"
    description = "Base probe"

    def prepare(self, ctx: ProbeContext) -> None:
        return None

    def run(self, ctx: ProbeContext) -> ProbeResult:
        raise NotImplementedError

    def cleanup(self, ctx: ProbeContext) -> None:
        return None

    def evidence(self, ctx: ProbeContext, result: dict[str, Any]) -> Path:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = ctx.evidence_dir / f"{self.name}_{stamp}.json"
        tmp = out.with_name(f"{out.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.replace(tmp, out)
        return out


def run_local_command(argv: list[str], cwd: Path, timeout: int = 60) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "cwd": str(cwd),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "cwd": str(cwd),
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timeout": True,
        }
