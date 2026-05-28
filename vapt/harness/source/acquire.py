"""Source acquisition.

Clones a repo at a locked commit SHA into a sandbox dir under
`vapt/harness/source_cache/<owner>/<repo>/<sha>/`. Idempotent: if the
target exists with the expected SHA, reuse it.

Local-path passthrough: if `repo_url` is a local filesystem path, no
network is touched.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def cache_root(root: Path) -> Path:
    return root / "vapt" / "harness" / "source_cache"


def _repo_slug(repo_url: str) -> str:
    if "://" in repo_url:
        tail = repo_url.split("://", 1)[1]
    else:
        tail = repo_url
    tail = tail.rstrip("/")
    if tail.endswith(".git"):
        tail = tail[:-4]
    parts = re.split(r"[\\/]+", tail)
    return "_".join(p for p in parts if p)[:160] or "repo"


def _resolve_head_sha(path: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    return out.decode().strip() or None


def acquire(*, root: Path, repo_url: str, commit: str | None = None) -> dict[str, Any]:
    """Materialize a local checkout. Returns descriptor with the locked sha."""
    if not repo_url:
        raise ValueError("repo_url required")
    local_passthrough = repo_url.startswith("/") or repo_url.startswith("file://")
    if local_passthrough:
        local_path = Path(repo_url.replace("file://", "")).resolve()
        if not local_path.exists():
            raise FileNotFoundError(str(local_path))
        sha = commit or _resolve_head_sha(local_path) or "local"
        return {
            "repo_url": repo_url,
            "commit": sha,
            "path": str(local_path),
            "mode": "local",
        }
    slug = _repo_slug(repo_url)
    cache = cache_root(root) / slug
    cache.mkdir(parents=True, exist_ok=True)
    target_sha = commit or "HEAD"
    target = cache / target_sha
    if target.exists():
        sha = _resolve_head_sha(target) or target_sha
        return {"repo_url": repo_url, "commit": sha, "path": str(target), "mode": "cache"}
    workdir = cache / f"{target_sha}.tmp"
    if workdir.exists():
        shutil.rmtree(workdir)
    try:
        subprocess.check_call(
            ["git", "clone", "--quiet", "--filter=blob:none", repo_url, str(workdir)],
            stderr=subprocess.STDOUT,
        )
        if commit:
            subprocess.check_call(
                ["git", "-C", str(workdir), "checkout", "--quiet", commit],
                stderr=subprocess.STDOUT,
            )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        raise RuntimeError(f"git acquire failed: {exc}")
    workdir.rename(target)
    sha = _resolve_head_sha(target) or target_sha
    return {"repo_url": repo_url, "commit": sha, "path": str(target), "mode": "fresh"}
