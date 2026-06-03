"""Tarball-vs-git supply-chain diff.

Per ``knowledge/case_studies/xz_utils_supply_chain.md``: release
tarballs published to language registries (npm, PyPI, RubyGems,
crates.io) sometimes carry files that are NOT in the corresponding
git tag. The xz-utils backdoor lived in the autoconf-generated
m4 macros shipped only in the tarball; the git tag was clean.

This probe compares two trees -- an extracted tarball and a git
checkout of the same version -- and emits one finding per
differing path.

Finding kinds:
  - ``tarball_only``    file exists only in the tarball
  - ``content_differs`` same path, different SHA-256
  - ``git_only``        file in git but not in tarball (low EV)

Severity hint:
  - HIGH    tarball_only / content_differs for code-bearing files
            (``*.js``, ``*.py``, ``*.rb``, ``*.go``, ``*.c``,
             ``*.h``, ``*.cpp``, ``*.cc``, ``*.sh``, ``*.m4``,
             ``*.so``, ``*.dylib``, ``*.dll``)
  - MEDIUM  tarball_only / content_differs for docs, configs, data
  - LOW     git_only (almost always benign omissions)

Built-in suppression: autotool-generated paths (``configure``,
``Makefile.in``, ``aclocal.m4``, ``ltmain.sh``, ``compile``,
``depcomp``, ``install-sh``, ``missing``, ``test-driver``) and
npm-generated paths (``.package-lock.json``).
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path


_AUTOGEN_PATHS = frozenset({
    "configure",
    "configure.gnu",
    "Makefile.in",
    "aclocal.m4",
    "ltmain.sh",
    "compile",
    "depcomp",
    "install-sh",
    "missing",
    "test-driver",
    "ylwrap",
    "config.guess",
    "config.sub",
    ".package-lock.json",
})

_CODE_SUFFIXES = frozenset({
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".go",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".sh", ".bash",
    ".zsh", ".m4", ".pl", ".php", ".rs", ".swift", ".java",
    ".kt", ".scala", ".clj", ".so", ".dylib", ".dll", ".node",
})


def _is_autogen(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    return base in _AUTOGEN_PATHS or rel in _AUTOGEN_PATHS


def _severity(rel: str, kind: str) -> str:
    if kind == "git_only":
        return "low"
    suffix = Path(rel).suffix.lower()
    if suffix in _CODE_SUFFIXES:
        return "high"
    return "medium"


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_WALK_SKIP_DIRS = frozenset({".git", "node_modules", ".svn", ".hg"})


def _walk_relpaths(root: Path) -> dict[str, str]:
    """Return {relpath: sha256} for every file under root.

    Skips ``.git/``, ``node_modules/``, and other VCS / vendored dirs.
    ``.git/`` in particular is noise: git checkouts always have it, npm
    tarballs never do, so a naive walk produces dozens of irrelevant
    ``git_only`` findings.
    """
    out: dict[str, str] = {}
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP_DIRS]
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                rel = full.relative_to(root)
            except ValueError:
                continue
            out[str(rel).replace(os.sep, "/")] = _sha256_of(full)
    return out


def _is_archive(p: Path) -> bool:
    name = p.name.lower()
    return p.is_file() and (
        name.endswith(".tar.gz") or name.endswith(".tgz")
        or name.endswith(".tar.bz2") or name.endswith(".tar.xz")
        or name.endswith(".tar") or name.endswith(".zip")
    )


@dataclasses.dataclass
class SupplyChainDiffer:
    suppress_autogen: bool = True

    def diff(self, *, tarball_root: Path, git_root: Path) -> list[dict]:
        tarball_root = Path(tarball_root)
        git_root = Path(git_root)
        with tempfile.TemporaryDirectory() as scratch:
            if _is_archive(tarball_root):
                extracted = self._extract(tarball_root, Path(scratch))
                tar_map = _walk_relpaths(extracted)
            else:
                tar_map = _walk_relpaths(tarball_root)
            git_map = _walk_relpaths(git_root)
        return self._diff_maps(tar_map, git_map)

    def _diff_maps(self, tar_map: dict[str, str], git_map: dict[str, str]) -> list[dict]:
        findings: list[dict] = []
        tar_keys = set(tar_map)
        git_keys = set(git_map)
        for rel in sorted(tar_keys - git_keys):
            if self.suppress_autogen and _is_autogen(rel):
                continue
            findings.append({
                "kind": "tarball_only",
                "path": rel,
                "tarball_sha256": tar_map[rel],
                "severity": _severity(rel, "tarball_only"),
            })
        for rel in sorted(tar_keys & git_keys):
            if tar_map[rel] != git_map[rel]:
                if self.suppress_autogen and _is_autogen(rel):
                    continue
                findings.append({
                    "kind": "content_differs",
                    "path": rel,
                    "tarball_sha256": tar_map[rel],
                    "git_sha256": git_map[rel],
                    "severity": _severity(rel, "content_differs"),
                })
        for rel in sorted(git_keys - tar_keys):
            if self.suppress_autogen and _is_autogen(rel):
                continue
            findings.append({
                "kind": "git_only",
                "path": rel,
                "git_sha256": git_map[rel],
                "severity": _severity(rel, "git_only"),
            })
        return findings

    @staticmethod
    def _extract(archive: Path, scratch: Path) -> Path:
        target = scratch / "extracted"
        target.mkdir()
        name = archive.name.lower()
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                # `extractall` is safe here because we control the scratch dir.
                zf.extractall(target)
        else:
            mode = "r:*"
            with tarfile.open(archive, mode) as tar:
                _safe_extract_tar(tar, target)
        # npm tarballs unpack to `package/...`; pip sdists to `pkg-1.2.3/...`.
        # If the extracted dir contains exactly one directory, use that.
        entries = list(target.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return target


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if dest != member_path and dest not in member_path.parents:
            # Path traversal attempt. Skip silently; downstream sees no file.
            continue
        tar.extract(member, dest)
