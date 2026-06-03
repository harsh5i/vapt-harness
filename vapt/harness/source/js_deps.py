"""JS dependency lockfile parser + OSV cache matcher.

Parses ``package-lock.json`` (v1 nested, v2/v3 flat ``packages``) and
``yarn.lock`` (v1 / Classic) files and emits ``Dep(name, version, dev)``
records. Cross-references against the local OSV cache (shared with
``gates/osv.py``) -- network-free, offline-safe.

Cross-reference: ``knowledge/case_studies/portswigger_top10_2024.md``
(Top-10 #4, #6) for inherited client-side CVE patterns.

Out of scope (defer until a target needs it):
  - yarn.lock v2 / Berry (YAML)
  - pnpm-lock.yaml (custom YAML)
  - composer.lock (PHP)
  - Pipfile.lock / requirements.txt (Python -- already handled by
    pip-audit / OSV-Scanner wrappers in tools/commands.py)

The matcher does NOT decide exploitability. A CVE'd transitive dep
may be unreachable in the running app; the operator confirms via
``patch_variant_hunter`` / source-probe.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sqlite3
from pathlib import Path
from typing import Iterable


# --- Dep record -----------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Dep:
    name: str
    version: str
    dev: bool = False


# --- Lockfile parser ------------------------------------------------------

# yarn.lock v1 header line: `pkg@spec, pkg@spec2:` -- we want the package
# name out of the first spec. Names may be scoped (``@scope/name``).
_YARN_HEADER_RE = re.compile(
    r'^"?(?P<name>(?:@[^/]+/)?[^@\s"]+)@'
)


def _yarn_unquote(name: str) -> str:
    return name.strip().strip('"')


class LockfileParser:
    def parse(self, path: Path) -> list[Dep]:
        path = Path(path)
        if path.name == "package-lock.json":
            return self._parse_package_lock(path)
        if path.name == "yarn.lock":
            return self._parse_yarn_lock(path)
        if path.name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(path)
        return []

    def discover(
        self,
        root: Path,
        *,
        skip_dirs: Iterable[str] = ("node_modules", ".git", ".venv", "venv", "dist", "build"),
    ) -> list[Dep]:
        root = Path(root)
        skip = set(skip_dirs)
        out: list[Dep] = []
        # rglob and prune as we go.
        for p in self._iter_lockfiles(root, skip):
            out.extend(self.parse(p))
        return out

    @staticmethod
    def _iter_lockfiles(root: Path, skip: set[str]) -> Iterable[Path]:
        targets = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
        # os.walk-style iteration so we can prune.
        import os
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fname in filenames:
                if fname in targets:
                    yield Path(dirpath) / fname

    # ---- package-lock.json ----

    def _parse_package_lock(self, path: Path) -> list[Dep]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return []
        out: list[Dep] = []
        # v2/v3: flat ``packages`` keyed by path; "" is the project root.
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, entry in packages.items():
                if not isinstance(entry, dict) or key == "":
                    continue
                version = entry.get("version")
                if not version:
                    continue
                name = self._name_from_packages_key(key, entry)
                if not name:
                    continue
                out.append(Dep(
                    name=name,
                    version=str(version),
                    dev=bool(entry.get("dev", False) or entry.get("devOptional", False)),
                ))
            if out:
                return out

        # v1: nested ``dependencies`` tree.
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            self._walk_v1_deps(deps, out, dev_parent=False)
        return out

    @staticmethod
    def _name_from_packages_key(key: str, entry: dict) -> str | None:
        # The key looks like ``node_modules/foo`` or
        # ``node_modules/@scope/foo`` or ``node_modules/parent/node_modules/foo``.
        # We want the LAST ``node_modules/...`` segment.
        if "node_modules/" not in key:
            return entry.get("name")
        last = key.rsplit("node_modules/", 1)[-1]
        # Scope: ``@scope/name``; otherwise ``name``.
        return last or None

    def _walk_v1_deps(self, deps: dict, out: list[Dep], *, dev_parent: bool) -> None:
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if not version:
                continue
            is_dev = bool(entry.get("dev", False)) or dev_parent
            out.append(Dep(name=str(name), version=str(version), dev=is_dev))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                self._walk_v1_deps(nested, out, dev_parent=is_dev)

    # ---- yarn.lock v1 ----

    def _parse_yarn_lock(self, path: Path) -> list[Dep]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        out: list[Dep] = []
        current_name: str | None = None
        current_version: str | None = None
        for line in text.splitlines():
            if not line:
                # blank line ends the current block
                if current_name and current_version:
                    out.append(Dep(name=current_name, version=current_version, dev=False))
                current_name = None
                current_version = None
                continue
            if line.startswith("#"):
                continue
            stripped = line.strip()
            # Block header: starts at column 0, ends with `:` and contains `@`.
            if not line.startswith(" ") and stripped.endswith(":") and "@" in stripped:
                # Flush prior block if it was missing the trailing blank.
                if current_name and current_version:
                    out.append(Dep(name=current_name, version=current_version, dev=False))
                    current_version = None
                header = stripped.rstrip(":")
                # First spec: ``"pkg@spec"`` or ``pkg@spec``.
                first_spec = _yarn_unquote(header.split(",")[0].strip())
                # Yarn-berry alias form: ``localName@npm:realName@range``.
                # The ``@npm:`` marker means the local name is just an
                # import alias; the real package is everything between
                # ``@npm:`` and the trailing ``@<range>``. OSV cache
                # lookups must use the REAL package name (otherwise an
                # alias collides with a malicious package of the same
                # local name -- see MAL-2025-257 false positive on
                # GitLab's `vue-loader-vue3` alias of `vue-loader`).
                if "@npm:" in first_spec:
                    after_marker = first_spec.split("@npm:", 1)[1]
                    real_name, _, _range = after_marker.rpartition("@")
                    current_name = real_name or None
                else:
                    m = _YARN_HEADER_RE.match(first_spec)
                    current_name = _yarn_unquote(m.group("name")) if m else None
                current_version = None
                continue
            # Body line: `  version "1.2.3"`
            if current_name and stripped.startswith("version "):
                raw = stripped[len("version "):].strip().strip('"')
                current_version = raw
        # Trailing block.
        if current_name and current_version:
            out.append(Dep(name=current_name, version=current_version, dev=False))
        return out


    # ---- pnpm-lock.yaml (v6+ format) ----

    # pnpm v9 package key example: `'@scope/pkg@2.0.0':` or `'pkg@1.0.0(peer@2.0.0)':`.
    # We do a minimal text walk rather than pulling in PyYAML; the format is
    # regular enough that the harness ships YAML-free.
    _PNPM_KEY_RE = re.compile(r"^\s\s'?(?P<spec>[^':]+(?:@[^':]+)?)'?:\s*$")
    _PNPM_PACKAGE_HEADER_RE = re.compile(r"^packages:\s*$")

    def _parse_pnpm_lock(self, path: Path) -> list[Dep]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        out: list[Dep] = []
        in_packages = False
        for line in text.splitlines():
            if not in_packages:
                if self._PNPM_PACKAGE_HEADER_RE.match(line):
                    in_packages = True
                continue
            # A subsequent top-level section header (no indent, ends with `:`)
            # ends the packages block.
            if line and not line.startswith(" ") and line.rstrip().endswith(":"):
                break
            m = self._PNPM_KEY_RE.match(line)
            if not m:
                continue
            spec = m.group("spec").strip()
            # Strip any trailing `(peer@...)` parenthetical.
            if "(" in spec:
                spec = spec.split("(", 1)[0]
            # Last `@` separates name from version. Scopes start with `@`,
            # so use rsplit on `@` and require the version part to be
            # version-shaped (starts with a digit or `0-9` after optional `v`).
            if "@" not in spec[1:]:
                continue
            name, _, version = spec.rpartition("@")
            if not name or not version:
                continue
            # Filter spec parts that aren't package entries (e.g. `link:` /
            # `file:` / patch-only entries pnpm sometimes emits).
            if name.startswith("file:") or name.startswith("link:"):
                continue
            out.append(Dep(name=name, version=version, dev=False))
        return out


# --- OSV matcher ----------------------------------------------------------

@dataclasses.dataclass
class DependencyAuditor:
    osv_cache_path: Path | None = None
    ecosystem: str = "npm"

    def match(self, deps: list[Dep]) -> list[dict]:
        if not deps or self.osv_cache_path is None:
            return []
        path = Path(self.osv_cache_path)
        if not path.exists():
            return []
        out: list[dict] = []
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.OperationalError:
            return []
        try:
            cur = conn.cursor()
            for dep in deps:
                row = cur.execute(
                    "SELECT payload FROM osv_package WHERE ecosystem=? AND package=? AND version=?",
                    (self.ecosystem, dep.name, dep.version),
                ).fetchone()
                if not row:
                    continue
                try:
                    payload = json.loads(row[0])
                except json.JSONDecodeError:
                    continue
                vulns = payload.get("vulns") or []
                if not vulns:
                    continue
                vuln_ids = [v.get("id") for v in vulns if v.get("id")]
                summaries = [v.get("summary", "") for v in vulns]
                severities = [
                    (v.get("database_specific", {}) or {}).get("severity")
                    for v in vulns
                ]
                out.append({
                    "package": dep.name,
                    "version": dep.version,
                    "dev": dep.dev,
                    "ecosystem": self.ecosystem,
                    "vuln_ids": vuln_ids,
                    "summaries": summaries,
                    "severities": [s for s in severities if s],
                })
        finally:
            conn.close()
        return out
