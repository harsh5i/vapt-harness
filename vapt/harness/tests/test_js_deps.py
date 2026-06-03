"""Tests for the JS dependency CVE matcher.

Parses ``package-lock.json`` (v1, v2, v3) and ``yarn.lock`` (v1 / Classic)
files under a target, normalises ``(name, version)`` pairs, and cross-
references against the local OSV cache (offline-safe).

Test-fixture lockfiles are intentionally minimal to keep these unit
tests deterministic and offline -- the live OSV-cache lookup is
exercised only via the dedicated mock in `test_match_against_osv_cache`.
"""
from __future__ import annotations

import json
import sqlite3
import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def parser():
    from source.js_deps import LockfileParser
    return LockfileParser()


# --- parser tests ---------------------------------------------------------

def test_parses_package_lock_v3_flat_packages(parser, tmp_path):
    lockfile = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.17.1"},
            "node_modules/@scope/pkg": {"version": "2.0.0"},
        },
    }
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps(lockfile), encoding="utf-8")
    deps = parser.parse(f)
    pairs = {(d.name, d.version) for d in deps}
    assert ("lodash", "4.17.20") in pairs
    assert ("express", "4.17.1") in pairs
    assert ("@scope/pkg", "2.0.0") in pairs
    # The root package (key="") is the project itself, not a dependency.
    assert ("demo", "1.0.0") not in pairs


def test_package_lock_v3_marks_dev_deps(parser, tmp_path):
    lockfile = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/runtime-dep": {"version": "1.0.0"},
            "node_modules/test-dep": {"version": "2.0.0", "dev": True},
        },
    }
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps(lockfile), encoding="utf-8")
    deps = {d.name: d for d in parser.parse(f)}
    assert deps["runtime-dep"].dev is False
    assert deps["test-dep"].dev is True


def test_parses_package_lock_v1_nested(parser, tmp_path):
    lockfile = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {
                "version": "4.17.15",
                "dependencies": {
                    "underscore": {"version": "1.9.0"},
                },
            },
            "express": {"version": "4.17.1", "dev": True},
        },
    }
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps(lockfile), encoding="utf-8")
    deps = {d.name: d for d in parser.parse(f)}
    assert deps["lodash"].version == "4.17.15"
    assert deps["underscore"].version == "1.9.0"  # nested transitive
    assert deps["express"].dev is True


def test_yarn_alias_resolves_to_real_package(parser, tmp_path):
    # yarn berry alias syntax: `localName@npm:realName@version` MUST emit
    # the real (name, version), otherwise OSV cache lookups match on the
    # alias and produce false positives (e.g. GitLab aliasing
    # `vue-loader` as `vue-loader-vue3` looked like the malicious
    # vue-loader-vue3 1.0.0 package per OSV MAL-2025-257).
    text = textwrap.dedent('''
        "vue-loader-vue3@npm:vue-loader@17.4.2":
          version "17.4.2"
          resolved "https://registry.yarnpkg.com/vue-loader/-/vue-loader-17.4.2.tgz"

        "ember-foo@npm:@scope/real-pkg@2.1.0":
          version "2.1.0"
          resolved "https://registry.yarnpkg.com/@scope/real-pkg/-/real-pkg-2.1.0.tgz"
    ''').strip()
    f = tmp_path / "yarn.lock"
    f.write_text(text, encoding="utf-8")
    deps = {(d.name, d.version) for d in parser.parse(f)}
    assert ("vue-loader", "17.4.2") in deps
    assert ("@scope/real-pkg", "2.1.0") in deps
    # Crucially the alias name must NOT leak in:
    assert not any(name == "vue-loader-vue3" for name, _ in deps)
    assert not any(name == "ember-foo" for name, _ in deps)


def test_parses_pnpm_lock_v9(parser, tmp_path):
    text = textwrap.dedent('''
        lockfileVersion: '9.0'

        importers:
          .:
            dependencies:
              foo:
                specifier: ^1.0.0
                version: 1.0.5

        packages:

          '@scope/pkg@2.0.0':
            resolution: {integrity: sha512-aaa==}

          'lodash@4.17.20':
            resolution: {integrity: sha512-bbb==}

          'tough-cookie@4.1.2(peerdep@1.0.0)':
            resolution: {integrity: sha512-ccc==}
    ''').strip()
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text(text, encoding="utf-8")
    deps = {d.name: d for d in parser.parse(f)}
    assert deps["@scope/pkg"].version == "2.0.0"
    assert deps["lodash"].version == "4.17.20"
    # Peer-dep suffix `(peerdep@1.0.0)` must be stripped.
    assert deps["tough-cookie"].version == "4.1.2"


def test_parses_yarn_lock_v1(parser, tmp_path):
    text = textwrap.dedent('''
        # yarn lockfile v1
        # comment

        lodash@^4.17.15, lodash@^4.17.20:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

        "@types/node@^14.0.0":
          version "14.18.10"
          resolved "https://registry.yarnpkg.com/@types/node/-/node-14.18.10.tgz"

        express@4.17.1:
          version "4.17.1"
    ''').strip()
    f = tmp_path / "yarn.lock"
    f.write_text(text, encoding="utf-8")
    deps = {d.name: d for d in parser.parse(f)}
    assert deps["lodash"].version == "4.17.21"
    assert deps["@types/node"].version == "14.18.10"
    assert deps["express"].version == "4.17.1"


def test_unknown_lockfile_returns_empty(parser, tmp_path):
    f = tmp_path / "weird.lock"
    f.write_text('"not real"', encoding="utf-8")
    assert parser.parse(f) == []


# --- discovery tests ------------------------------------------------------

def test_discover_walks_target_root(parser, tmp_path):
    (tmp_path / "frontend" / "client").mkdir(parents=True)
    (tmp_path / "frontend" / "client" / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}},
        }),
        encoding="utf-8",
    )
    (tmp_path / "another" / "yarn.lock").parent.mkdir(parents=True)
    (tmp_path / "another" / "yarn.lock").write_text(
        'express@4.17.1:\n  version "4.17.1"\n',
        encoding="utf-8",
    )
    deps = parser.discover(tmp_path)
    pairs = {(d.name, d.version) for d in deps}
    assert ("lodash", "4.17.20") in pairs
    assert ("express", "4.17.1") in pairs


def test_discover_skips_node_modules(parser, tmp_path):
    # A real npm install creates node_modules with nested lockfiles --
    # we must NOT walk into them, otherwise we double-count.
    inner = tmp_path / "node_modules" / "leftpad"
    inner.mkdir(parents=True)
    (inner / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/main": {"version": "2.0.0"}}}),
        encoding="utf-8",
    )
    deps = parser.discover(tmp_path)
    names = {d.name for d in deps}
    assert "main" in names
    assert "x" not in names


# --- OSV matcher tests ----------------------------------------------------

def _seed_osv_cache(db_path: Path, *, name: str, version: str, payload: dict) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS osv_package (
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (ecosystem, package, version)
        )
    """)
    conn.execute(
        "INSERT OR REPLACE INTO osv_package(ecosystem,package,version,fetched_at,payload) VALUES (?,?,?,?,?)",
        ("npm", name, version, "2026-06-03T00:00:00Z", json.dumps(payload)),
    )
    conn.commit()
    conn.close()


def test_match_against_osv_cache(tmp_path):
    from source.js_deps import DependencyAuditor, Dep

    db_path = tmp_path / "osv.sqlite"
    _seed_osv_cache(
        db_path,
        name="lodash",
        version="4.17.20",
        payload={"vulns": [{
            "id": "CVE-2020-28500",
            "summary": "Regex DoS in lodash",
            "database_specific": {"severity": "MEDIUM"},
        }]},
    )

    deps = [
        Dep(name="lodash", version="4.17.20", dev=False),
        Dep(name="harmless", version="1.0.0", dev=False),
    ]
    auditor = DependencyAuditor(osv_cache_path=db_path)
    findings = auditor.match(deps)
    assert len(findings) == 1
    f = findings[0]
    assert f["package"] == "lodash"
    assert f["version"] == "4.17.20"
    assert "CVE-2020-28500" in f["vuln_ids"]


def test_match_dev_dep_marked_in_finding(tmp_path):
    from source.js_deps import DependencyAuditor, Dep

    db_path = tmp_path / "osv.sqlite"
    _seed_osv_cache(
        db_path,
        name="testlib",
        version="1.0.0",
        payload={"vulns": [{"id": "CVE-2025-1", "summary": "x"}]},
    )
    findings = DependencyAuditor(osv_cache_path=db_path).match(
        [Dep(name="testlib", version="1.0.0", dev=True)]
    )
    assert findings[0]["dev"] is True


def test_no_match_when_version_clean(tmp_path):
    from source.js_deps import DependencyAuditor, Dep

    db_path = tmp_path / "osv.sqlite"
    _seed_osv_cache(db_path, name="lodash", version="4.17.21", payload={"vulns": []})
    findings = DependencyAuditor(osv_cache_path=db_path).match(
        [Dep(name="lodash", version="4.17.21", dev=False)]
    )
    assert findings == []


def test_no_cache_hit_does_not_crash(tmp_path):
    # Offline + no cache entry must produce no finding, not an error.
    from source.js_deps import DependencyAuditor, Dep

    db_path = tmp_path / "osv.sqlite"
    # Initialise empty cache schema.
    _seed_osv_cache(db_path, name="other", version="1.0", payload={"vulns": []})

    findings = DependencyAuditor(osv_cache_path=db_path).match(
        [Dep(name="unknown-pkg", version="9.9.9", dev=False)]
    )
    assert findings == []


# --- E2E probe test -------------------------------------------------------

def test_probe_run(tmp_path):
    from probes.base import ProbeContext
    from probes.js_dep_audit import JsDepAuditProbe

    # Seed cache with a known vuln
    db_path = tmp_path / "cache" / "osv.sqlite"
    _seed_osv_cache(
        db_path,
        name="left-pad",
        version="1.3.0",
        payload={"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "demo"}]},
    )
    # Seed a lockfile under the target
    (tmp_path / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/left-pad": {"version": "1.3.0"},
            },
        }),
        encoding="utf-8",
    )
    ctx = ProbeContext(
        run_dir=tmp_path,
        target={"local_path": str(tmp_path)},
        candidate={"id": "CAND-DEP"},
        knobs={"osv_cache_path": str(db_path)},
    )
    result = JsDepAuditProbe().run(ctx)
    assert result["name"] == "js_dep_audit"
    assert result["finding_count"] == 1
    assert result["findings"][0]["package"] == "left-pad"
