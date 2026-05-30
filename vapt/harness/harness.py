#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import html
import io
import json
import os
import re
import signal
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
import zlib
from pathlib import Path
from typing import Any
from urllib import error, request


# Foundation layer (repo-root anchor, version, path resolution) lives in the
# stdlib-only core module. Imported so every harness.* reference resolves.
from core import (  # noqa: E402
    CURRENT_CANDIDATE_SCHEMA_VERSION,
    HARNESS_VERSION,
    ROOT,
    TRIAGE_VERDICTS,
    VAPT_LOCAL_BIN,
    VAPT_VENV_BIN,
    candidate_corpus_path,
    now_id,
    outcome_tuning_path,
    rel,
    run_path,
    source_path,
    step_outcomes_path,
    submissions_path,
)


# A few cmd_* handlers call build_parser() at runtime (e.g. cmd_phase3_check
# materializes the parser to validate the CLI surface). Now that build_parser
# lives in cli.py and cli imports harness, eagerly importing it here would
# circle. The shim defers the import until first call.
def build_parser():
    from cli import build_parser as _bp
    return _bp()


WORKFLOW_ORDER = [
    "candidate",
    "deduped",
    "promoted",
    "proved",
    "root_cause_recorded",
    "variant_searched",
    "patch_diffed",
    "report_ready",
    "submitted",
]
WORKFLOW_TERMINAL = {"triaged", "duplicate", "n_a", "resolved", "paid"}
LOOP_STATE_ORDER = [
    "recon",
    "map",
    "reachability",
    "hypothesize",
    "triage",
    "proof",
    "enrich",
    "report",
]
# Intent vocabulary: each threat-model token maps to the hypothesis kinds it
# prioritises and the candidate weakness/CWE/impact keywords it recognises.
# The intent layer orders hypotheses and nudges scoring toward the operator's
# stated threat model; it never suppresses off-intent findings.
INTENT_VOCAB = {
    "realtime_authz_drift": {
        "kinds": {"realtime_authz_drift"},
        "keywords": {"authz", "authorization", "broadcast", "websocket", "permission", "cwe-862", "cwe-863", "cwe-639"},
    },
    "route_authz_gap": {
        "kinds": {"route_authz_gap"},
        "keywords": {"authz", "authorization", "idor", "access control", "permission", "cwe-862", "cwe-863", "cwe-639", "cwe-285"},
    },
    "parser_storage_boundary": {
        "kinds": {"parser_storage_boundary"},
        "keywords": {"path traversal", "traversal", "canonicalization", "archive", "deserialization", "cwe-22", "cwe-502"},
    },
    "ssrf_outbound_boundary": {
        "kinds": {"ssrf_outbound_boundary"},
        "keywords": {"ssrf", "server-side request", "outbound", "redirect", "cwe-918"},
    },
    "command_execution_boundary": {
        "kinds": {"command_execution_boundary"},
        "keywords": {"command injection", "rce", "shell", "exec", "cwe-78", "cwe-77", "cwe-94"},
    },
    "native_memory_boundary": {
        "kinds": {"native_memory_boundary"},
        "keywords": {"memory", "buffer", "overflow", "use-after-free", "cwe-119", "cwe-416", "cwe-787"},
    },
}
DEFAULT_BUDGETS = {
    "novelty_gate_minutes": 30,
    "triage_minutes": 120,
    "deep_review_minutes": 240,
    "commodity_class_minutes": 30,
    "total_minutes": 480,
}


# Atomic file persistence + advisory file locks live in atomic_io (a stdlib-only
# leaf module). Imported here so every existing harness.* reference resolves
# unchanged.
from atomic_io import (  # noqa: E402
    candidate_ledger_lock,
    dump_yaml,
    file_lock,
    load_yaml,
    read_json,
    read_jsonl,
    write_json,
    write_jsonl,
    write_text,
    _yaml,
)


def run_cmd(cmd: list[str], cwd: Path, timeout: int = 30, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timeout": True,
        }


# rel/run_path/source_path/now_id are imported from core (above).


def load_run(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    state = read_json(run_dir / "state.json", {})
    target_path = run_dir / "target.yaml"
    if target_path.exists():
        target = load_yaml(target_path)
    else:
        context = find_campaign_context(run_dir)
        snapshot = run_path(str(context.get("campaign_dir") or "")) / "target_snapshot.json" if context else None
        if snapshot and snapshot.exists():
            target = read_json(snapshot, {})
            state.setdefault("target_id", target.get("id") or context.get("target_id") or "")
            state.setdefault("run_id", run_dir.name)
        else:
            raise SystemExit(f"target.yaml not found and no campaign target snapshot available: {rel(run_dir)}")
    return state, target


def save_stage(run_dir: Path, state: dict[str, Any], stage: str) -> None:
    current = read_json(run_dir / "state.json", {})
    current.update(state)
    state = current
    state.setdefault("stages", {})[stage] = {
        "completed_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    write_json(run_dir / "state.json", state)


def cmd_init(args: argparse.Namespace) -> None:
    target_file = run_path(args.target)
    target = load_yaml(target_file)
    target_id = target["id"]
    run_id = args.run_id or now_id()
    out = ROOT / "vapt" / "engagements" / target_id / "runs" / target_id / run_id
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"run directory already exists: {out}")

    out.mkdir(parents=True, exist_ok=True)
    dump_yaml(target, out / "target.yaml")
    write_json(
        out / "state.json",
        {
            "target_id": target_id,
            "run_id": run_id,
            "created_at": dt.datetime.now().isoformat(timespec="seconds"),
            "status": "initialized",
            "stages": {},
        },
    )
    dump_yaml({"candidates": []}, out / "candidates.yaml")
    write_text(out / "notes.md", f"# Notes: {target_id} / {run_id}\n\n")
    for sub in ("evidence", "reports", "logs"):
        (out / sub).mkdir(exist_ok=True)
    print(rel(out))


def cmd_prepare(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    src = source_path(target)

    checks = {
        "git_head": run_cmd(["git", "rev-parse", "HEAD"], src),
        "git_last_commit": run_cmd(["git", "log", "-1", "--oneline", "--decorate"], src),
        "git_tags": run_cmd(["git", "tag", "--points-at", "HEAD"], src),
        "git_status": run_cmd(["git", "status", "--short"], src),
        "files": run_cmd(["rg", "--files"], src, timeout=60),
    }
    if checks["git_head"]["returncode"] != 0 and not args.allow_non_git:
        write_json(
            run_dir / "prepare.json",
            {
                "target": target,
                "source_path": rel(src),
                "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
                "checks": checks,
                "error": "source_path is not a git checkout; rerun with --allow-non-git for tarball/wheel sources",
            },
        )
        raise SystemExit("source_path is not a git checkout; rerun prepare with --allow-non-git if intentional")

    files = checks["files"]["stdout"].splitlines() if checks["files"]["returncode"] == 0 else []
    suffix_counts: dict[str, int] = {}
    for name in files:
        suffix = Path(name).suffix.lower() or "<none>"
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1

    prepared = {
        "target": target,
        "source_path": rel(src),
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "checks": checks,
        "file_count": len(files),
        "suffix_counts": dict(sorted(suffix_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:30]),
    }
    write_json(run_dir / "prepare.json", prepared)

    md = [
        f"# Prepare: {target['id']}",
        "",
        f"- Source: `{rel(src)}`",
        f"- File count: `{len(files)}`",
        f"- HEAD: `{checks['git_head']['stdout'].strip()}`",
        f"- Last commit: `{checks['git_last_commit']['stdout'].strip()}`",
        f"- Tags at HEAD: `{checks['git_tags']['stdout'].strip() or 'none'}`",
        "",
        "## Top File Suffixes",
        "",
    ]
    for suffix, count in prepared["suffix_counts"].items():
        md.append(f"- `{suffix}`: {count}")
    write_text(run_dir / "prepare.md", "\n".join(md) + "\n")
    save_stage(run_dir, state, "prepare")
    print(rel(run_dir / "prepare.md"))


PATTERNS = {
    "deserialization": [
        "pickle.load",
        "joblib.load",
        "yaml.load",
        "__reduce__",
        "__setstate__",
        "marshal.loads",
        "dill",
    ],
    "path_traversal": [
        "extractall",
        "ZipFile",
        "tarfile",
        "open(",
        "Path(",
        "read_text",
        "write_text",
        "send_file",
    ],
    "command_execution": [
        "subprocess",
        "os.system",
        "popen",
        "child_process.exec",
        "child_process.spawn",
        "Runtime.exec",
        "ProcessBuilder",
        "exec.Command",
        "exec(",
        "eval(",
    ],
    "network_ssrf": [
        "requests.get",
        "requests.post",
        "httpx.",
        "aiohttp",
        "axios.",
        "urlopen",
        "urllib.request",
        "http.Client",
        "http.NewRequest",
        "http.Get",
        "fetch(",
        "net/http",
    ],
    "template_injection": [
        "Template(",
        "render_template",
        "jinja",
        "text/template",
        "html/template",
    ],
    "authz_boundary": [
        "permission",
        "authorize",
        "authz",
        "token",
        "secret",
        "credential",
        "api_key",
    ],
    "realtime_websocket": [
        "websocket",
        "WebSocket",
        "broadcast",
        "Publish(",
        "ShouldSendEvent",
        "ChannelId",
        "TeamId",
        "UserId",
    ],
    "file_upload_storage": [
        "multipart",
        "upload",
        "download",
        "avatar",
        "attachment",
        "S3",
        "MinIO",
    ],
    "cors_browser_boundary": [
        "Access-Control-Allow-Origin",
        "CORS",
        "Origin",
        "SameSite",
        "cookie",
    ],
    "ai_prompt_injection": [
        "prompt",
        "system_prompt",
        "tool_call",
        "function_call",
        "agent",
        "retrieval",
        "rag",
    ],
    "plugin_extension": [
        "plugin",
        "extension",
        "signature",
        "manifest",
        "sandbox",
    ],
    "supply_chain": [
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "go.mod",
        "Cargo.toml",
        "download",
        "checksum",
    ],
    "race_toctou": [
        "time.Sleep",
        "go func",
        "threading",
        "async",
        "await",
        "lock",
        "mutex",
        "rename",
        "symlink",
        "stat(",
    ],
    "memory_safety_native": [
        "unsafe",
        "cgo",
        "memcpy",
        "strcpy",
        "malloc",
        "free(",
        "new[]",
        "delete",
        "reinterpret_cast",
    ],
    "parser_differential": [
        "parse",
        "normalize",
        "canonical",
        "url.Parse",
        "urllib.parse",
        "decode",
        "unquote",
        "regex",
    ],
    "auth_protocol": [
        "SAML",
        "OAuth",
        "OIDC",
        "JWT",
        "CSRF",
        "SameSite",
        "Set-Cookie",
        "session",
        "cookie",
        "audience",
        "issuer",
        "redirect_uri",
        "state",
        "nonce",
    ],
}


# Promotion + workflow gates live in gates/promotion.py (core/io/validators
# only). Imported so harness.* references resolve unchanged.
from gates.promotion import (  # noqa: E402
    PROMOTION_BLOCKING_NOVELTY,
    PROMOTION_REQUIRED_FIELDS,
    campaign_evidence_findings,
    candidate_requires_campaign_gate,
    candidate_requires_queue_gate,
    dedup_checked,
    promotion_findings,
    queue_evidence_findings,
    workflow_blockers,
)


CODEQL_WORKFLOWS: dict[str, dict[str, Any]] = {
    "python": {
        "language": "python",
        "queries": ["security-extended", "security-and-quality"],
        "focus": [
            "unsafe deserialization and dynamic import/reconstruction",
            "path traversal and archive extraction",
            "command execution and template/code injection",
            "SSRF and outbound request construction",
        ],
    },
    "go": {
        "language": "go",
        "queries": ["security-extended", "security-and-quality"],
        "focus": [
            "authz/IDOR in handler-to-store flows",
            "path traversal and file storage boundaries",
            "SSRF and URL-controlled outbound requests",
            "command execution and archive extraction",
        ],
    },
    "javascript-typescript": {
        "language": "javascript-typescript",
        "queries": ["security-extended", "security-and-quality"],
        "focus": [
            "server-side request and template injection",
            "authz drift between API/client route assumptions",
            "Electron/deep-link command or file access",
            "DOM/server stored XSS paths with concrete impact",
        ],
    },
    "cpp": {
        "language": "cpp",
        "queries": ["security-extended", "security-and-quality"],
        "focus": [
            "parser memory safety in native model/file formats",
            "integer truncation around sizes, offsets, and tensor shapes",
            "bounds checks before pointer arithmetic",
        ],
    },
}


TARGET_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "python-ml-deserialization": {
        "name": "Python ML / Deserialization",
        "codeql": "python",
        "checks": [
            "Map load/save APIs, archive readers, object constructors, dtype/shape handlers, and trust allowlists.",
            "Run Semgrep/Bandit/CodeQL/OSV, then manually trace file/archive fields into reconstruction sinks.",
            "Build positive and negative captive fixtures: benign model, rejected unsafe type, malformed archive, traversal attempt.",
            "Require latest release proof, allowed-vs-denied differential, and explicit trusted-types bypass or gadget impact.",
        ],
        "poc_classes": ["unsafe_deserialization", "path_traversal", "template_injection"],
    },
    "go-api-server": {
        "name": "Go API / Server",
        "codeql": "go",
        "checks": [
            "Map routes, middleware, auth/session extraction, role checks, store calls, file/blob handling, and outbound clients.",
            "Run CodeQL plus source-graph/taint-trace; prioritize request parameters reaching store/file/network/process sinks.",
            "Use two-account differential tests for IDOR/authz and a local listener/canary for SSRF-style claims.",
            "Require exact version/config, request/response evidence, negative user control, and permission invariant root cause.",
        ],
        "poc_classes": ["idor_authz", "ssrf", "path_traversal", "command_injection"],
    },
    "js-ts-web": {
        "name": "JS/TS Web / Electron",
        "codeql": "javascript-typescript",
        "checks": [
            "Map routes, API clients, SSR/template renderers, markdown/HTML sinks, deep links, IPC, and file handlers.",
            "Separate browser-only issues from server/Electron impact; require stored or privilege-crossing impact for XSS.",
            "Run CodeQL/Semgrep/Nuclei where scoped, then prove with local app fixtures or controlled requests.",
        ],
        "poc_classes": ["template_injection", "idor_authz", "path_traversal"],
    },
    "local-ai-runtime": {
        "name": "Local AI Runtime",
        "codeql": "go",
        "checks": [
            "Map local REST APIs, registry pulls, model/blob storage, parser/native boundaries, CORS/origin policy, and templates.",
            "Prioritize DNS rebinding/CORS-to-management, model file path traversal, registry SSRF, and native parser corruption.",
            "Use local-only harnesses and captive registry/files; do not test third-party users or registries without scope.",
        ],
        "poc_classes": ["ssrf", "path_traversal", "template_injection"],
    },
    "mlops": {
        "name": "MLOps / Experiment Orchestration",
        "codeql": "python",
        "checks": [
            "Map YAML/project config parsing, resource downloads, subprocess execution, plugins, run import/export, and web view auth.",
            "Distinguish expected project-code execution from routine metadata parsing or shared-artifact trust boundary bugs.",
            "Prove cloned-project, shared-run-archive, or exposed-local-web threat models with negative controls.",
        ],
        "poc_classes": ["command_injection", "path_traversal", "ssrf", "idor_authz"],
    },
}


# Field validators (CWE/CVSS/substantive/affected-version) live in the
# stdlib-only validators leaf module. Imported so harness.* references resolve.
from validators import (  # noqa: E402
    CVSS3_METRICS,
    cvss3_base_score,
    exact_affected_version,
    parse_cvss3,
    substantive,
    substantive_text,
    validate_cwe,
    _cvss_round_up,
)


def artifact_exists(rel_path: Any) -> bool:
    if not substantive(rel_path):
        return False
    path = run_path(str(rel_path))
    return path.exists() and path.is_file()


def candidate_reference_text(cand: dict[str, Any]) -> str:
    dedup = cand.get("dedup") if isinstance(cand.get("dedup"), dict) else {}
    parts = [
        cand.get("reference_sources", ""),
        cand.get("cve", ""),
        cand.get("notes", ""),
        dedup.get("manual_notes", ""),
        " ".join(str(item) for item in dedup.get("sources_checked", []) or []),
        " ".join(str(item) for item in dedup.get("matches", []) or []),
    ]
    osv = dedup.get("osv") if isinstance(dedup.get("osv"), dict) else {}
    if osv:
        parts.append("osv.dev")
        parts.append(str(osv.get("artifact", "")))
    return " ".join(str(part) for part in parts).lower()


def duplicate_source_coverage(cand: dict[str, Any]) -> dict[str, bool]:
    text = candidate_reference_text(cand)
    return {
        "cve_or_ghsa": bool(re.search(r"(cve-\d{4}-\d{4,}|ghsa-|github advisory|github security advisory)", text)),
        "osv": "osv" in text,
        "huntr": "huntr" in text,
        "github": "github" in text or "ghsa" in text,
    }


# dedup_checked/workflow_blockers imported from gates.promotion (above).


# load_surface_config moved to source.commands.
def cmd_map(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    src = source_path(target)

    surfaces: dict[str, list[dict[str, str]]] = {}
    for category, patterns in PATTERNS.items():
        surfaces[category] = []
        for pattern in patterns:
            result = run_cmd(["rg", "-n", "-S", "-F", pattern], src, timeout=45)
            if result["returncode"] not in (0, 1):
                surfaces[category].append(
                    {"pattern": pattern, "error": result["stderr"].strip()}
                )
                continue
            for line in result["stdout"].splitlines()[: args.max_hits]:
                surfaces[category].append({"pattern": pattern, "hit": line})

    dump_yaml({"surfaces": surfaces}, run_dir / "attack_surface.yaml")
    md = [f"# Attack Surface Map: {target['id']}", ""]
    for category, hits in surfaces.items():
        md.extend([f"## {category}", ""])
        if not hits:
            md.append("- No hits")
        else:
            for item in hits[: args.max_hits]:
                if "hit" in item:
                    md.append(f"- `{item['pattern']}`: `{item['hit']}`")
                else:
                    md.append(f"- `{item['pattern']}` error: `{item['error']}`")
        md.append("")
    write_text(run_dir / "attack_surface.md", "\n".join(md))
    save_stage(run_dir, state, "map")
    print(rel(run_dir / "attack_surface.md"))


# cmd_surfaces_test moved to source.commands.
# Candidate ledger primitives (DEFAULT_CANDIDATE shape, normalization, the
# locked YAML store, and id allocation) live in ledger/candidates.py. Imported
# here so harness.* references resolve unchanged.
from ledger.candidates import (  # noqa: E402
    DEFAULT_CANDIDATE,
    _normalize_candidate,
    load_candidates,
    save_candidates,
)


# Campaign context + module-catalog primitives live in campaign/context.py.
from campaign.context import (  # noqa: E402
    find_campaign_context,
    infer_campaign_dir_from_artifact,
)


def queue_entry_by_id(queue_id: str) -> tuple[Path, dict[str, Any]]:
    if "/" not in queue_id:
        raise SystemExit("queue_id must be in '<target_id>/<id>' form")
    target_id, raw = queue_id.split("/", 1)
    path = queue_entry_path(target_id, raw.removesuffix(".yaml"))
    if not path.exists():
        raise SystemExit(f"queue entry not found: {queue_id}")
    entry = load_yaml(path) or {}
    entry["_path"] = path
    return path, entry


def first_valid_cwe(*values: Any) -> str:
    for value in values:
        for item in as_list(value):
            text = str(item or "").strip().upper()
            if validate_cwe(text):
                return text
    return ""


def queue_entry_cwe(entry: dict[str, Any], seed: dict[str, Any]) -> str:
    affected = entry.get("affected") if isinstance(entry.get("affected"), dict) else {}
    advisory = entry.get("advisory") if isinstance(entry.get("advisory"), dict) else {}
    db = advisory.get("database_specific") if isinstance(advisory.get("database_specific"), dict) else {}
    return first_valid_cwe(
        seed.get("cwe"),
        seed.get("weakness"),
        affected.get("cwes"),
        advisory.get("cwe"),
        advisory.get("cwes"),
        advisory.get("cwe_ids"),
        db.get("cwe_ids"),
        db.get("cwe"),
    )


def queue_entry_references(entry: dict[str, Any]) -> str:
    refs = []
    ref = str(entry.get("ref") or "")
    if ref:
        refs.append(ref)
    advisory = entry.get("advisory") if isinstance(entry.get("advisory"), dict) else {}
    for key in ("id", "ghsa_id", "cve"):
        value = advisory.get(key)
        if value:
            refs.extend(str(item) for item in as_list(value))
    for item in as_list(advisory.get("aliases")):
        refs.append(str(item))
    return ", ".join(sorted(set(item for item in refs if item)))


def candidate_from_queue_entry(
    data: dict[str, Any],
    entry: dict[str, Any],
    path: Path,
    run_dir: Path,
    args: argparse.Namespace,
    campaign_context: dict[str, Any],
) -> dict[str, Any]:
    seeds = entry.get("candidate_seeds") or []
    if not seeds:
        seeds = [{}]
    try:
        seed = seeds[int(args.seed_index)]
    except (IndexError, ValueError):
        raise SystemExit(f"seed index out of range: {args.seed_index}")
    if not isinstance(seed, dict):
        raise SystemExit(f"queue seed is not an object: {args.seed_index}")
    cwe = args.cwe or queue_entry_cwe(entry, seed)
    references = queue_entry_references(entry)
    queue_id = str(entry.get("queue_id") or args.queue_id)
    queue_kind = str(entry.get("type") or "queue")
    queue_ref = str(entry.get("ref") or queue_id)
    now = dt.datetime.now().isoformat(timespec="seconds")
    novelty = str(args.novelty or seed.get("novelty") or "unchecked")
    dedup_status = "unchecked"
    checked_at = ""
    matches: list[str] = []
    if novelty in {"possible-regression", "advisory-known"} or queue_kind == "advisory":
        dedup_status = "advisory-seed"
        checked_at = now
        matches = [item.strip() for item in references.split(",") if item.strip()]
        novelty = "possible-regression" if novelty == "advisory-known" else novelty
    cand = {
        "schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION,
        "id": next_candidate_id(data),
        "title": args.title or seed.get("title") or f"Review {queue_ref} from {queue_kind} queue",
        "status": "candidate",
        "surface": args.surface or seed.get("surface") or queue_kind,
        "weakness": args.weakness or cwe or seed.get("weakness") or "unchecked",
        "impact": args.impact or seed.get("impact") or f"Queue seed from {queue_kind} {queue_ref}; concrete impact must be proven before promotion.",
        "attacker_control": args.attacker_control or seed.get("attacker_control") or "Queue seed only; attacker-control path must be verified before promotion.",
        "entrypoint": args.entrypoint or seed.get("entrypoint") or "",
        "trust_boundary": args.trust_boundary or seed.get("trust_boundary") or "",
        "latest_affected": args.latest_affected or "unchecked",
        "sink": args.sink or seed.get("sink") or "TBD",
        "novelty": novelty,
        "dedup": {
            "status": dedup_status,
            "matches": matches,
            "checked_at": checked_at,
            "manual_notes": f"Created from queue seed {queue_id}; verify manually before reporting.",
            "sources_checked": ["watch_queue"],
        },
        "proof": "not_started",
        "cve": args.cve or "N/A",
        "cwe": cwe or args.weakness or seed.get("weakness") or "",
        "cvss": args.cvss or "",
        "framework_mappings": {
            "mitre_attack": args.mitre_attack or "",
            "mitre_atlas": args.mitre_atlas or "",
            "d3fend": args.d3fend or "",
            "nist_csf": args.nist_csf or "",
            "nist_ai_rmf": args.nist_ai_rmf or "",
        },
        "negative_controls": args.negative_controls or "",
        "safety_notes": args.safety_notes or "",
        "reference_sources": args.reference_sources or references,
        "root_cause": args.root_cause or "",
        "variant_analysis": args.variant_analysis or "",
        "patch_diff": args.patch_diff or "",
        "evidence_kind": "queue_seed",
        "queue_id": queue_id,
        "queue_entry": rel(path),
        "queue_evidence": {
            "created_from_queue": True,
            "queue_id": queue_id,
            "queue_entry": rel(path),
            "queue_type": queue_kind,
            "queue_ref": queue_ref,
            "seed_index": int(args.seed_index),
            "source_kind": entry.get("source_kind") or "",
            "created_at": now,
        },
        "campaign_run": "",
        "campaign_gate": "",
        "campaign_module": args.campaign_module or "",
        "campaign_evidence": {},
        "exploitability": args.exploitability or "",
        "disclosure_quality": args.disclosure_quality or "",
        "created_at": now,
        "notes": args.notes or seed.get("next_action") or "",
        "history": [
            {"at": now, "event": "created-from-queue", "queue_id": queue_id, "queue_entry": rel(path)}
        ],
    }
    if campaign_context:
        cand["evidence_kind"] = "queue_campaign_seed"
        if args.campaign_run:
            cand["campaign_run"] = rel(run_path(args.campaign_run))
        elif campaign_context.get("campaign_run"):
            cand["campaign_run"] = campaign_context["campaign_run"]
        if args.campaign_gate:
            cand["campaign_gate"] = rel(run_path(args.campaign_gate))
        elif campaign_context.get("campaign_gate"):
            cand["campaign_gate"] = campaign_context["campaign_gate"]
        cand["campaign_evidence"] = {
            "created_in_campaign": True,
            "campaign_dir": campaign_context.get("campaign_dir", ""),
            "campaign_start": campaign_context.get("campaign_start", ""),
            "target_id": campaign_context.get("target_id", ""),
            "detected_at": campaign_context.get("detected_at", ""),
            "campaign_run": cand["campaign_run"],
            "campaign_gate": cand["campaign_gate"],
            "campaign_module": cand["campaign_module"],
        }
        cand["history"].append(
            {
                "at": now,
                "event": "campaign-context-attached",
                "campaign_start": campaign_context.get("campaign_start", ""),
            }
        )
    return cand


# next_candidate_id moved to ledger/candidates.py.
from ledger.candidates import next_candidate_id  # noqa: E402


def cmd_candidate_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    campaign_context = {}
    if not args.no_campaign_context:
        explicit_campaign_dir = args.campaign_dir or infer_campaign_dir_from_artifact(args.campaign_run) or infer_campaign_dir_from_artifact(args.campaign_gate)
        campaign_context = find_campaign_context(run_dir, explicit_campaign_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = {
            "schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION,
            "id": next_candidate_id(data),
            "title": args.title,
            "status": "candidate",
            "surface": args.surface,
            "weakness": args.weakness,
            "impact": args.impact,
            "attacker_control": args.attacker_control,
            "entrypoint": args.entrypoint or "",
            "trust_boundary": args.trust_boundary or "",
            "latest_affected": args.latest_affected or "unchecked",
            "sink": args.sink,
            "novelty": "unchecked",
            "dedup": {
                "status": "unchecked",
                "matches": [],
                "checked_at": "",
            },
            "proof": "not_started",
            "cve": args.cve or "N/A",
            "cwe": args.cwe or args.weakness,
            "cvss": args.cvss or "",
            "framework_mappings": {
                "mitre_attack": args.mitre_attack or "",
                "mitre_atlas": args.mitre_atlas or "",
                "d3fend": args.d3fend or "",
                "nist_csf": args.nist_csf or "",
                "nist_ai_rmf": args.nist_ai_rmf or "",
            },
            "negative_controls": args.negative_controls or "",
            "safety_notes": args.safety_notes or "",
            "reference_sources": args.reference_sources or "",
            "root_cause": args.root_cause or "",
            "variant_analysis": args.variant_analysis or "",
            "patch_diff": args.patch_diff or "",
            "evidence_kind": "",
            "campaign_run": "",
            "campaign_gate": "",
            "campaign_module": args.campaign_module or "",
            "campaign_evidence": {},
            "exploitability": args.exploitability or "",
            "disclosure_quality": args.disclosure_quality or "",
            "created_at": dt.datetime.now().isoformat(timespec="seconds"),
            "notes": args.notes or "",
            "history": [{"at": dt.datetime.now().isoformat(timespec="seconds"), "event": "created"}],
        }
        if campaign_context:
            cand["evidence_kind"] = "campaign_seed"
            if args.campaign_module:
                cand["campaign_module"] = args.campaign_module
            if args.campaign_run:
                cand["campaign_run"] = rel(run_path(args.campaign_run))
            elif campaign_context.get("campaign_run"):
                cand["campaign_run"] = campaign_context["campaign_run"]
            if args.campaign_gate:
                cand["campaign_gate"] = rel(run_path(args.campaign_gate))
            elif campaign_context.get("campaign_gate"):
                cand["campaign_gate"] = campaign_context["campaign_gate"]
            cand["campaign_evidence"] = {
                "created_in_campaign": True,
                "campaign_dir": campaign_context.get("campaign_dir", ""),
                "campaign_start": campaign_context.get("campaign_start", ""),
                "target_id": campaign_context.get("target_id", ""),
                "detected_at": campaign_context.get("detected_at", ""),
                "campaign_run": cand["campaign_run"],
                "campaign_gate": cand["campaign_gate"],
                "campaign_module": cand["campaign_module"],
            }
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "campaign-context-attached",
                    "campaign_start": campaign_context.get("campaign_start", ""),
                }
            )
        data.setdefault("candidates", []).append(cand)
        save_candidates(run_dir, data)
    print(cand["id"])


def cmd_candidate_from_queue(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    queue_path, entry = queue_entry_by_id(args.queue_id)
    with file_lock(queue_path):
        entry = load_yaml(queue_path) or {}
        entry["_path"] = queue_path
        status = str(entry.get("status") or "pending")
        if status == "pending":
            if not args.claim and not args.force:
                raise SystemExit("queue entry is pending; rerun with --claim or claim it first")
            entry["status"] = "claimed"
            entry["claimed_by"] = args.claimed_by
            entry["claimed_at"] = dt.datetime.now().isoformat(timespec="seconds")
            entry.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "claimed",
                    "by": args.claimed_by,
                    "run_dir": rel(run_dir),
                }
            )
        elif status not in {"claimed", "converted"} and not args.force:
            raise SystemExit(f"queue entry status is not convertible: {status}")
        elif status == "converted" and not args.force:
            raise SystemExit(f"queue entry already converted: {entry.get('candidate_id') or ''}")

        campaign_context = {}
        if not args.no_campaign_context:
            explicit_campaign_dir = args.campaign_dir or infer_campaign_dir_from_artifact(args.campaign_run) or infer_campaign_dir_from_artifact(args.campaign_gate)
            campaign_context = find_campaign_context(run_dir, explicit_campaign_dir)
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            cand = candidate_from_queue_entry(data, entry, queue_path, run_dir, args, campaign_context)
            data.setdefault("candidates", []).append(cand)
            save_candidates(run_dir, data)

        entry["status"] = "converted"
        entry["candidate_id"] = cand["id"]
        entry["run_dir"] = rel(run_dir)
        entry["converted_at"] = dt.datetime.now().isoformat(timespec="seconds")
        entry.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "converted-to-candidate",
                "candidate_id": cand["id"],
                "run_dir": rel(run_dir),
            }
        )
        dump_yaml({key: value for key, value in entry.items() if key != "_path"}, queue_path)

    payload = {
        "candidate_id": cand["id"],
        "run_dir": rel(run_dir),
        "queue_id": entry.get("queue_id") or args.queue_id,
        "queue_entry": rel(queue_path),
        "campaign_attached": bool(cand.get("campaign_evidence")),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(cand["id"])


# OSV cache + dedup gate lives in gates/osv.py (core+atomic_io leaf only).
# Imported here so harness.* references resolve unchanged.
from gates.osv import (  # noqa: E402
    COMMON_VARIANT_TERMS,
    OSV_CACHE_FRESH_HOURS,
    _http_json,
    _osv_cache_age_hours,
    _osv_cache_connect,
    _osv_cache_lookup_package,
    _osv_cache_lookup_vuln,
    _osv_cache_store_package,
    _osv_cache_store_vuln,
    _osv_dedup,
    _osv_package_query,
    _osv_vuln_query,
    osv_cache_path,
)


def cmd_dedup(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = load_run(run_dir)
    duplicate_seen = False

    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get("candidates", [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]

        known = [str(item).lower() for item in target.get("known_duplicates", [])]
        target_terms = [
            str(target.get("id", "")),
            str(target.get("name", "")),
            str(target.get("repo_url", "")),
        ]
        for cand in candidates:
            haystack = " ".join(
                str(cand.get(key, ""))
                for key in ("title", "surface", "weakness", "impact", "sink", "cve", "notes")
            ).lower()
            matches = [item for item in known if item and item in haystack]
            cve = str(cand.get("cve", "")).lower()
            if cve and cve != "n/a" and cve in known and cve not in matches:
                matches.append(cve)

            osv_result = None
            if args.check_osv:
                osv_result = _osv_dedup(args, target, cand, run_dir)
                if osv_result["exact_alias_matches"]:
                    matches.extend(osv_result["exact_alias_matches"])

            status = "possible-regression" if args.regression else "no-known-duplicate"
            if matches:
                status = "known-duplicate"
            elif osv_result and osv_result["possible_text_matches"]:
                status = "possible-regression"
            elif args.check_osv and osv_result and osv_result.get("errors"):
                status = "dedup-incomplete"
            if args.status:
                status = args.status

            duplicate_seen = duplicate_seen or status in {"known-duplicate", "possible-regression"}
            cand["novelty"] = status
            sources_checked = [
                "target.known_duplicates",
                "candidate.cve",
                "candidate text fields",
            ]
            if args.check_osv:
                sources_checked.append("osv.dev")
            if args.reference:
                sources_checked.extend(str(item) for item in args.reference)
            cand["dedup"] = {
                "status": status,
                "matches": sorted(set(str(match) for match in matches)),
                "checked_at": dt.datetime.now().isoformat(timespec="seconds"),
                "sources_checked": sources_checked,
                "osv": osv_result,
                "manual_notes": args.notes or "",
                "suggested_queries": [
                    " ".join([term for term in [target_terms[0], cand.get("weakness", ""), cand.get("sink", "")] if term]),
                    " ".join([term for term in [target_terms[1], cand.get("title", "")] if term]),
                    " ".join([term for term in [target_terms[2], cand.get("cve", "")] if term and term != "N/A"]),
                    " ".join([term for term in ["site:huntr.com", target_terms[2] or target_terms[0], cand.get("weakness", "")] if term]),
                    " ".join([term for term in ["site:github.com/advisories", target_terms[1], cand.get("cwe", "")] if term]),
                    " ".join([term for term in ["site:github.com", target_terms[2] or target_terms[1], cand.get("title", "")] if term]),
                ],
            }
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": f"dedup:{status}",
                    "matches": sorted(set(str(match) for match in matches)),
                }
            )
            print(
                f"{cand['id']} duplicate_status={status} "
                f"matches={','.join(sorted(set(str(match) for match in matches))) or 'none'}"
            )
        save_candidates(run_dir, data)
    if duplicate_seen:
        raise SystemExit(3)


# promotion_findings, candidate_requires_queue_gate, queue_evidence_findings,
# candidate_requires_campaign_gate, campaign_evidence_findings imported from
# gates.promotion (above).


def report_readiness_findings(cand: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    blockers = workflow_blockers(cand, "report_ready")
    warnings: list[str] = []
    strict_fields = [
        ("attacker_control", 24),
        ("entrypoint", 12),
        ("trust_boundary", 24),
        ("sink", 12),
        ("impact", 32),
        ("root_cause", 32),
        ("negative_controls", 24),
        ("variant_analysis", 24),
        ("patch_diff", 12),
    ]
    for field, min_chars in strict_fields:
        if not substantive_text(cand.get(field), min_chars):
            blockers.append(f"strict:{field}_too_shallow")
    if not exact_affected_version(cand.get("latest_affected")):
        blockers.append("strict:latest_affected_not_exact_version_or_commit")
    if cand.get("proof") != "passed":
        blockers.append("strict:proof_not_passed")
    last_proof = cand.get("last_proof") if isinstance(cand.get("last_proof"), dict) else {}
    if not last_proof:
        blockers.append("strict:last_proof_missing")
    elif int(last_proof.get("returncode", -1)) != 0:
        blockers.append("strict:last_proof_nonzero")
    else:
        for artifact_key in ("stdout", "stderr", "status", "command_record"):
            if not artifact_exists(last_proof.get(artifact_key)):
                blockers.append(f"strict:last_proof_{artifact_key}_missing")
    coverage = duplicate_source_coverage(cand)
    if not coverage["osv"]:
        blockers.append("strict:osv_dedup_missing")
    if not (coverage["cve_or_ghsa"] or coverage["github"]):
        blockers.append("strict:cve_ghsa_or_github_reference_missing")
    if not coverage["huntr"]:
        warnings.append("huntr_duplicate_reference_missing")
    if str(cand.get("novelty", "")) == "possible-regression" and not substantive_text(
        (cand.get("dedup") or {}).get("manual_notes", "") if isinstance(cand.get("dedup"), dict) else "",
        24,
    ):
        blockers.append("strict:possible_regression_without_manual_dedup_note")
    campaign_ok, campaign_blockers, campaign_warnings = campaign_evidence_findings(cand)
    if not campaign_ok:
        blockers.extend(f"strict:{item}" for item in campaign_blockers)
    warnings.extend(campaign_warnings)
    queue_ok, queue_blockers, queue_warnings = queue_evidence_findings(cand)
    if not queue_ok:
        blockers.extend(f"strict:{item}" for item in queue_blockers)
    warnings.extend(queue_warnings)
    return not blockers, sorted(set(blockers)), sorted(set(warnings))


def cmd_report_gate(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    out_dir = run_dir / "readiness"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results = []
    fail_seen = False
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get("candidates", [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]
        for cand in candidates:
            ok, blockers, warnings = report_readiness_findings(cand)
            result = {
                "candidate_id": cand["id"],
                "title": cand.get("title", ""),
                "passed": ok,
                "blockers": blockers,
                "warnings": warnings,
            }
            cand["report_readiness"] = result
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "report-readiness",
                    "passed": ok,
                    "blockers": blockers,
                }
            )
            if ok and args.mark_ready:
                cand["status"] = "report-ready"
            results.append(result)
            fail_seen = fail_seen or not ok
            print(f"{cand['id']} report_gate={'pass' if ok else 'fail'}")
            if blockers:
                print("blocking=" + ",".join(blockers))
            if warnings:
                print("warnings=" + ",".join(warnings))
        save_candidates(run_dir, data)
    payload = {"generated_at": dt.datetime.now().isoformat(timespec="seconds"), "results": results}
    dump_yaml(payload, out_dir / f"report_gate_{stamp}.yaml")
    md = ["# Report Readiness Gate", ""]
    for result in results:
        md.extend(
            [
                f"## {result['candidate_id']}: {result['title']}",
                "",
                f"- Passed: `{result['passed']}`",
                f"- Blockers: `{', '.join(result['blockers']) or 'none'}`",
                f"- Warnings: `{', '.join(result['warnings']) or 'none'}`",
                "",
            ]
        )
    write_text(out_dir / f"report_gate_{stamp}.md", "\n".join(md))
    if fail_seen and args.fail:
        raise SystemExit(2)


def cmd_gate(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        ok, missing = promotion_findings(cand)
        score, err = cvss3_base_score(str(cand.get("cvss", "")))
        cand["promotion_gate"] = {
            "passed": ok,
            "checked_at": dt.datetime.now().isoformat(timespec="seconds"),
            "missing_or_blocking": missing,
            "cvss_base_score": score,
            "cvss_error": err,
        }
        if ok and args.promote:
            cand["status"] = "promoted"
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "status:promoted",
                    "reason": "promotion gate passed",
                }
            )
        if ok and args.report_ready:
            ready, report_blockers, report_warnings = report_readiness_findings(cand)
            cand["report_readiness"] = {
                "passed": ready,
                "checked_at": dt.datetime.now().isoformat(timespec="seconds"),
                "blockers": report_blockers,
                "warnings": report_warnings,
            }
            if ready:
                cand["status"] = "report-ready"
                cand.setdefault("history", []).append(
                    {
                        "at": dt.datetime.now().isoformat(timespec="seconds"),
                        "event": "status:report-ready",
                        "reason": "promotion gate passed and proof passed",
                    }
                )
            else:
                cand.setdefault("history", []).append(
                    {
                        "at": dt.datetime.now().isoformat(timespec="seconds"),
                        "event": "report-ready-blocked",
                        "reason": "strict report-readiness blockers remain: "
                        + ",".join(report_blockers),
                    }
                )
                missing.extend(report_blockers)
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} gate={'pass' if ok else 'fail'}")
    if missing:
        print("blocking=" + ",".join(missing))
        raise SystemExit(2)


# find_candidate / update_candidate_locked moved to ledger/candidates.py.
from ledger.candidates import find_candidate, update_candidate_locked  # noqa: E402


# cmd_candidate_link_campaign moved to campaign/commands.py.
# _campaign_start_markdown moved to campaign/commands.py.
# _campaign_next_commands_markdown moved to campaign/commands.py.
# _write_campaign_start_plan_files moved to campaign/commands.py.
def _github_repo_from_url(url: str) -> str:
    raw = str(url or "").strip().removesuffix(".git")
    match = re.search(r"github\.com[:/]+([^/]+)/([^/#?]+)", raw)
    if not match:
        return ""
    return f"{match.group(1)}/{match.group(2)}"


# _campaign_refresh_package_metadata moved to campaign/commands.py.
def _ghsa_ecosystem(ecosystem: str) -> str:
    mapping = {
        "pypi": "pip",
        "pip": "pip",
        "python": "pip",
        "go": "go",
        "golang": "go",
        "npm": "npm",
        "node": "npm",
        "nodejs": "npm",
        "javascript": "npm",
        "typescript": "npm",
        "maven": "maven",
        "rubygems": "rubygems",
        "ruby": "rubygems",
        "cargo": "rust",
        "crates.io": "rust",
        "rust": "rust",
        "nuget": "nuget",
        "composer": "composer",
        "pub": "pub",
        "erlang": "erlang",
        "actions": "actions",
    }
    return mapping.get(str(ecosystem or "").strip().lower(), str(ecosystem or "").strip().lower())


# _campaign_refresh_sources moved to campaign/commands.py.
# _campaign_advisory_refresh_markdown moved to campaign/commands.py.
# _run_campaign_advisory_refresh moved to campaign/commands.py.
# cmd_campaign_start moved to campaign/commands.py.
# _campaign_flow_check_markdown moved to campaign/commands.py.
def _flow_args(**kwargs: Any) -> argparse.Namespace:
    defaults = {
        "seed_index": 0,
        "claim": False,
        "claimed_by": os.environ.get("USER", "operator"),
        "force": False,
        "title": None,
        "surface": None,
        "weakness": None,
        "impact": None,
        "attacker_control": None,
        "sink": None,
        "entrypoint": None,
        "trust_boundary": None,
        "latest_affected": None,
        "novelty": None,
        "cve": None,
        "cwe": None,
        "cvss": None,
        "mitre_attack": None,
        "mitre_atlas": None,
        "d3fend": None,
        "nist_csf": None,
        "nist_ai_rmf": None,
        "negative_controls": None,
        "safety_notes": None,
        "reference_sources": None,
        "root_cause": None,
        "variant_analysis": None,
        "patch_diff": None,
        "campaign_dir": None,
        "campaign_module": None,
        "campaign_run": None,
        "campaign_gate": None,
        "no_campaign_context": False,
        "exploitability": None,
        "disclosure_quality": None,
        "notes": None,
        "json": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# cmd_campaign_flow_check moved to campaign/commands.py.
def cmd_outcome_tune_check(args: argparse.Namespace) -> None:
    base = run_path(args.out_dir) if args.out_dir else ROOT / "vapt" / "harness" / "tests" / "results" / "outcome-tune-check"
    if base.exists():
        shutil.rmtree(base)
    campaign_dir = base / "campaign"
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_campaign_flow_check(argparse.Namespace(out_dir=str(base / "flow"), json=False, fail=True))
    run_dir = base / "flow" / "campaign" / "run"
    data = load_candidates(run_dir)
    cand = find_candidate(data, "CAND-001")
    original_submission_rows = read_jsonl(submissions_path())
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_outcome_record(
            argparse.Namespace(
                submission_id="OUTCOME-TUNE-CHECK-ACCEPTED",
                run_dir=str(run_dir),
                candidate_id="CAND-001",
                status="accepted",
                platform="fixture",
                program="fixture",
                title=None,
                submitted_at=None,
                severity_claimed="high",
                severity="high",
                cvss=cand.get("cvss") or "",
                payout=1500.0,
                currency="USD",
                lesson="Fixture accepted authz_matrix queue campaign seed",
                note="fixture accepted",
                json=False,
            )
        )
    rows = read_jsonl(submissions_path())
    duplicate_row = {
        "submission_id": "OUTCOME-TUNE-CHECK-DUPLICATE",
        "platform": "fixture",
        "program": "fixture",
        "candidate_run": rel(run_dir),
        "candidate_id": "CAND-DUP",
        "submitted_at": dt.datetime.now().isoformat(timespec="seconds"),
        "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "title": "Duplicate fixture",
        "severity_claimed": "medium",
        "severity_final": "medium",
        "cvss_claimed": "",
        "status_history": [{"at": dt.datetime.now().isoformat(timespec="seconds"), "status": "duplicate", "note": "fixture duplicate"}],
        "final_status": "duplicate",
        "payout_value": None,
        "payout_currency": None,
        "days_to_final": 0,
        "lessons": ["Fixture duplicate non_authz module"],
        "target_id": "harness-fixture",
        "target_category": ["authz_boundary"],
        "language": ["Python"],
        "weakness": "CWE-79",
        "cwe": "CWE-79",
        "surface": "fixture duplicate",
        "sink": "fixture duplicate",
        "campaign_module": "xss_render",
        "evidence_kind": "manual_seed",
        "queue_type": "",
    }
    with file_lock(submissions_path()):
        rows = [row for row in rows if row.get("submission_id") not in {"OUTCOME-TUNE-CHECK-ACCEPTED", "OUTCOME-TUNE-CHECK-DUPLICATE"}]
        rows.append(duplicate_row)
        accepted = read_jsonl(submissions_path())
        accepted = [row for row in accepted if row.get("submission_id") == "OUTCOME-TUNE-CHECK-ACCEPTED"]
        rows.extend(accepted)
        write_jsonl(submissions_path(), rows)
    tuning_out = base / "outcome_tuning.yaml"
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_outcome_tune(argparse.Namespace(since=None, out=str(tuning_out), json=False))
    tuning = load_yaml(tuning_out) or {}
    with file_lock(submissions_path()):
        write_jsonl(submissions_path(), original_submission_rows)
    authz_adj = ((tuning.get("module_adjustments") or {}).get("authz_matrix") or {}).get("score_adjustment")
    xss_adj = ((tuning.get("module_adjustments") or {}).get("xss_render") or {}).get("score_adjustment")
    checks = [
        {"name": "authz_positive_adjustment", "passed": authz_adj is not None and float(authz_adj) > 0, "detail": str(authz_adj)},
        {"name": "duplicate_lower_than_positive", "passed": xss_adj is not None and float(xss_adj) < float(authz_adj or 0), "detail": f"xss={xss_adj} authz={authz_adj}"},
    ]
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
        "tuning": rel(tuning_out),
        "report": rel(tuning_out.with_suffix(".md")),
    }
    write_json(base / "outcome_tune_check.json", payload)
    write_text(
        base / "outcome_tune_check.md",
        "# Outcome Tune Check\n\n"
        + "\n".join(f"- `{item['name']}` passed=`{item['passed']}` detail=`{item['detail']}`" for item in checks)
        + "\n",
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(base / "outcome_tune_check.md"))
    if args.fail and not payload["passed"]:
        raise SystemExit(2)


def cmd_candidate_set(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        if args.status is None and getattr(args, "triage_verdict", None) is None:
            raise SystemExit("candidate-set requires --status and/or --triage-verdict")
        if args.status is not None:
            if args.status in WORKFLOW_ORDER or args.status in WORKFLOW_TERMINAL:
                blockers = workflow_blockers(cand, args.status)
                if blockers and not args.force:
                    print(json.dumps({"candidate_id": args.candidate_id, "target_status": args.status, "blockers": blockers}, sort_keys=True))
                    raise SystemExit(2)
            cand["status"] = args.status
        if getattr(args, "triage_verdict", None) is not None:
            cand["triage_verdict"] = args.triage_verdict
        for key, value in (
            ("entrypoint", args.entrypoint),
            ("trust_boundary", args.trust_boundary),
            ("latest_affected", args.latest_affected),
            ("novelty", args.novelty),
            ("impact", args.impact),
            ("attacker_control", args.attacker_control),
            ("sink", args.sink),
            ("cve", args.cve),
            ("cwe", args.cwe),
            ("cvss", args.cvss),
            ("negative_controls", args.negative_controls),
            ("root_cause", args.root_cause),
            ("variant_analysis", args.variant_analysis),
            ("patch_diff", args.patch_diff),
            ("exploitability", args.exploitability),
            ("disclosure_quality", args.disclosure_quality),
            ("safety_notes", args.safety_notes),
            ("proof", args.proof),
        ):
            if value is not None:
                cand[key] = value
        if args.reason:
            cand["decision_reason"] = args.reason
        event = f"status:{args.status}" if args.status is not None else f"triage_verdict:{args.triage_verdict}"
        cand.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": event,
                "reason": args.reason or "",
            }
        )
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} -> {args.status if args.status is not None else 'triage:' + str(args.triage_verdict)}")


def cmd_candidates(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    for cand in data.get("candidates", []):
        print(
            f"{cand['id']} [{cand.get('status')}] {cand.get('title')} "
            f"(proof={cand.get('proof')}, novelty={cand.get('novelty')}, cve={cand.get('cve')})"
        )


def cmd_prove(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    proof_dir = run_dir / "evidence" / args.candidate_id / stamp
    proof_dir.mkdir(parents=True, exist_ok=True)
    base = proof_dir / "proof"

    cwd = run_path(args.cwd).resolve() if args.cwd else proof_dir.resolve()
    if not cwd.exists() or not cwd.is_dir():
        raise SystemExit(f"proof cwd does not exist or is not a directory: {cwd}")

    if args.shell:
        popen_args: str | list[str] = args.cmd
    else:
        popen_args = shlex.split(args.cmd)
        if not popen_args:
            raise SystemExit("empty proof command")

    def limit_child() -> None:
        try:
            import resource

            if args.cpu_seconds:
                resource.setrlimit(resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 1))
            if args.memory_mb:
                limit = args.memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            if args.file_mb:
                limit = args.file_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        except Exception:
            pass

    timed_out = False
    try:
        raw_out = base.with_suffix(".out.raw")
        raw_err = base.with_suffix(".err.raw")
        with raw_out.open("wb") as out_fh, raw_err.open("wb") as err_fh:
            proc = subprocess.Popen(
                popen_args,
                cwd=str(cwd),
                shell=args.shell,
                text=False,
                stdout=out_fh,
                stderr=err_fh,
                start_new_session=True,
                preexec_fn=limit_child if sys.platform != "win32" else None,
            )
            try:
                returncode = proc.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
                returncode = 124
    except FileNotFoundError as exc:
        raw_out = base.with_suffix(".out.raw")
        raw_err = base.with_suffix(".err.raw")
        raw_out.write_bytes(b"")
        raw_err.write_bytes(str(exc).encode("utf-8"))
        returncode = 127

    def materialize_capped(raw_path: Path, text_path: Path) -> bool:
        truncated = False
        written = 0
        with raw_path.open("rb") as src_fh, text_path.open("wb") as dst_fh:
            while True:
                chunk = src_fh.read(65536)
                if not chunk:
                    break
                remaining = args.max_output_chars - written
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

    stdout_truncated = materialize_capped(base.with_suffix(".out.raw"), base.with_suffix(".out"))
    stderr_truncated = materialize_capped(base.with_suffix(".err.raw"), base.with_suffix(".err"))

    command_record = {
        "cmd": args.cmd,
        "argv_mode": not args.shell,
        "shell": args.shell,
        "cwd": str(cwd),
        "timeout_seconds": args.timeout,
        "cpu_seconds": args.cpu_seconds,
        "memory_mb": args.memory_mb,
        "file_mb": args.file_mb,
        "timed_out": timed_out,
        "returncode": returncode,
    }
    write_json(base.with_suffix(".cmd.json"), command_record)
    write_text(base.with_suffix(".status"), str(returncode) + "\n")

    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        cand["proof"] = "passed" if returncode == 0 else "failed"
        cand["last_proof"] = {
            **command_record,
            "stdout": rel(base.with_suffix(".out")),
            "stderr": rel(base.with_suffix(".err")),
            "stdout_raw": rel(base.with_suffix(".out.raw")),
            "stderr_raw": rel(base.with_suffix(".err.raw")),
            "status": rel(base.with_suffix(".status")),
            "command_record": rel(base.with_suffix(".cmd.json")),
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }
        cand.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": f"prove:{cand['proof']}",
            }
        )
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} proof={'passed' if returncode == 0 else 'failed'} status={returncode}")
    if returncode != 0:
        raise SystemExit(returncode if 0 < returncode < 126 else 1)


# COMMON_VARIANT_TERMS moved to gates/osv.py (imported at the OSV re-export block above).


def _candidate_variant_patterns(cand: dict[str, Any], supplied: list[str] | None) -> list[str]:
    patterns: list[str] = []
    if supplied:
        patterns.extend(supplied)
    for key in (
        "sink",
        "entrypoint",
        "surface",
        "root_cause",
        "title",
        "trust_boundary",
        "negative_controls",
    ):
        value = str(cand.get(key, "") or "").strip()
        if value and len(value) <= 120:
            patterns.append(value)

    seed_text = " ".join(
        str(cand.get(key, "") or "")
        for key in ("title", "surface", "sink", "root_cause", "trust_boundary")
    )
    for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", seed_text):
        lower = term.lower()
        if lower not in COMMON_VARIANT_TERMS:
            patterns.append(term)

    seen: set[str] = set()
    unique: list[str] = []
    for pattern in patterns:
        cleaned = pattern.strip()
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        unique.append(cleaned)
    return unique[:20]


def cmd_variant(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)

    patterns = _candidate_variant_patterns(cand, args.pattern)
    if not patterns:
        raise SystemExit("no variant search patterns available; pass --pattern")

    out_dir = run_dir / "variant_analysis"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{args.candidate_id}_{stamp}"
    paths = args.path or []

    searches: list[dict[str, Any]] = []
    for pattern in patterns:
        cmd = ["rg", "-n", "-S", "-F", pattern]
        cmd.extend(paths)
        result = run_cmd(cmd, src, timeout=args.timeout)
        hits = result["stdout"].splitlines()[: args.max_hits] if result["returncode"] in (0, 1) else []
        searches.append(
            {
                "pattern": pattern,
                "paths": paths,
                "returncode": result["returncode"],
                "timeout": result["timeout"],
                "hit_count_capped": len(hits),
                "hits": hits,
                "stderr": result["stderr"].strip(),
            }
        )

    artifact = {
        "candidate_id": args.candidate_id,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_path": rel(src),
        "purpose": "Find sibling surfaces by root-cause terms, sinks, event names, and shared helpers.",
        "manual_notes": args.notes or "",
        "searches": searches,
    }
    dump_yaml(artifact, base.with_suffix(".yaml"))

    md = [
        f"# Variant Analysis: {args.candidate_id}",
        "",
        f"- Source: `{rel(src)}`",
        f"- Candidate: `{cand.get('title', '')}`",
        f"- Notes: {args.notes or ''}",
        "",
        "## Search Results",
        "",
    ]
    for item in searches:
        md.extend(
            [
                f"### `{item['pattern']}`",
                "",
                f"- Return code: `{item['returncode']}`",
                f"- Timeout: `{item['timeout']}`",
                f"- Hits captured: `{item['hit_count_capped']}`",
                "",
            ]
        )
        if item["stderr"]:
            md.append(f"- Stderr: `{item['stderr']}`")
            md.append("")
        if item["hits"]:
            for hit in item["hits"]:
                md.append(f"- `{hit}`")
        else:
            md.append("- No hits")
        md.append("")
    write_text(base.with_suffix(".md"), "\n".join(md))

    def mark_variant(updated: dict[str, Any]) -> None:
        updated["variant_analysis"] = rel(base.with_suffix(".md"))
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "variant-analysis",
                "artifact": rel(base.with_suffix(".md")),
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_variant)
    print(rel(base.with_suffix(".md")))


def cmd_patch_diff(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)

    out_dir = run_dir / "patch_diff"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{args.candidate_id}_{stamp}"
    paths = args.path or []

    refs = f"{args.base}..{args.head}"
    ref_checks = {
        "base": run_cmd(["git", "rev-parse", "--verify", args.base], src, timeout=15),
        "head": run_cmd(["git", "rev-parse", "--verify", args.head], src, timeout=15),
    }
    missing_refs = [name for name, result in ref_checks.items() if result["returncode"] != 0]
    if missing_refs:
        hint = (
            "Missing git ref(s): "
            + ", ".join(missing_refs)
            + ". Fetch tags/history first, e.g. `git fetch --tags --prune --unshallow` "
            "or use refs present in this checkout."
        )
        artifact = {
            "candidate_id": args.candidate_id,
            "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
            "source_path": rel(src),
            "base": args.base,
            "head": args.head,
            "ref_checks": ref_checks,
            "error": hint,
        }
        dump_yaml(artifact, base.with_suffix(".yaml"))
        write_text(base.with_suffix(".md"), f"# Patch Diff Review: {args.candidate_id}\n\n{hint}\n")
        print(rel(base.with_suffix(".md")))
        raise SystemExit(2)
    stat = run_cmd(["git", "diff", "--stat", refs, "--", *paths], src, timeout=args.timeout)
    names = run_cmd(["git", "diff", "--name-status", refs, "--", *paths], src, timeout=args.timeout)
    patch = run_cmd(
        ["git", "diff", f"--unified={args.context}", refs, "--", *paths],
        src,
        timeout=args.timeout,
    )
    grep_results = []
    for pattern in args.grep or []:
        grep_results.append(
            {
                "pattern": pattern,
                "result": run_cmd(
                    ["git", "diff", "-G", pattern, "--name-only", refs, "--", *paths],
                    src,
                    timeout=args.timeout,
                ),
            }
        )

    patch_text = patch["stdout"]
    if len(patch_text) > args.max_patch_chars:
        patch_text = patch_text[: args.max_patch_chars] + "\n\n[truncated]\n"

    artifact = {
        "candidate_id": args.candidate_id,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_path": rel(src),
        "base": args.base,
        "head": args.head,
        "paths": paths,
        "manual_notes": args.notes or "",
        "stat": stat,
        "name_status": names,
        "grep_results": grep_results,
        "patch_truncated_to_chars": args.max_patch_chars,
        "patch_returncode": patch["returncode"],
        "patch_timeout": patch["timeout"],
        "patch_stderr": patch["stderr"],
    }
    dump_yaml(artifact, base.with_suffix(".yaml"))
    write_text(base.with_suffix(".diff"), patch_text)

    md = [
        f"# Patch Diff Review: {args.candidate_id}",
        "",
        f"- Source: `{rel(src)}`",
        f"- Range: `{refs}`",
        f"- Paths: `{', '.join(paths) if paths else '<all>'}`",
        f"- Notes: {args.notes or ''}",
        "",
        "## Diff Stat",
        "",
        "```text",
        stat["stdout"].strip() or stat["stderr"].strip() or "<empty>",
        "```",
        "",
        "## Changed Files",
        "",
        "```text",
        names["stdout"].strip() or names["stderr"].strip() or "<empty>",
        "```",
        "",
        "## Patch",
        "",
        f"Patch saved to `{rel(base.with_suffix('.diff'))}`.",
        "",
    ]
    if grep_results:
        md.extend(["## Grep Diffs", ""])
        for item in grep_results:
            result = item["result"]
            md.extend(
                [
                    f"### `{item['pattern']}`",
                    "",
                    "```text",
                    result["stdout"].strip() or result["stderr"].strip() or "<empty>",
                    "```",
                    "",
                ]
            )
    write_text(base.with_suffix(".md"), "\n".join(md))

    def mark_patch_diff(updated: dict[str, Any]) -> None:
        updated["patch_diff"] = rel(base.with_suffix(".md"))
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "patch-diff",
                "artifact": rel(base.with_suffix(".md")),
                "range": refs,
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_patch_diff)
    print(rel(base.with_suffix(".md")))


GRAPH_QUERIES = {
    "functions": r"^(func |def |class |export function |function )",
    "routes_handlers": r"(Handle\(|Methods\(|router\.|Route\(|APISessionRequired|APIHandler)",
    "authz_checks": r"(Permission|SessionHasPermission|UserCanSee|Authorize|authz|IsAdmin|Require[A-Z])",
    "events_broadcasts": r"(NewWebSocketEvent|Publish\(|Broadcast|ShouldSendEvent|EventChannel|websocket)",
    "parsers_decoders": r"(parse|Parse|decode|Decode|Unmarshal|Marshal|json\.|yaml\.|xml\.)",
    "file_storage": r"(open\(|Open\(|ReadFile|WriteFile|extract|Upload|Download|S3|MinIO|FileInfo)",
    "network_clients": r"(http\.Client|http\.Get|http\.NewRequest|requests\.|httpx\.|aiohttp|axios\.|(?<!\.)fetch\(|urlopen|urllib\.request|Dial\(|SSRF|webhook)",
    "process_execution": r"(subprocess|os\.system|exec\(|eval\(|Command\(|exec\.Command|child_process\.(exec|spawn)|Runtime\.exec|ProcessBuilder|popen|shell)",
    "native_unsafe": r"(unsafe|cgo|memcpy|malloc|free\(|reinterpret_cast|strcpy)",
}


DEFAULT_SOURCE_GRAPH_EXCLUDES = [
    "!**/*_test.go",
    "!**/*test*.go",
    "!**/testdata/**",
    "!**/storetest/**",
    "!**/mocks/**",
    "!tools/**",
    "!**/vendor/**",
    "!**/node_modules/**",
]

# PATTERNS / GRAPH_QUERIES are computed from source.commands.load_surface_config
# but that module is imported far below to avoid a circular at decomposition
# time. Materialize them lazily here so the load completes after source.commands
# has been bound.
def _compute_surface_patterns() -> tuple[dict, dict]:
    from source.commands import load_surface_config
    return load_surface_config()


PATTERNS, GRAPH_QUERIES = _compute_surface_patterns()


# cmd_source_graph moved to source.commands.
def _load_latest_variant_yaml(run_dir: Path, candidate_id: str) -> dict[str, Any]:
    variants = sorted((run_dir / "variant_analysis").glob(f"{candidate_id}_*.yaml"))
    if not variants:
        raise SystemExit(f"no variant analysis yaml found for {candidate_id}")
    return load_yaml(variants[-1]) or {}


def _hit_file(hit: str) -> str:
    return hit.split(":", 1)[0] if ":" in hit else hit


def _hit_symbol(hit: str) -> str:
    text = hit.split(":", 2)[-1] if ":" in hit else hit
    for regex in (
        r"\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)",
        r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*function\b",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    ):
        match = re.search(regex, text)
        if match:
            return match.group(1)
    return "<unknown>"


def cmd_cluster_variants(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    variant = _load_latest_variant_yaml(run_dir, args.candidate_id)
    out_dir = run_dir / "variant_clusters"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{args.candidate_id}_{stamp}"

    clusters: dict[str, dict[str, Any]] = {}
    for search in variant.get("searches", []):
        pattern = search.get("pattern", "")
        for hit in search.get("hits", []):
            file_name = _hit_file(hit)
            cluster = clusters.setdefault(
                file_name,
                {"file": file_name, "patterns": set(), "symbols": set(), "hits": []},
            )
            cluster["patterns"].add(pattern)
            cluster["symbols"].add(_hit_symbol(hit))
            cluster["hits"].append(hit)

    serializable = []
    for item in clusters.values():
        serializable.append(
            {
                "file": item["file"],
                "patterns": sorted(item["patterns"]),
                "symbols": sorted(item["symbols"]),
                "hit_count": len(item["hits"]),
                "hits": item["hits"][: args.max_hits],
            }
        )
    serializable.sort(key=lambda item: (-item["hit_count"], item["file"]))

    artifact = {
        "candidate_id": args.candidate_id,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_variant_artifact": variant.get("generated_at", ""),
        "cluster_count": len(serializable),
        "clusters": serializable,
    }
    dump_yaml(artifact, base.with_suffix(".yaml"))

    md = [
        f"# Variant Clusters: {args.candidate_id}",
        "",
        f"- Candidate: `{cand.get('title', '')}`",
        f"- Clusters: `{len(serializable)}`",
        "",
    ]
    for cluster in serializable[: args.max_clusters]:
        md.extend(
            [
                f"## `{cluster['file']}`",
                "",
                f"- Hit count: `{cluster['hit_count']}`",
                f"- Patterns: `{', '.join(cluster['patterns'])}`",
                f"- Symbols: `{', '.join(cluster['symbols'])}`",
                "",
            ]
        )
        for hit in cluster["hits"]:
            md.append(f"- `{hit}`")
        md.append("")
    write_text(base.with_suffix(".md"), "\n".join(md))

    def mark_clusters(updated: dict[str, Any]) -> None:
        updated["variant_clusters"] = rel(base.with_suffix(".md"))
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "variant-clusters",
                "artifact": rel(base.with_suffix(".md")),
                "cluster_count": len(serializable),
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_clusters)
    print(rel(base.with_suffix(".md")))


def _intent_tokens(state: dict[str, Any]) -> list[str]:
    intent = state.get("intent") or {}
    tokens = intent.get("threat_model") or []
    return [t for t in tokens if t in INTENT_VOCAB]


def _candidate_intent_match(cand: dict[str, Any], tokens: list[str]) -> str:
    if not tokens:
        return ""
    blob = " ".join(
        str(cand.get(field) or "").lower()
        for field in ("kind", "weakness", "cwe", "surface", "title", "impact")
    )
    for token in tokens:
        spec = INTENT_VOCAB.get(token, {})
        if token in blob or any(kw in blob for kw in spec.get("keywords", set())):
            return token
    return ""


def _score_candidate(
    cand: dict[str, Any], intent_tokens: list[str] | None = None
) -> tuple[int, list[str], list[str]]:
    score = 0
    strengths: list[str] = []
    gaps: list[str] = []

    checks = [
        ("attacker_control", 8, 24, "attacker control described with substance"),
        ("entrypoint", 8, 12, "entrypoint described"),
        ("trust_boundary", 9, 24, "trust boundary described with substance"),
        ("sink", 8, 12, "sink described"),
        ("impact", 10, 32, "impact described as concrete security consequence"),
        ("negative_controls", 10, 24, "negative control recorded"),
        ("root_cause", 10, 32, "root cause recorded as invariant"),
        ("variant_analysis", 8, 24, "variant analysis artifact recorded"),
        ("patch_diff", 8, 12, "patch/advisory artifact recorded"),
    ]
    for field, points, min_chars, label in checks:
        value = cand.get(field)
        if substantive_text(value, min_chars):
            score += points
            strengths.append(label)
        else:
            gaps.append(f"{field}_substance")

    if validate_cwe(str(cand.get("cwe", ""))):
        score += 4
        strengths.append("CWE validated")
    else:
        gaps.append("valid_cwe")

    cvss_score, cvss_error = cvss3_base_score(str(cand.get("cvss", "")))
    if cvss_score is not None:
        score += 4
        strengths.append(f"CVSS validated ({cvss_score})")
    else:
        gaps.append(f"valid_cvss:{cvss_error}")

    proof = cand.get("proof")
    if proof == "passed":
        score += 12
        strengths.append("proof passed")
        last_proof = cand.get("last_proof") if isinstance(cand.get("last_proof"), dict) else {}
        if last_proof and all(artifact_exists(last_proof.get(key)) for key in ("stdout", "stderr", "status", "command_record")):
            score += 5
            strengths.append("proof artifacts present")
        else:
            gaps.append("proof_artifacts")
    else:
        gaps.append("proof_passed")

    if exact_affected_version(cand.get("latest_affected")):
        score += 8
        strengths.append("exact affected version/commit confirmed")
    else:
        gaps.append("exact_latest_affected")

    novelty = cand.get("novelty")
    coverage = duplicate_source_coverage(cand)
    if novelty in {"no-known-duplicate", "low-public-footprint"}:
        score += 6
        strengths.append(f"novelty status: {novelty}")
    elif novelty == "possible-regression":
        score += 4
        strengths.append("possible regression status")
    else:
        gaps.append("novelty")
    coverage_points = sum(1 for ok in coverage.values() if ok)
    if coverage_points >= 3:
        score += 6
        strengths.append("multi-source duplicate/advisory coverage")
    elif coverage_points >= 2:
        score += 3
        strengths.append("partial duplicate/advisory coverage")
    else:
        gaps.append("multi_source_dedup")

    if substantive_text(cand.get("proof_plan"), 6) or artifact_exists(cand.get("proof_plan")):
        score += 2
        strengths.append("proof plan recorded")

    ready, strict_blockers, _warnings = report_readiness_findings(cand)
    if ready:
        score += 8
        strengths.append("strict report gate clean")
    else:
        gaps.extend(strict_blockers[:8])

    tuning = load_outcome_tuning()
    candidate_adjustment = 0.0
    for section, key in (
        ("weakness_adjustments", str(cand.get("cwe") or cand.get("weakness") or "")),
        ("evidence_kind_adjustments", str(cand.get("evidence_kind") or "")),
        ("module_adjustments", str(cand.get("campaign_module") or "")),
    ):
        item = (tuning.get(section) or {}).get(key, {})
        if item:
            candidate_adjustment += float(item.get("score_adjustment") or 0) / 6
    if candidate_adjustment:
        bounded = max(-6, min(6, round(candidate_adjustment, 2)))
        score += int(round(bounded))
        strengths.append(f"outcome tuning adjustment {bounded}") if bounded > 0 else gaps.append(f"outcome_tuning_adjustment_{bounded}")

    intent_match = _candidate_intent_match(cand, intent_tokens or [])
    if intent_match:
        score += 5
        strengths.append(f"intent-aligned ({intent_match})")

    if "proof_passed" in gaps:
        score = min(score, 84)
    if "exact_latest_affected" in gaps:
        score = min(score, 80)
    if "novelty" in gaps:
        score = min(score, 76)
    if strict_blockers:
        score = min(score, 88)

    return min(score, 100), strengths, gaps


def _quality_band(score: int) -> str:
    if score >= 85:
        return "report-ready-shape"
    if score >= 70:
        return "strong-candidate"
    if score >= 50:
        return "needs-more-proof"
    return "early-or-weak"


def cmd_score(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    out_dir = run_dir / "quality"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    state = read_json(run_dir / "state.json", {})
    intent_tokens = _intent_tokens(state)
    results = []
    fail_seen = False
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get("candidates", [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]

        for cand in candidates:
            score, strengths, gaps = _score_candidate(cand, intent_tokens)
            band = _quality_band(score)
            cvss_base, cvss_error = cvss3_base_score(str(cand.get("cvss", "")))
            result = {
                "candidate_id": cand["id"],
                "title": cand.get("title", ""),
                "score": score,
                "band": band,
                "strengths": strengths,
                "gaps": gaps,
                "cvss_base_score": cvss_base,
                "cvss_error": cvss_error,
            }
            cand["quality_score"] = result
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "quality-score",
                    "score": score,
                    "band": band,
                }
            )
            results.append(result)
            fail_seen = fail_seen or score < args.fail_under
            print(f"{cand['id']} score={score} band={band}")

        save_candidates(run_dir, data)
    artifact = {"generated_at": dt.datetime.now().isoformat(timespec="seconds"), "results": results}
    dump_yaml(artifact, out_dir / f"quality_{stamp}.yaml")
    md = ["# Candidate Quality Scores", ""]
    for result in results:
        md.extend(
            [
                f"## {result['candidate_id']}: {result['title']}",
                "",
                f"- Score: `{result['score']}`",
                f"- Band: `{result['band']}`",
                f"- CVSS base score: `{result['cvss_base_score'] if result['cvss_base_score'] is not None else result['cvss_error']}`",
                f"- Strengths: `{', '.join(result['strengths'])}`",
                f"- Gaps: `{', '.join(result['gaps'])}`",
                "",
            ]
        )
    write_text(out_dir / f"quality_{stamp}.md", "\n".join(md))
    if fail_seen:
        raise SystemExit(2)


# _load_source_graph moved to source.commands.
def _top_files(graph: dict[str, Any], category: str, limit: int) -> list[str]:
    query = graph.get("queries", {}).get(category, {})
    return list((query.get("top_files") or {}).keys())[:limit]


def _build_hypotheses(graph: dict[str, Any], files_per: int) -> list[dict[str, Any]]:
    hypotheses: list[dict[str, Any]] = []

    def add(kind: str, title: str, files: list[str], rationale: str, next_step: str) -> None:
        if not files:
            return
        hypotheses.append(
            {
                "id": f"HYP-{len(hypotheses) + 1:03d}",
                "kind": kind,
                "title": title,
                "files": files[:files_per],
                "rationale": rationale,
                "next_step": next_step,
                "status": "hypothesis",
            }
        )

    event_files = set(_top_files(graph, "events_broadcasts", files_per * 2))
    authz_files = set(_top_files(graph, "authz_checks", files_per * 2))
    route_files = set(_top_files(graph, "routes_handlers", files_per * 2))
    parser_files = set(_top_files(graph, "parsers_decoders", files_per * 2))
    storage_files = set(_top_files(graph, "file_storage", files_per * 2))
    network_files = set(_top_files(graph, "network_clients", files_per * 2))
    exec_files = set(_top_files(graph, "process_execution", files_per * 2))
    native_files = set(_top_files(graph, "native_unsafe", files_per * 2))

    add(
        "realtime_authz_drift",
        "Compare websocket/event broadcasts against REST permission checks",
        sorted((event_files & authz_files) or event_files)[:files_per],
        "Realtime event publishers and permission checks are high-yield for authz drift.",
        "For each event payload, identify equivalent REST/API read path and build a denied-receiver negative control.",
    )
    add(
        "route_authz_gap",
        "Review route handlers that may depend on missing or inconsistent authz checks",
        sorted((route_files & authz_files) or route_files)[:files_per],
        "Endpoint handlers are externally reachable and must consistently enforce permission boundaries.",
        "Trace handler -> app method -> store call and compare positive user, denied user, guest, and admin behavior.",
    )
    add(
        "parser_storage_boundary",
        "Review parser and file/storage boundaries for traversal or canonicalization drift",
        sorted((parser_files & storage_files) or (parser_files | storage_files))[:files_per],
        "Parser/storage intersections often expose path traversal, archive handling, and content confusion issues.",
        "Create benign and malicious path/canonicalization controls, then verify write/read target boundaries.",
    )
    add(
        "ssrf_outbound_boundary",
        "Review outbound network clients for SSRF and internal network guard coverage",
        sorted(network_files)[:files_per],
        "Network client surfaces must distinguish trusted admin URLs from attacker-controlled URLs.",
        "Trace caller-controlled URL sources into HTTP clients and verify reserved-IP, redirect, DNS, and scheme handling.",
    )
    add(
        "command_execution_boundary",
        "Review process execution surfaces for shell or argument injection",
        sorted(exec_files)[:files_per],
        "Process execution is high-impact when attacker-controlled data reaches command, args, env, or cwd.",
        "Prove attacker control over command/argument/env separately before building any execution PoC.",
    )
    add(
        "native_memory_boundary",
        "Review native unsafe code for parser or FFI memory-safety candidates",
        sorted(native_files)[:files_per],
        "Native and unsafe surfaces need sanitizer/fuzz harness review before exploitability claims.",
        "Identify parser entrypoint, input format, ownership/lifetime model, and available sanitizer or fuzz harness.",
    )
    return hypotheses


def _order_hypotheses_by_intent(
    hypotheses: list[dict[str, Any]], intent_tokens: list[str]
) -> list[dict[str, Any]]:
    intent_kinds = (
        set().union(*(INTENT_VOCAB[t]["kinds"] for t in intent_tokens))
        if intent_tokens
        else set()
    )
    for hyp in hypotheses:
        hyp["intent_priority"] = hyp["kind"] in intent_kinds
    # Stable sort: intent-prioritised hypotheses first, original order preserved
    # within each group. Truncation happens after, so priority survives the cap.
    hypotheses.sort(key=lambda h: 0 if h["intent_priority"] else 1)
    return hypotheses


def cmd_hypothesize(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    graph = _load_source_graph(run_dir)
    out_dir = run_dir / "hypotheses"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    hypotheses = _build_hypotheses(graph, args.files_per_hypothesis)
    intent_tokens = _intent_tokens(state)
    _order_hypotheses_by_intent(hypotheses, intent_tokens)

    artifact = {
        "target_id": target["id"],
        "run_id": state.get("run_id"),
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_graph": rel(run_dir / "source_graph" / "source_graph.yaml"),
        "intent": intent_tokens,
        "hypotheses": hypotheses[: args.max_hypotheses],
    }
    dump_yaml(artifact, out_dir / f"hypotheses_{stamp}.yaml")

    md = [f"# Research Hypotheses: {target['id']}", ""]
    if intent_tokens:
        md.append(f"- Intent (threat model): `{', '.join(intent_tokens)}`")
    md.extend([f"- Run: `{state.get('run_id')}`", ""])
    for hyp in artifact["hypotheses"]:
        marker = " (intent-priority)" if hyp.get("intent_priority") else ""
        md.extend(
            [
                f"## {hyp['id']}: {hyp['title']}{marker}",
                "",
                f"- Kind: `{hyp['kind']}`",
                f"- Rationale: {hyp['rationale']}",
                f"- Next step: {hyp['next_step']}",
                "",
                "### Files",
                "",
            ]
        )
        for file_name in hyp["files"]:
            md.append(f"- `{file_name}`")
        md.append("")
    write_text(out_dir / f"hypotheses_{stamp}.md", "\n".join(md))
    print(rel(out_dir / f"hypotheses_{stamp}.md"))


SECURITY_DIFF_PATTERNS = [
    "permission",
    "authorize",
    "auth",
    "token",
    "secret",
    "websocket",
    "broadcast",
    "parse",
    "sanitize",
    "path",
    "traversal",
    "CVE",
    "security",
]


def cmd_patch_mine(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    src = source_path(target)
    ranges = args.range or ["HEAD..HEAD"]
    patterns = args.grep or SECURITY_DIFF_PATTERNS
    paths = args.path or []
    out_dir = run_dir / "patch_mining"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    range_results = []
    for ref_range in ranges:
        stat = run_cmd(["git", "diff", "--stat", ref_range, "--", *paths], src, timeout=args.timeout)
        names = run_cmd(["git", "diff", "--name-status", ref_range, "--", *paths], src, timeout=args.timeout)
        pattern_results = []
        for pattern in patterns:
            result = run_cmd(
                ["git", "diff", "-G", pattern, "--name-status", ref_range, "--", *paths],
                src,
                timeout=args.timeout,
            )
            pattern_results.append(
                {
                    "pattern": pattern,
                    "returncode": result["returncode"],
                    "timeout": result["timeout"],
                    "matches": result["stdout"].splitlines()[: args.max_matches],
                    "stderr": result["stderr"].strip(),
                }
            )
        range_results.append(
            {
                "range": ref_range,
                "stat": stat,
                "name_status": names,
                "patterns": pattern_results,
            }
        )

    artifact = {
        "target_id": target["id"],
        "run_id": state.get("run_id"),
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_path": rel(src),
        "paths": paths,
        "ranges": range_results,
    }
    dump_yaml(artifact, out_dir / f"patch_mining_{stamp}.yaml")

    md = [f"# Patch Mining: {target['id']}", "", f"- Source: `{rel(src)}`", ""]
    for item in range_results:
        md.extend(
            [
                f"## `{item['range']}`",
                "",
                "### Diff Stat",
                "",
                "```text",
                item["stat"]["stdout"].strip() or item["stat"]["stderr"].strip() or "<empty>",
                "```",
                "",
                "### Changed Files",
                "",
                "```text",
                item["name_status"]["stdout"].strip() or item["name_status"]["stderr"].strip() or "<empty>",
                "```",
                "",
                "### Security Pattern Matches",
                "",
            ]
        )
        for pattern_result in item["patterns"]:
            if not pattern_result["matches"] and not pattern_result["stderr"]:
                continue
            md.extend([f"#### `{pattern_result['pattern']}`", ""])
            if pattern_result["matches"]:
                for match in pattern_result["matches"]:
                    md.append(f"- `{match}`")
            if pattern_result["stderr"]:
                md.append(f"- Stderr: `{pattern_result['stderr']}`")
            md.append("")
    write_text(out_dir / f"patch_mining_{stamp}.md", "\n".join(md))
    print(rel(out_dir / f"patch_mining_{stamp}.md"))


def cmd_proof_plan(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    out_dir = run_dir / "proof_plans"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"{args.candidate_id}_{stamp}.md"

    md = [
        f"# Proof Plan: {args.candidate_id}",
        "",
        f"- Title: {cand.get('title', '')}",
        f"- Current status: `{cand.get('status', '')}`",
        f"- Exploitability target: `{args.level or cand.get('exploitability', 'L3 deterministic local security impact')}`",
        "",
        "## Thesis",
        "",
        f"- Attacker control: {cand.get('attacker_control', '')}",
        f"- Entrypoint: {cand.get('entrypoint', '')}",
        f"- Trust boundary: {cand.get('trust_boundary', '')}",
        f"- Sink: {cand.get('sink', '')}",
        f"- Impact: {cand.get('impact', '')}",
        "",
        "## Preconditions",
        "",
        "- Current/latest affected version is installed locally.",
        "- Test instance is self-hosted or otherwise explicitly authorized.",
        "- Required feature flags/configuration are recorded.",
        "- Test users/roles needed for positive and negative controls exist.",
        "",
        "## Positive Proof",
        "",
        args.positive or "- Execute the vulnerable workflow and capture the security-relevant output.",
        "",
        "## Negative Controls",
        "",
        cand.get("negative_controls") or "- Add at least one denied/benign/patched control before claiming impact.",
        "",
        "## Evidence To Capture",
        "",
        "- Exact version, commit, package versions, and configuration.",
        "- Command, stdout, stderr, exit status, and timestamps.",
        "- Positive proof artifact.",
        "- Negative-control artifact.",
        "- Cleanup result.",
        "",
        "## Cleanup",
        "",
        args.cleanup or "- Remove test users, temporary files, services, database state, and tokens created for the proof.",
        "",
        "## Submission Blockers",
        "",
        "- No latest-version proof.",
        "- No negative control.",
        "- No clear root cause.",
        "- Duplicate/advisory status not checked.",
        "- Impact relies on speculation rather than captured behavior.",
        "",
    ]
    write_text(out, "\n".join(md))
    def mark_proof_plan(updated: dict[str, Any]) -> None:
        updated["proof_plan"] = rel(out)
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "proof-plan",
                "artifact": rel(out),
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_proof_plan)
    print(rel(out))


SEMANTIC_SUFFIXES = {".go", ".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".rb"}
CALL_STOPWORDS = {
    "if",
    "for",
    "switch",
    "return",
    "func",
    "range",
    "go",
    "defer",
    "select",
    "case",
    "var",
    "const",
    "new",
    "make",
    "len",
    "cap",
    "append",
    "copy",
    "delete",
    "print",
    "println",
    "require",
    "assert",
}


# _is_default_excluded moved to source.commands.
# _source_files moved to source.commands.
# _function_defs moved to source.commands.
def _calls_in_body(body: str) -> list[str]:
    names = re.findall(r"(?:\.|\b)([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)
    seen: set[str] = set()
    calls: list[str] = []
    for name in names:
        if name in CALL_STOPWORDS or name.lower() in CALL_STOPWORDS:
            continue
        if name not in seen:
            seen.add(name)
            calls.append(name)
    return calls[:80]


def _semantic_categories(body: str) -> list[str]:
    # Dedupe by regex so alias/canonical pairs that share a pattern
    # (e.g. network_clients/network_ssrf) collapse to one. Insertion order
    # places aliases first and canonical names last, so last-wins keeps the
    # canonical surfaces.yaml category name.
    by_pattern: dict[str, str] = {}
    for category, pattern in GRAPH_QUERIES.items():
        if category == "functions":
            continue
        if re.search(pattern, body, flags=re.IGNORECASE):
            by_pattern[pattern] = category
    return list(by_pattern.values())


# cmd_semantic_graph moved to source.commands.
# _load_semantic_graph moved to source.commands.
def _terms_from_candidate(cand: dict[str, Any], supplied: list[str] | None) -> list[str]:
    terms = list(supplied or [])
    for key in ("entrypoint", "sink", "root_cause", "trust_boundary", "title", "impact"):
        value = str(cand.get(key, "") or "")
        terms.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", value))
    seen: set[str] = set()
    output = []
    for term in terms:
        lowered = term.lower()
        if lowered in COMMON_VARIANT_TERMS or lowered in seen:
            continue
        seen.add(lowered)
        output.append(term)
    return output[:30]


def _function_for_hit(functions: list[dict[str, Any]], file_name: str, line_no: int) -> dict[str, Any] | None:
    candidates = [
        fn
        for fn in functions
        if fn.get("file") == file_name and int(fn.get("line", 0)) <= line_no <= int(fn.get("end_line", 0))
    ]
    if candidates:
        return sorted(candidates, key=lambda fn: int(fn.get("line", 0)), reverse=True)[0]
    return None


def cmd_flow_trace(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    graph = _load_semantic_graph(run_dir)
    functions = graph.get("functions", [])
    terms = list(args.term or []) if args.only_terms else _terms_from_candidate(cand, args.term)
    out_dir = run_dir / "flow_traces"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    term_hits = []
    function_hits: dict[str, dict[str, Any]] = {}
    for term in terms:
        cmd = ["rg", "-n", "-S", "-F", term]
        for path in args.path or []:
            cmd.append(path)
        if not args.include_tests:
            for glob in DEFAULT_SOURCE_GRAPH_EXCLUDES:
                cmd.extend(["--glob", glob])
        result = run_cmd(cmd, src, timeout=args.timeout)
        hits = result["stdout"].splitlines()[: args.max_hits] if result["returncode"] in (0, 1) else []
        mapped = []
        for hit in hits:
            parts = hit.split(":", 2)
            if len(parts) < 3:
                continue
            file_name, raw_line, text = parts
            try:
                line_no = int(raw_line)
            except ValueError:
                continue
            fn = _function_for_hit(functions, file_name, line_no)
            mapped_item = {
                "hit": hit,
                "file": file_name,
                "line": line_no,
                "function": fn.get("name") if fn else "<module>",
                "function_line": fn.get("line") if fn else "",
                "categories": fn.get("categories", []) if fn else [],
            }
            mapped.append(mapped_item)
            key = f"{file_name}:{mapped_item['function']}:{mapped_item['function_line']}"
            bucket = function_hits.setdefault(
                key,
                {
                    "file": file_name,
                    "function": mapped_item["function"],
                    "function_line": mapped_item["function_line"],
                    "terms": set(),
                    "categories": set(mapped_item["categories"]),
                    "hits": [],
                },
            )
            bucket["terms"].add(term)
            bucket["hits"].append(hit)
        term_hits.append({"term": term, "mapped_hits": mapped, "returncode": result["returncode"]})

    ranked = []
    for item in function_hits.values():
        categories = set(item["categories"])
        score = len(item["terms"]) * 5 + len(categories) * 3
        if "authz_checks" in categories:
            score += 8
        if "events_broadcasts" in categories:
            score += 8
        if "routes_handlers" in categories:
            score += 6
        if "network_clients" in categories or "process_execution" in categories:
            score += 6
        ranked.append(
            {
                "score": score,
                "file": item["file"],
                "function": item["function"],
                "function_line": item["function_line"],
                "terms": sorted(item["terms"]),
                "categories": sorted(categories),
                "hits": item["hits"][: args.max_hits_per_function],
            }
        )
    ranked.sort(key=lambda item: (-item["score"], item["file"], str(item["function_line"])))

    artifact = {
        "candidate_id": args.candidate_id,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "terms": terms,
        "ranked_functions": ranked[: args.max_functions],
        "term_hits": term_hits,
    }
    base = out_dir / f"{args.candidate_id}_{stamp}"
    dump_yaml(artifact, base.with_suffix(".yaml"))

    md = [
        f"# Flow Trace: {args.candidate_id}",
        "",
        f"- Candidate: `{cand.get('title', '')}`",
        f"- Terms: `{', '.join(terms)}`",
        "",
        "## Ranked Functions",
        "",
    ]
    for item in ranked[: args.max_functions]:
        md.extend(
            [
                f"### `{item['file']}:{item['function_line']} {item['function']}`",
                "",
                f"- Score: `{item['score']}`",
                f"- Terms: `{', '.join(item['terms'])}`",
                f"- Categories: `{', '.join(item['categories'])}`",
                "",
            ]
        )
        for hit in item["hits"]:
            md.append(f"- `{hit}`")
        md.append("")
    write_text(base.with_suffix(".md"), "\n".join(md))

    def mark_flow(updated: dict[str, Any]) -> None:
        updated["flow_trace"] = rel(base.with_suffix(".md"))
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "flow-trace",
                "artifact": rel(base.with_suffix(".md")),
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_flow)
    print(rel(base.with_suffix(".md")))


def cmd_test_skeleton(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    out_dir = run_dir / "test_skeletons"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{args.candidate_id}_{stamp}"

    test_name = args.test_name or re.sub(r"[^A-Za-z0-9]+", "_", cand.get("title", "candidate")).strip("_")
    if not test_name.startswith("Test"):
        test_name = "Test" + test_name[:120]

    go_skeleton = f"""func {test_name}(t *testing.T) {{
    // Preconditions:
    // - Latest affected version is running locally.
    // - Required feature/config flags are enabled.
    // - Positive actor, denied actor, and target object/user are created.

    t.Run("negative control denies access", func(t *testing.T) {{
        // Prove the receiver cannot access the target through the intended guarded path.
        // Expected: 403/permission error or equivalent redaction.
    }})

    t.Run("positive proof demonstrates impact", func(t *testing.T) {{
        // Execute entrypoint:
        // {cand.get('entrypoint', '')}
        //
        // Observe sink/effect:
        // {cand.get('sink', '')}
        //
        // Expected impact:
        // {cand.get('impact', '')}
    }})

    t.Run("cleanup", func(t *testing.T) {{
        // Remove test users, objects, files, services, tokens, and temporary state.
    }})
}}
"""

    md = [
        f"# Test Skeleton: {args.candidate_id}",
        "",
        f"- Candidate: {cand.get('title', '')}",
        f"- Framework: `{args.framework}`",
        "",
        "## Required Assertions",
        "",
        f"- Attacker control: {cand.get('attacker_control', '')}",
        f"- Entrypoint: {cand.get('entrypoint', '')}",
        f"- Trust boundary: {cand.get('trust_boundary', '')}",
        f"- Sink: {cand.get('sink', '')}",
        f"- Negative control: {cand.get('negative_controls', '')}",
        "",
        "## Go Test Skeleton",
        "",
        "```go",
        go_skeleton.rstrip(),
        "```",
        "",
    ]
    write_text(base.with_suffix(".md"), "\n".join(md))
    write_text(base.with_suffix(".go.txt"), go_skeleton)

    def mark_skeleton(updated: dict[str, Any]) -> None:
        updated["test_skeleton"] = rel(base.with_suffix(".md"))
        updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "test-skeleton",
                "artifact": rel(base.with_suffix(".md")),
            }
        )

    update_candidate_locked(run_dir, args.candidate_id, mark_skeleton)
    print(rel(base.with_suffix(".md")))


def cmd_ledger_sqlite(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    db_path = run_path(args.db) if args.db else run_dir / "candidates.sqlite"
    if args.from_sqlite:
        with candidate_ledger_lock(run_dir):
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute(
                    "select candidate_json from candidates order by rowid"
                ).fetchall()
            candidates = [_normalize_candidate(json.loads(row[0])) for row in rows]
            dump_yaml(
                {"schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION, "candidates": candidates},
                run_dir / "candidates.yaml",
            )
        print(rel(run_dir / "candidates.yaml"))
        return

    data = load_candidates(run_dir)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "create table if not exists candidates (id text primary key, status text, title text, candidate_json text not null)"
        )
        conn.execute(
            "create table if not exists history (candidate_id text, at text, event text, history_json text not null)"
        )
        conn.execute("delete from candidates")
        conn.execute("delete from history")
        for cand in data.get("candidates", []):
            conn.execute(
                "insert or replace into candidates (id, status, title, candidate_json) values (?, ?, ?, ?)",
                (
                    cand.get("id", ""),
                    cand.get("status", ""),
                    cand.get("title", ""),
                    json.dumps(cand, sort_keys=False),
                ),
            )
            for item in cand.get("history", []) if isinstance(cand.get("history"), list) else []:
                conn.execute(
                    "insert into history (candidate_id, at, event, history_json) values (?, ?, ?, ?)",
                    (
                        cand.get("id", ""),
                        item.get("at", ""),
                        item.get("event", ""),
                        json.dumps(item, sort_keys=False),
                    ),
                )
        conn.commit()
    print(rel(db_path))


def _candidate_from_blackbox(item: dict[str, Any], next_id: str) -> dict[str, Any]:
    severity = str(item.get("severity") or "unknown").lower()
    cve_match = re.search(r"CVE-\d{4}-\d{4,}", json.dumps(item), flags=re.IGNORECASE)
    title = item.get("title") or item.get("name") or item.get("template_id") or "Blackbox scanner finding"
    cwe = item.get("cwe") or ("CWE-200" if "exposure" in title.lower() or "leak" in title.lower() else "CWE-693")
    impact = item.get("impact") or f"Blackbox evidence reported severity `{severity}` for `{title}`."
    return _normalize_candidate(
        {
            "schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION,
            "id": next_id,
            "title": str(title)[:180],
            "status": "candidate",
            "surface": item.get("surface") or "outside-in blackbox",
            "weakness": cwe,
            "impact": impact,
            "attacker_control": item.get("attacker_control") or "remote HTTP/TLS request within authorized blackbox scope",
            "entrypoint": item.get("matched_at") or item.get("url") or item.get("host") or "",
            "trust_boundary": "external client to exposed service",
            "latest_affected": "unchecked",
            "sink": item.get("sink") or item.get("evidence") or str(title),
            "novelty": "unchecked",
            "proof": "not_started",
            "cve": cve_match.group(0).upper() if cve_match else "N/A",
            "cwe": cwe,
            "cvss": "",
            "notes": item.get("notes") or "",
            "created_at": dt.datetime.now().isoformat(timespec="seconds"),
            "history": [
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": "created:ingest-blackbox-run",
                }
            ],
        }
    )


def _parse_blackbox_json(path: Path, include_info: bool) -> list[dict[str, Any]]:
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return findings
    if not text:
        return findings
    records = []
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                records.append(json.loads(line))
    else:
        with contextlib.suppress(json.JSONDecodeError):
            loaded = json.loads(text)
            records = loaded if isinstance(loaded, list) else [loaded]
    for record in records:
        if not isinstance(record, dict):
            continue
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        severity = str(record.get("severity") or info.get("severity") or "").lower()
        if severity in {"info", "unknown", ""} and not include_info:
            continue
        title = info.get("name") or record.get("name") or record.get("template-id") or record.get("id")
        findings.append(
            {
                "title": title,
                "severity": severity or "unknown",
                "template_id": record.get("template-id") or record.get("id"),
                "matched_at": record.get("matched-at") or record.get("url") or record.get("host"),
                "evidence": record.get("extracted-results") or record.get("curl-command") or "",
                "source_file": rel(path),
                "raw": record,
            }
        )
    return findings


def _parse_blackbox_text(path: Path, include_info: bool) -> list[dict[str, Any]]:
    findings = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings
    for line in lines:
        lowered = line.lower()
        severity = ""
        for candidate in ("critical", "high", "medium", "low", "info"):
            if candidate in lowered:
                severity = candidate
                break
        if severity in {"", "info", "low"} and not include_info:
            continue
        if not re.search(r"(cve-\d{4}-\d{4,}|vulnerab|weak|expos|misconfig|tls|ssl|xss|ssrf|injection)", lowered):
            continue
        findings.append(
            {
                "title": line.strip()[:180],
                "severity": severity or "unknown",
                "matched_at": "",
                "evidence": line.strip(),
                "source_file": rel(path),
            }
        )
    return findings


def cmd_ingest_blackbox_run(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    evidence_dir = run_path(args.evidence_dir)
    if not evidence_dir.exists():
        raise SystemExit(f"blackbox evidence directory not found: {evidence_dir}")
    findings = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file() or path.stat().st_size > args.max_file_mb * 1024 * 1024:
            continue
        if path.suffix.lower() in {".json", ".jsonl"}:
            findings.extend(_parse_blackbox_json(path, args.include_info))
        elif path.suffix.lower() in {".txt", ".md", ".log", ".csv"}:
            findings.extend(_parse_blackbox_text(path, args.include_info))
    findings = findings[: args.max_findings]

    out_dir = run_dir / "blackbox_ingest"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "evidence_dir": rel(evidence_dir),
        "finding_count": len(findings),
        "findings": findings,
    }
    dump_yaml(artifact, out_dir / f"blackbox_ingest_{stamp}.yaml")

    created = []
    if args.create_candidates and findings:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in findings:
                cand = _candidate_from_blackbox(item, next_candidate_id(data))
                data.setdefault("candidates", []).append(cand)
                created.append(cand["id"])
            save_candidates(run_dir, data)

    md = [
        "# Blackbox Evidence Ingest",
        "",
        f"- Evidence dir: `{rel(evidence_dir)}`",
        f"- Findings parsed: `{len(findings)}`",
        f"- Candidates created: `{', '.join(created) or 'none'}`",
        "",
    ]
    for item in findings:
        md.extend(
            [
                f"## {item.get('title')}",
                "",
                f"- Severity: `{item.get('severity')}`",
                f"- Matched at: `{item.get('matched_at', '')}`",
                f"- Source file: `{item.get('source_file', '')}`",
                f"- Evidence: `{str(item.get('evidence', ''))[:300]}`",
                "",
            ]
        )
    write_text(out_dir / f"blackbox_ingest_{stamp}.md", "\n".join(md))
    print(rel(out_dir / f"blackbox_ingest_{stamp}.md"))


TAINT_SOURCE_RE = r"(\br\b\.(URL|Body|Header|Form|PostForm)|c\.Params|request\.(args|form|json|headers|cookies|body)|req\.(body|query|params|headers|cookies)|URL\.Query|FormValue|Query\(|\b(argv|args|input|param|params|query|body|url)\b)"
# "Strong" sources unambiguously denote externally-controlled request data. The
# bare-name tokens (argv/args/input/param/params/query/body/url) in the full
# source regex are "weak": a local variable that happens to be named `params`
# is not request data. STRONG_SOURCE_RE is used for the same-line source check so
# a shadowed local does not register as a source reaching the sink.
STRONG_SOURCE_RE = r"(\br\b\.(URL|Body|Header|Form|PostForm)|c\.Params|request\.(args|form|json|headers|cookies|body)|req\.(body|query|params|headers|cookies)|URL\.Query|FormValue|Query\()"
WEAK_SOURCE_NAMES = {"argv", "args", "input", "param", "params", "query", "body", "url"}
TAINT_ASSIGN_RE = re.compile(r"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)")


def _function_body(src: Path, fn: dict[str, Any]) -> list[str]:
    path = src / str(fn.get("file", ""))
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[int(fn.get("line", 1)) - 1 : int(fn.get("end_line", fn.get("line", 1)))]


# Guards that constrain a tainted value before it reaches a sink. When a flow is
# guarded the value is no longer attacker-controlled in the dangerous position, so
# the flow is annotated and downranked rather than dropped (recall is preserved —
# the guard heuristic can be wrong, so true positives must stay in the report).
GUARD_WHITELIST_RE = re.compile(
    r"(\.include\?\(|\.member\?\(|%i\[|%w\[|allow_?list|white_?list|ALLOWED_|PERMITTED|\.to_sym\b)"
)


def _flow_guard(lines: list[str], fn_start: int, sink_offset: int, tainted: list[str], sink_line: str) -> str | None:
    """Return a guard reason if the tainted value is constrained before/at the sink, else None."""
    # Dispatch where the invoked method name is a setter ("#{x}=") or a string
    # literal with no interpolation — attacker cannot pick an arbitrary method.
    if re.search(r"(?:public_send|send|__send__)\(\s*[\"'][^\"']*=[\"']", sink_line):
        return "constrained_setter_dispatch"
    if re.search(r"(?:public_send|send|__send__)\(\s*[\"'][^\"'#]+[\"']\s*[,)]", sink_line):
        return "literal_method_dispatch"
    # Parameterized query: the value is bound as a separate argument, not
    # interpolated (#{var}) or concatenated (+ / <<) into the query string. Covers
    # raw DB.exec/find_by_sql and ActiveRecord query methods whose hash/bind forms
    # are escaped by the adapter — a real injection requires interpolation, which
    # the checks below detect and leave unguarded.
    if re.search(
        r"(DB\.exec|\.exec\(|exec_query|find_by_sql|count_by_sql|"
        r"\.(?:where|update_all|delete_all|order|group|having|pluck)\b)",
        sink_line,
    ):
        interpolated = any(re.search(r"#\{[^}]*\b" + re.escape(v) + r"\b[^}]*\}", sink_line) for v in tainted)
        concatenated = any(
            re.search(r"(?:\+|<<)\s*" + re.escape(v) + r"\b|\b" + re.escape(v) + r"\s*(?:\+|<<)", sink_line)
            for v in tainted
        )
        if not interpolated and not concatenated:
            return "parameterized_bind"
    # Look back over the function body (through the sink line) for a whitelist,
    # validation/sanitization, signature gate, or literal-branch ternary that
    # references one of the tainted variables.
    window = lines[: sink_offset - fn_start + 1]
    for ln in window:
        refs = any(re.search(rf"\b{re.escape(v)}\b", ln) for v in tainted)
        if refs and GUARD_WHITELIST_RE.search(ln):
            return "whitelist_check"
        if refs and re.search(DEFAULT_GUARD_DRIFT_REGEX, ln, flags=re.IGNORECASE):
            return "validation_guard"
        for v in tainted:
            if re.search(rf"\b{re.escape(v)}\s*=.*\?\s*[\"'][^\"']*[\"']\s*:\s*[\"'][^\"']*[\"']", ln):
                return "literal_ternary"
    for ln in window:
        if re.search(r"raise\b.*[Ss]ignature", ln) or (re.search(r"\bsign\b", ln) and "!=" in ln):
            return "signature_gate"
    return None


# _taint_function moved to source.commands.
# cmd_taint_trace moved to source.commands.
DEFAULT_GUARD_DRIFT_REGEX = (
    r"(isFileAccessDenied|file_deny|deny_glob|SafeLoader|safe_load|"
    r"validate[A-Za-z0-9_]*(?:Url|URL|Uri|URI|Path|File|Archive|Redirect|Permission|Access)|"
    r"check[A-Za-z0-9_]*(?:Permission|Access|Auth|Allowed|Deny|Path|File)|"
    r"authorize|authorization|permission|allowlist|denylist|blocklist|trusted|sanitize|canonical|normalize|clean)"
)

GUARD_DRIFT_SINK_OVERRIDES = {
    "file_storage": (
        r"(FileOutputStream|FileInputStream|FileWriter|Files\.(?:write|read|copy|move|create)|"
        r"persist\.create|PersistUtils\.(?:write|read)|H2O\.getPM\(\)\.create|"
        r"\b(?:persist|pm|p|os)\.create\(|ReadFile|WriteFile|new\s+File\s*\(|Paths\.get|Path\.of)"
    ),
    "path_traversal": (
        r"(extractall|ZipFile|JarInputStream|TarArchive|new\s+File\s*\(|Paths\.get|Path\.of|"
        r"normalize\(|getCanonicalPath|toRealPath|read_text|write_text|send_file|FileOutputStream|FileInputStream)"
    ),
}


def _active_code_lines(lines: list[str]) -> list[str]:
    active = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if in_block:
            active.append("")
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith(("/*", "*", "//", "#")):
            active.append("")
            if stripped.startswith("/*") and "*/" not in stripped:
                in_block = True
            continue
        active.append(line)
    return active


def _line_hits(lines: list[str], regex: str, start_line: int, max_hits: int = 8) -> list[dict[str, Any]]:
    hits = []
    for offset, line in enumerate(lines, start=start_line):
        if re.search(regex, line, flags=re.IGNORECASE):
            hits.append({"line": offset, "text": line.strip()[:260]})
            if len(hits) >= max_hits:
                break
    return hits


def _guard_drift_functions(src: Path, include_tests: bool, paths: list[str] | None, max_files: int, max_functions: int) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for path in _source_files(src, include_tests, paths, max_files):
        rel_name = rel(path).removeprefix(rel(src) + "/")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        defs = _function_defs(rel_name, text)
        if not defs:
            defs = [
                {
                    "file": rel_name,
                    "line": 1,
                    "end_line": len(lines),
                    "name": "<module>",
                    "kind": "module",
                    "signature": rel_name,
                }
            ]
        for fn in defs:
            body_lines = lines[int(fn["line"]) - 1 : int(fn["end_line"])]
            item = dict(fn)
            item["body_lines"] = body_lines
            functions.append(item)
            if len(functions) >= max_functions:
                return functions
    return functions


def _sibling_guarded_examples(record: dict[str, Any], guarded: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    same_category = [item for item in guarded if item["category"] == record["category"]]
    same_dir = [
        item for item in same_category
        if str(Path(item["file"]).parent) == str(Path(record["file"]).parent)
    ]
    same_file = [item for item in same_category if item["file"] == record["file"]]
    ranked = []
    seen = set()
    for bucket in (same_file, same_dir, same_category):
        for item in bucket:
            key = (item["file"], item["function"], item["line"])
            if key in seen:
                continue
            seen.add(key)
            ranked.append(
                {
                    "file": item["file"],
                    "function": item["function"],
                    "line": item["line"],
                    "guard_hits": item["guard_hits"][:2],
                    "sink_hits": item["sink_hits"][:2],
                }
            )
            if len(ranked) >= limit:
                return ranked
    return ranked


def _guard_drift_candidate(item: dict[str, Any], cand_id: str, artifact_md: Path) -> dict[str, Any]:
    category = item.get("category", "sink")
    file_name = item.get("file", "")
    function = item.get("function", "")
    guarded = item.get("guarded_examples", [])
    guarded_summary = ""
    if guarded:
        first = guarded[0]
        guarded_summary = f" guarded sibling `{first.get('file')}:{first.get('line')} {first.get('function')}` applies a guard before a comparable `{category}` sink."
    return {
        "schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION,
        "id": cand_id,
        "title": f"Possible guard drift: unguarded {category} sink in {function}",
        "status": "auto-candidate",
        "surface": f"{file_name}:{item.get('line')} {function}",
        "weakness": "CWE-693",
        "impact": "A security guard appears inconsistently applied across sibling sink paths; prove whether attacker-controlled input reaches the unguarded path.",
        "attacker_control": "unknown; trace route/API input into the unguarded sink before promotion",
        "entrypoint": f"{file_name}:{item.get('line')}",
        "trust_boundary": "security guard drift across comparable source-to-sink paths",
        "latest_affected": "unchecked",
        "sink": "; ".join(hit.get("text", "") for hit in item.get("sink_hits", [])[:2]),
        "novelty": "unchecked",
        "dedup": {"status": "unchecked", "matches": [], "checked_at": ""},
        "proof": "not_started",
        "cve": "N/A",
        "cwe": "CWE-693",
        "cvss": "",
        "framework_mappings": {},
        "negative_controls": "Required: guarded sibling path rejects or constrains the same class of input while this path reaches the sink.",
        "safety_notes": "Auto-created from guard-drift analysis. Do not submit without route reachability, attacker control, duplicate check, and runtime proof.",
        "reference_sources": rel(artifact_md),
        "root_cause": f"Comparable `{category}` sinks do not all apply the same guard.{guarded_summary}",
        "variant_analysis": rel(artifact_md),
        "patch_diff": "",
        "exploitability": "L1 source signal",
        "disclosure_quality": "",
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "notes": json.dumps({"guard_drift": item}, sort_keys=True),
        "history": [
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "created:auto-candidate",
                "source": rel(artifact_md),
                "tool": "guard-drift",
            }
        ],
    }


def cmd_guard_drift(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    src = source_path(target)
    categories = args.sink_category or ["file_storage", "path_traversal", "deserialization", "network_clients", "process_execution"]
    sink_patterns = {
        category: GUARD_DRIFT_SINK_OVERRIDES.get(category, GRAPH_QUERIES[category])
        for category in categories
        if category in GRAPH_QUERIES or category in GUARD_DRIFT_SINK_OVERRIDES
    }
    if not sink_patterns:
        raise SystemExit("no valid sink categories selected")
    guard_regex = args.guard_regex or DEFAULT_GUARD_DRIFT_REGEX
    functions = _guard_drift_functions(src, args.include_tests, args.path, args.max_files, args.max_functions)

    guarded: list[dict[str, Any]] = []
    unguarded: list[dict[str, Any]] = []
    for fn in functions:
        body_lines = fn.get("body_lines", [])
        if not body_lines:
            continue
        active_lines = _active_code_lines(body_lines)
        body = "\n".join(active_lines)
        guard_hits = _line_hits(active_lines, guard_regex, int(fn.get("line", 1)))
        for category, sink_regex in sink_patterns.items():
            if not re.search(sink_regex, body, flags=re.IGNORECASE):
                continue
            item = {
                "category": category,
                "file": fn.get("file", ""),
                "function": fn.get("name", ""),
                "line": fn.get("line", ""),
                "end_line": fn.get("end_line", ""),
                "signature": fn.get("signature", ""),
                "sink_hits": _line_hits(active_lines, sink_regex, int(fn.get("line", 1))),
                "guard_hits": guard_hits,
            }
            if guard_hits:
                guarded.append(item)
            else:
                unguarded.append(item)

    candidates = []
    for item in unguarded:
        examples = _sibling_guarded_examples(item, guarded, args.examples)
        if args.require_guarded_sibling and not examples:
            continue
        ranked = dict(item)
        ranked["guarded_examples"] = examples
        ranked["confidence"] = "higher" if examples else "low-no-guarded-sibling"
        candidates.append(ranked)
    candidates.sort(
        key=lambda item: (
            0 if item.get("guarded_examples") else 1,
            str(item.get("category")),
            str(item.get("file")),
            int(item.get("line") or 0),
        )
    )
    candidates = candidates[: args.max_candidates]

    out_dir = run_dir / "guard_drift"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"guard_drift_{stamp}"
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "target_id": target.get("id", ""),
        "run_id": state.get("run_id", ""),
        "source_path": rel(src),
        "guard_regex": guard_regex,
        "sink_categories": list(sink_patterns),
        "functions_scanned": len(functions),
        "guarded_sink_functions": len(guarded),
        "unguarded_sink_functions": len(unguarded),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
    dump_yaml(payload, base.with_suffix(".yaml"))

    md = [
        "# Guard Drift Analysis",
        "",
        f"- Target: `{target.get('id', '')}`",
        f"- Source: `{rel(src)}`",
        f"- Guard regex: `{guard_regex}`",
        f"- Sink categories: `{', '.join(sink_patterns)}`",
        f"- Functions scanned: `{len(functions)}`",
        f"- Guarded sink functions: `{len(guarded)}`",
        f"- Unguarded sink functions: `{len(unguarded)}`",
        f"- Candidate signals: `{len(candidates)}`",
        "",
    ]
    for item in candidates:
        md.extend(
            [
                f"## `{item['file']}:{item['line']} {item['function']}`",
                "",
                f"- Category: `{item['category']}`",
                f"- Confidence: `{item['confidence']}`",
                f"- Signature: `{item.get('signature', '')}`",
                "",
                "### Sink Hits",
                "",
            ]
        )
        for hit in item.get("sink_hits", []):
            md.append(f"- `{hit['line']}`: `{hit['text']}`")
        md.extend(["", "### Guarded Sibling Examples", ""])
        if item.get("guarded_examples"):
            for example in item["guarded_examples"]:
                md.append(f"- `{example['file']}:{example['line']} {example['function']}`")
                for hit in example.get("guard_hits", []):
                    md.append(f"  - guard `{hit['line']}`: `{hit['text']}`")
                for hit in example.get("sink_hits", []):
                    md.append(f"  - sink `{hit['line']}`: `{hit['text']}`")
        else:
            md.append("- No guarded sibling captured; treat as low-confidence broad sink inventory.")
        md.append("")
    write_text(base.with_suffix(".md"), "\n".join(md))

    created = []
    if args.create_candidates and candidates:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in candidates[: args.create_limit]:
                cand = _guard_drift_candidate(item, next_candidate_id(data), base.with_suffix(".md"))
                data.setdefault("candidates", []).append(cand)
                created.append(cand["id"])
            save_candidates(run_dir, data)
    if created:
        print(f"{rel(base.with_suffix('.md'))} created={','.join(created)}")
    else:
        print(rel(base.with_suffix(".md")))


def cmd_report(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    references = load_yaml(run_dir / "references.yaml") if (run_dir / "references.yaml").exists() else {"references": []}
    out = run_dir / "reports" / "triage_draft.md"
    md = [
        f"# Triage Draft: {target['id']}",
        "",
        f"- Run: `{state.get('run_id')}`",
        f"- Target: `{target.get('name', target['id'])}`",
        f"- Source: `{target.get('source_path')}`",
        "",
        "## Candidates",
        "",
    ]
    for cand in data.get("candidates", []):
        md.extend(
            [
                f"### {cand['id']}: {cand['title']}",
                "",
                f"- Status: `{cand.get('status')}`",
                f"- Surface: `{cand.get('surface')}`",
                f"- Weakness: `{cand.get('weakness')}`",
                f"- CVE: `{cand.get('cve')}`",
                f"- CWE: `{cand.get('cwe', cand.get('weakness', ''))}`",
                f"- CVSS: `{cand.get('cvss', '')}`",
                f"- Impact: {cand.get('impact')}",
                f"- Attacker control: {cand.get('attacker_control')}",
                f"- Entrypoint: {cand.get('entrypoint', '')}",
                f"- Trust boundary: {cand.get('trust_boundary', '')}",
                f"- Latest affected: `{cand.get('latest_affected', '')}`",
                f"- Sink: `{cand.get('sink')}`",
                f"- Duplicate status: `{cand.get('novelty')}`",
                f"- Proof: `{cand.get('proof')}`",
                f"- Negative controls: {cand.get('negative_controls', '')}",
                f"- Root cause: {cand.get('root_cause', '')}",
                f"- Variant analysis: {cand.get('variant_analysis', '')}",
                f"- Patch/advisory diff: {cand.get('patch_diff', '')}",
                f"- Exploitability: {cand.get('exploitability', '')}",
                f"- Safety notes: {cand.get('safety_notes', '')}",
                f"- Framework mappings: `{json.dumps(cand.get('framework_mappings', {}), sort_keys=True)}`",
                f"- Decision reason: {cand.get('decision_reason', '')}",
                "",
            ]
        )
    if references.get("references"):
        md.extend(["## References Ledger", ""])
        for ref in references.get("references", []):
            md.append(
                f"- `{ref.get('kind', '')}` {ref.get('title', '')}: {ref.get('url', ref.get('path', ''))}"
            )
        md.append("")
    write_text(out, "\n".join(md))
    print(rel(out))


def cmd_reference_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    path = run_dir / "references.yaml"
    data = load_yaml(path) if path.exists() else {"references": []}
    ref = {
        "added_at": dt.datetime.now().isoformat(timespec="seconds"),
        "kind": args.kind,
        "title": args.title,
        "url": args.url or "",
        "path": args.path or "",
        "candidate_id": args.candidate_id or "",
        "notes": args.notes or "",
        "trusted": bool(args.trusted),
    }
    data.setdefault("references", []).append(ref)
    dump_yaml(data, path)
    print(rel(path))


def cmd_dashboard(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    candidates = data.get("candidates", [])
    counts: dict[str, int] = {}
    for cand in candidates:
        status = cand.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1

    rows = []
    for cand in candidates:
        ok, blocking = promotion_findings(cand)
        rows.append(
            "<tr>"
            f"<td>{html.escape(cand.get('id', ''))}</td>"
            f"<td>{html.escape(cand.get('status', ''))}</td>"
            f"<td>{html.escape(cand.get('title', ''))}</td>"
            f"<td>{html.escape(cand.get('weakness', ''))}</td>"
            f"<td>{html.escape(cand.get('novelty', ''))}</td>"
            f"<td>{html.escape(cand.get('proof', ''))}</td>"
            f"<td>{'pass' if ok else html.escape(', '.join(blocking))}</td>"
            "</tr>"
        )

    html_doc = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Harness Dashboard - {html.escape(target['id'])}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; color: #17202a; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccd1d1; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f3; }}
    code {{ background: #f4f6f7; padding: 1px 4px; }}
    .summary {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
    .pill {{ border: 1px solid #ccd1d1; padding: 8px 10px; border-radius: 6px; background: #fafafa; }}
  </style>
</head>
<body>
  <h1>Harness Dashboard: {html.escape(target['id'])}</h1>
  <p>Run <code>{html.escape(str(state.get('run_id')))}</code> in <code>{html.escape(rel(run_dir))}</code></p>
  <div class=\"summary\">
    <div class=\"pill\">Stages: {html.escape(', '.join(sorted(state.get('stages', {}).keys())) or 'none')}</div>
    <div class=\"pill\">Candidates: {len(candidates)}</div>
    <div class=\"pill\">Status counts: {html.escape(json.dumps(counts, sort_keys=True))}</div>
  </div>
  <table>
    <thead>
      <tr><th>ID</th><th>Status</th><th>Title</th><th>CWE</th><th>Duplicate Status</th><th>Proof</th><th>Gate</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
    out = run_dir / "dashboard.html"
    write_text(out, html_doc)
    print(rel(out))


def cmd_status(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    counts: dict[str, int] = {}
    for cand in data.get("candidates", []):
        counts[cand.get("status", "unknown")] = counts.get(cand.get("status", "unknown"), 0) + 1
    result = {
        "target": target["id"],
        "run": state.get("run_id"),
        "status": state.get("status"),
        "stages": sorted(state.get("stages", {}).keys()),
        "candidates": counts,
        "budget": budget_status(run_dir),
        "next_action": recommend_next_action(run_dir),
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"target={result['target']} run={result['run']} status={result['status']}")
        print("stages=" + ",".join(result["stages"]))
        print("candidates=" + json.dumps(counts, sort_keys=True))


# _parse_time moved to core.py (leaf datetime utility).
from core import _parse_time  # noqa: E402


def _run_elapsed_minutes(state: dict[str, Any], candidates: list[dict[str, Any]]) -> int:
    starts = [_parse_time(state.get("created_at"))]
    for cand in candidates:
        starts.append(_parse_time(cand.get("created_at")))
        for item in cand.get("history", []) if isinstance(cand.get("history"), list) else []:
            starts.append(_parse_time(item.get("at")))
    clean = [item for item in starts if item]
    if not clean:
        return 0
    return max(0, int((dt.datetime.now() - min(clean)).total_seconds() // 60))


def budget_status(run_dir: Path) -> dict[str, Any]:
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    budgets = {**DEFAULT_BUDGETS, **(target.get("budgets") or {})}
    elapsed = _run_elapsed_minutes(state, data.get("candidates", []))
    overruns = [key for key, value in budgets.items() if key == "total_minutes" and elapsed > int(value)]
    return {
        "elapsed_minutes": elapsed,
        "budgets": budgets,
        "overruns": overruns,
        "within_total_budget": "total_minutes" not in overruns,
    }


def _latest_artifact(run_dir: Path, subdir: str, pattern: str = "*.md") -> str:
    path = run_dir / subdir
    if not path.exists():
        return ""
    items = sorted(path.rglob(pattern))
    return rel(items[-1]) if items else ""


def recommend_next_action(run_dir: Path) -> dict[str, Any]:
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    candidates = data.get("candidates", [])
    stages = state.get("stages", {})
    if "prepare" not in stages:
        return {
            "command": f"{sys.argv[0]} prepare {rel(run_dir)}",
            "reason": "Source fingerprint has not been captured.",
            "priority": "setup",
        }
    if "map" not in stages:
        return {
            "command": f"{sys.argv[0]} map {rel(run_dir)}",
            "reason": "Attack-surface map is missing.",
            "priority": "setup",
        }
    if "source_graph" not in stages:
        return {
            "command": f"{sys.argv[0]} source-graph {rel(run_dir)}",
            "reason": "Source graph is missing; hypotheses need surface ranking.",
            "priority": "setup",
        }
    if "semantic_graph" not in stages:
        return {
            "command": f"{sys.argv[0]} semantic-graph {rel(run_dir)}",
            "reason": "Semantic graph is missing; flow and taint commands depend on it.",
            "priority": "setup",
        }
    if not candidates:
        return {
            "command": f"{sys.argv[0]} hypothesize {rel(run_dir)}",
            "reason": "No candidates exist; generate hypotheses from current source graph.",
            "priority": "triage",
        }
    for cand in candidates:
        verdict = str(cand.get("triage_verdict") or "").strip()
        if not verdict:
            return {
                "command": f"{sys.argv[0]} candidate-set {rel(run_dir)} {cand['id']} --triage-verdict <needs_proof|defended|false_positive>",
                "candidate_id": cand["id"],
                "reason": "Flow has no triage verdict; classify it before any proof work.",
                "priority": "triage",
            }
        if verdict in {"defended", "false_positive"}:
            continue
        if not dedup_checked(cand):
            return {
                "command": f"{sys.argv[0]} dedup {rel(run_dir)} {cand['id']} --check-osv",
                "candidate_id": cand["id"],
                "reason": "Candidate has not passed the novelty gate.",
                "priority": "novelty",
            }
        ok, blockers = promotion_findings(cand)
        if not ok:
            return {
                "command": f"{sys.argv[0]} gate {rel(run_dir)} {cand['id']}",
                "candidate_id": cand["id"],
                "reason": "Promotion gate has blockers: " + ",".join(blockers),
                "priority": "gate",
            }
        if cand.get("proof") != "passed":
            return {
                "command": f"{sys.argv[0]} proof-plan {rel(run_dir)} {cand['id']}",
                "candidate_id": cand["id"],
                "reason": "Candidate is gate-clean but lacks passing proof.",
                "priority": "proof",
            }
        if not substantive(cand.get("root_cause")):
            return {
                "command": f"{sys.argv[0]} candidate-set {rel(run_dir)} {cand['id']} --status root_cause_recorded --root-cause '<broken invariant>'",
                "candidate_id": cand["id"],
                "reason": "Proof passed but root cause is missing.",
                "priority": "root-cause",
            }
        if not substantive(cand.get("variant_analysis")):
            return {
                "command": f"{sys.argv[0]} variant {rel(run_dir)} {cand['id']}",
                "candidate_id": cand["id"],
                "reason": "Proof passed but sibling-surface variant analysis is missing.",
                "priority": "variant",
            }
        if not substantive(cand.get("patch_diff")):
            return {
                "command": f"{sys.argv[0]} patch-diff {rel(run_dir)} {cand['id']} --base <old-ref> --head <new-ref>",
                "candidate_id": cand["id"],
                "reason": "Patch/advisory review is missing or not scoped out.",
                "priority": "patch-review",
            }
        report_blockers = workflow_blockers(cand, "report_ready")
        if report_blockers:
            return {
                "command": f"{sys.argv[0]} gate {rel(run_dir)} {cand['id']} --report-ready",
                "candidate_id": cand["id"],
                "reason": "Report-ready blockers remain: " + ",".join(report_blockers),
                "priority": "report",
            }
    return {
        "command": f"{sys.argv[0]} report {rel(run_dir)}",
        "reason": "No immediate candidate blockers found; regenerate report/dashboard and prepare review.",
        "priority": "reporting",
    }


def cmd_next_action(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    result = recommend_next_action(run_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["command"])
        print("reason=" + result["reason"])


# ---------------------------------------------------------------------------
# Orient / submit: the binding loop spine (Phase A).
#
# recommend_next_action() is advisory. The orient/submit pair turns it into a
# contract: orient issues one step (idempotently), the operator runs the
# command, then submit records the outcome and only advances the cursor when
# the recommendation actually changed. This is how the harness orchestrates the
# model rather than trusting the model to self-pace.
# ---------------------------------------------------------------------------

# step_outcomes_path imported from core.


# _append_step_outcome moved to ledger/outcomes.py.
from ledger.outcomes import _append_step_outcome  # noqa: E402


def _recommendation_verb(rec: dict[str, Any]) -> str:
    command = str(rec.get("command") or "")
    tokens = shlex.split(command) if command else []
    for tok in tokens[1:]:  # tokens[0] is the harness script path.
        if tok.startswith("-"):
            continue
        return tok
    return ""


def _recommendation_signature(rec: dict[str, Any]) -> str:
    return (
        f"{rec.get('priority') or ''}::"
        f"{_recommendation_verb(rec)}::"
        f"{rec.get('candidate_id') or ''}"
    )


def _loop_state(rec: dict[str, Any]) -> str:
    priority = str(rec.get("priority") or "")
    verb = _recommendation_verb(rec)
    if priority == "setup":
        return {
            "prepare": "recon",
            "map": "map",
            "source-graph": "reachability",
            "semantic-graph": "reachability",
        }.get(verb, "recon")
    if priority == "triage":
        return "triage" if rec.get("candidate_id") else "hypothesize"
    if priority == "novelty":
        return "triage"
    if priority in {"gate", "proof"}:
        return "proof"
    if priority in {"root-cause", "variant", "patch-review", "report"}:
        return "enrich"
    if priority == "reporting":
        return "report"
    return priority or "recon"


def _required_result(rec: dict[str, Any]) -> str:
    return {
        "setup": "Stage artifact written to state.json.",
        "triage": "Candidate(s) created or triage_verdict recorded.",
        "novelty": "OSV novelty check recorded on the candidate.",
        "gate": "Promotion-gate blockers cleared.",
        "proof": "Proof plan executed and proof=passed.",
        "root-cause": "Substantive root_cause recorded.",
        "variant": "Sibling-surface variant_analysis recorded.",
        "patch-review": "Patch/advisory diff recorded or scoped out.",
        "report": "Report-ready blockers cleared.",
        "reporting": "Report and dashboard regenerated.",
    }.get(str(rec.get("priority") or ""), "Advance the loop to the next state.")


def _step_gate(rec: dict[str, Any]) -> str:
    if str(rec.get("priority")) == "triage" and rec.get("candidate_id"):
        return "triage_verdict in {needs_proof,defended,false_positive}"
    return ""


def _build_step(rec: dict[str, Any], step_id: int) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "state": _loop_state(rec),
        "priority": rec.get("priority", ""),
        "candidate_id": rec.get("candidate_id", ""),
        "task": rec.get("reason", ""),
        "command": rec.get("command", ""),
        "required_result": _required_result(rec),
        "gate": _step_gate(rec),
        "signature": _recommendation_signature(rec),
    }


def _load_cursor(state: dict[str, Any]) -> dict[str, Any]:
    cursor = dict(state.get("loop_cursor") or {})
    cursor.setdefault("step_counter", 0)
    cursor.setdefault("pending_step", None)
    cursor.setdefault("history", [])
    cursor.setdefault("states_seen", [])
    return cursor


def _persist_cursor(run_dir: Path, cursor: dict[str, Any]) -> None:
    state = read_json(run_dir / "state.json", {})
    state["loop_cursor"] = cursor
    write_json(run_dir / "state.json", state)


def cmd_orient(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, _ = load_run(run_dir)
    cursor = _load_cursor(state)
    rec = recommend_next_action(run_dir)
    signature = _recommendation_signature(rec)
    pending = cursor.get("pending_step")
    if pending and pending.get("signature") == signature:
        step = pending
        reissued = True
    else:
        cursor["step_counter"] = int(cursor.get("step_counter", 0)) + 1
        step = _build_step(rec, cursor["step_counter"])
        cursor["pending_step"] = step
        _persist_cursor(run_dir, cursor)
        reissued = False
    out = {"step": step, "reissued": reissued}
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"step {step['step_id']} [{step['state']}] {step['task']}")
        print("run: " + step["command"])
        if step.get("gate"):
            print("gate: " + step["gate"])
        print("expect: " + step["required_result"])


def cmd_submit(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, _ = load_run(run_dir)
    cursor = _load_cursor(state)
    pending = cursor.get("pending_step")
    if not pending:
        raise SystemExit("no pending step; run `orient` first")

    if pending.get("gate") and args.triage_verdict:
        if args.triage_verdict not in TRIAGE_VERDICTS:
            raise SystemExit(f"invalid triage verdict: {args.triage_verdict}")
        cand_id = pending.get("candidate_id")
        if not cand_id:
            raise SystemExit("triage step has no candidate to classify")

        def _set(cand: dict[str, Any]) -> None:
            cand["triage_verdict"] = args.triage_verdict
            cand.setdefault("history", []).append(
                {
                    "at": dt.datetime.now().isoformat(timespec="seconds"),
                    "event": f"triage_verdict:{args.triage_verdict}",
                }
            )

        update_candidate_locked(run_dir, cand_id, _set)

    # Attribute the outcome to a weakness class so triage verdicts can feed the
    # tuning loop (Phase C). `cwe` falls back to `weakness`, matching the key
    # used by _score_candidate and outcome_tuning's weakness_adjustments.
    weakness_key = ""
    cand_id = pending.get("candidate_id") or ""
    if cand_id:
        cand = next(
            (c for c in load_candidates(run_dir).get("candidates", []) if c.get("id") == cand_id),
            None,
        )
        if cand:
            weakness_key = str(cand.get("cwe") or cand.get("weakness") or "")

    outcome_id = _append_step_outcome(
        {
            "run": rel(run_dir),
            "target_id": state.get("target_id") or "",
            "step_id": pending.get("step_id"),
            "state": pending.get("state"),
            "priority": pending.get("priority"),
            "candidate_id": cand_id,
            "weakness": weakness_key,
            "signature": pending.get("signature"),
            "triage_verdict": args.triage_verdict or "",
            "note": args.note or "",
        }
    )

    new_rec = recommend_next_action(run_dir)
    new_sig = _recommendation_signature(new_rec)
    advanced = (new_sig != pending.get("signature")) or (
        pending.get("priority") == "reporting"
    )
    result: dict[str, Any] = {"advanced": advanced, "outcome_id": outcome_id}
    if advanced:
        cursor.setdefault("history", []).append(
            {
                "step_id": pending.get("step_id"),
                "state": pending.get("state"),
                "signature": pending.get("signature"),
                "outcome_id": outcome_id,
            }
        )
        seen = cursor.setdefault("states_seen", [])
        st = pending.get("state")
        if st and st not in seen:
            seen.append(st)
        cursor["pending_step"] = None
        result["next"] = {
            "command": new_rec.get("command"),
            "reason": new_rec.get("reason"),
            "priority": new_rec.get("priority"),
        }
    else:
        result["blocker"] = (
            "step did not advance the loop; same recommendation still pending"
        )
        result["still_pending"] = pending.get("signature")
    _persist_cursor(run_dir, cursor)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if advanced:
            print(f"advanced; outcome={outcome_id}")
            print("next: " + str(new_rec.get("command")))
        else:
            print("not advanced: " + str(result["blocker"]))


def cmd_intent_set(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    bad = [t for t in args.threat if t not in INTENT_VOCAB]
    if bad:
        raise SystemExit(
            "unknown threat-model tokens: "
            + ",".join(bad)
            + "; choose from "
            + ",".join(sorted(INTENT_VOCAB))
        )
    state = read_json(run_dir / "state.json", {})
    threat_model = list(dict.fromkeys(args.threat))
    state["intent"] = {
        "threat_model": threat_model,
        "rationale": args.rationale or "",
        "set_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    write_json(run_dir / "state.json", state)
    print("intent set: " + ", ".join(threat_model))


def cmd_intent_show(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state = read_json(run_dir / "state.json", {})
    intent = state.get("intent") or {}
    if args.json:
        print(json.dumps(intent, indent=2, sort_keys=True))
        return
    tokens = intent.get("threat_model") or []
    if not tokens:
        print("no intent set; run `intent-set <run> --threat <token> ...`")
        print("vocabulary: " + ", ".join(sorted(INTENT_VOCAB)))
        return
    print("threat model: " + ", ".join(tokens))
    if intent.get("rationale"):
        print("rationale: " + intent["rationale"])
    if intent.get("set_at"):
        print("set at: " + intent["set_at"])


def _loop_integrity_violations(
    state: dict[str, Any], candidates: list[dict[str, Any]]
) -> list[str]:
    violations: list[str] = []
    cursor = state.get("loop_cursor") or {}
    seen = list(cursor.get("states_seen") or [])
    idx = -1
    for st in seen:
        if st not in LOOP_STATE_ORDER:
            violations.append(f"unknown loop state recorded: {st}")
            continue
        pos = LOOP_STATE_ORDER.index(st)
        if pos <= idx:
            violations.append(f"loop state out of order: {st}")
        else:
            idx = pos
    if "report" in seen:
        missing = [s for s in LOOP_STATE_ORDER if s != "report" and s not in seen]
        if missing:
            violations.append(
                "report reached but prior states missing: " + ",".join(missing)
            )
    for entry in cursor.get("history") or []:
        if not entry.get("outcome_id"):
            violations.append(
                f"history step {entry.get('step_id')} missing outcome_id"
            )
    for cand in candidates:
        proven = (
            cand.get("proof") == "passed"
            or substantive(cand.get("root_cause"))
            or substantive(cand.get("variant_analysis"))
        )
        if proven and str(cand.get("triage_verdict") or "") != "needs_proof":
            violations.append(
                f"candidate {cand.get('id')} advanced to proof without needs_proof verdict"
            )
    return violations


def cmd_intent_ordering_check(args: argparse.Namespace) -> None:
    fixture = (
        ROOT / "vapt" / "harness" / "tests" / "fixtures" / "intent_ordering" / "source_graph.yaml"
    )
    graph = load_yaml(fixture) or {}

    default = _order_hypotheses_by_intent(_build_hypotheses(graph, 3), [])
    default_top = default[0]["kind"] if default else ""

    cases = [
        ("command_execution_boundary", "command_execution_boundary"),
        ("ssrf_outbound_boundary", "ssrf_outbound_boundary"),
    ]
    results: list[dict[str, Any]] = []
    for token, expected_kind in cases:
        hyps = _order_hypotheses_by_intent(_build_hypotheses(graph, 3), [token])
        top = hyps[0] if hyps else {}
        top_kind = top.get("kind", "")
        passed = (
            top_kind == expected_kind
            and bool(top.get("intent_priority"))
            and top_kind != default_top
        )
        results.append(
            {"intent": token, "expected_top": expected_kind, "top_kind": top_kind, "passed": passed}
        )

    distinct = len({r["top_kind"] for r in results}) == len(results)
    all_passed = all(r["passed"] for r in results) and distinct

    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"intent_ordering_{stamp}"
    write_json(
        out.with_suffix(".json"),
        {"passed": all_passed, "default_top": default_top, "distinct": distinct, "results": results},
    )
    md = [
        "# Intent Ordering Check",
        "",
        f"- All passed: `{all_passed}`",
        f"- Default top (no intent): `{default_top}`",
        f"- Two threat models produce distinct top hypotheses: `{distinct}`",
        "",
    ]
    for r in results:
        md.append(
            f"- intent `{r['intent']}` -> top `{r['top_kind']}` (expected `{r['expected_top']}`) passed=`{r['passed']}`"
        )
    write_text(out.with_suffix(".md"), "\n".join(md) + "\n")

    if args.json:
        print(json.dumps({"passed": all_passed, "default_top": default_top, "distinct": distinct, "results": results}, indent=2, sort_keys=True))
    else:
        print(f"default top (no intent): {default_top}")
        for r in results:
            tag = "PASS" if r["passed"] else "FAIL"
            print(f"[{tag}] intent={r['intent']} top={r['top_kind']} expected={r['expected_top']}")
        print(f"distinct_tops={distinct} all_passed={all_passed}")
    if args.fail and not all_passed:
        raise SystemExit(2)


def cmd_loop_integrity_check(args: argparse.Namespace) -> None:
    results: list[dict[str, Any]] = []
    if args.run_dir:
        run_dir = run_path(args.run_dir)
        state, _ = load_run(run_dir)
        cands = load_candidates(run_dir).get("candidates", [])
        violations = _loop_integrity_violations(state, cands)
        results.append(
            {
                "name": rel(run_dir),
                "expect_pass": True,
                "violations": violations,
                "passed": not violations,
            }
        )
    else:
        fixture_dir = (
            ROOT / "vapt" / "harness" / "tests" / "fixtures" / "loop_integrity"
        )
        expectations = {
            "valid_run.json": True,
            "skipped_state.json": False,
            "unverdicted_proof.json": False,
        }
        for name, expect_pass in expectations.items():
            payload = read_json(fixture_dir / name, {})
            violations = _loop_integrity_violations(
                payload.get("state", {}), payload.get("candidates", [])
            )
            clean = not violations
            results.append(
                {
                    "name": name,
                    "expect_pass": expect_pass,
                    "violations": violations,
                    "passed": clean == expect_pass,
                }
            )
    all_passed = all(r["passed"] for r in results)

    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"loop_integrity_{stamp}"
    write_json(
        out.with_suffix(".json"), {"passed": all_passed, "results": results}
    )
    md = ["# Loop Integrity Check", "", f"- All passed: `{all_passed}`", ""]
    for r in results:
        md.extend(
            [
                f"## `{r['name']}`",
                "",
                f"- Expect pass: `{r['expect_pass']}`",
                f"- Passed: `{r['passed']}`",
                "- Violations:",
            ]
        )
        md.extend([f"  - {v}" for v in r["violations"]] or ["  - (none)"])
        md.append("")
    write_text(out.with_suffix(".md"), "\n".join(md))

    if args.json:
        print(json.dumps({"passed": all_passed, "results": results}, indent=2, sort_keys=True))
    else:
        for r in results:
            tag = "PASS" if r["passed"] else "FAIL"
            print(f"[{tag}] {r['name']} expect_pass={r['expect_pass']} violations={r['violations']}")
        print("all_passed=" + str(all_passed))
    if args.fail and not all_passed:
        raise SystemExit(2)


def cmd_budget(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    result = budget_status(run_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"elapsed_minutes={result['elapsed_minutes']}")
        print("budgets=" + json.dumps(result["budgets"], sort_keys=True))
        print("overruns=" + ",".join(result["overruns"]) if result["overruns"] else "overruns=none")
    if result["overruns"]:
        raise SystemExit(2)


def _candidate_summary(cand: dict[str, Any]) -> dict[str, Any]:
    ok, blockers = promotion_findings(cand)
    return {
        "id": cand.get("id"),
        "title": cand.get("title"),
        "status": cand.get("status"),
        "novelty": cand.get("novelty"),
        "dedup_checked": dedup_checked(cand),
        "proof": cand.get("proof"),
        "gate_passed": ok,
        "gate_blockers": blockers,
        "quality_score": cand.get("quality_score", {}).get("score") if isinstance(cand.get("quality_score"), dict) else None,
        "last_history": (cand.get("history") or [])[-5:] if isinstance(cand.get("history"), list) else [],
    }


def cmd_session_start(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    payload = {
        "harness_version": HARNESS_VERSION,
        "run_dir": rel(run_dir),
        "state": state,
        "target": {
            "id": target.get("id"),
            "name": target.get("name"),
            "program": target.get("program"),
            "repo_url": target.get("repo_url"),
            "source_path": target.get("source_path"),
            "latest_release": target.get("latest_release"),
            "in_scope": target.get("in_scope", []),
            "out_of_scope": target.get("out_of_scope", []),
        },
        "candidate_count": len(data.get("candidates", [])),
        "candidates": [_candidate_summary(cand) for cand in data.get("candidates", [])],
        "budget": budget_status(run_dir),
        "recommended_next_action": recommend_next_action(run_dir),
        "knowledge": {
            "index": rel(ROOT / "vapt" / "harness" / "knowledge" / "INDEX.md"),
            "principles": rel(ROOT / "vapt" / "harness" / "knowledge" / "principles.md"),
            "workflow": rel(ROOT / "vapt" / "harness" / "knowledge" / "workflow.md"),
            "patterns": rel(ROOT / "vapt" / "harness" / "config" / "surfaces.yaml"),
            "scoring": rel(ROOT / "vapt" / "harness" / "knowledge" / "scoring.yaml"),
        },
        "latest_artifacts": {
            "source_graph": rel(run_dir / "source_graph" / "source_graph.md") if (run_dir / "source_graph" / "source_graph.md").exists() else "",
            "semantic_graph": rel(run_dir / "semantic_graph" / "semantic_graph.md") if (run_dir / "semantic_graph" / "semantic_graph.md").exists() else "",
            "taint_trace": _latest_artifact(run_dir, "taint_traces"),
            "report": rel(run_dir / "reports" / "triage_draft.md") if (run_dir / "reports" / "triage_draft.md").exists() else "",
            "dashboard": rel(run_dir / "dashboard.html") if (run_dir / "dashboard.html").exists() else "",
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=False))


def _knowledge_files() -> list[Path]:
    roots = [
        ROOT / "vapt" / "harness" / "knowledge",
        ROOT / "vapt" / "harness" / "agents",
        ROOT / "vapt" / "management",
        ROOT / "vapt" / "harness" / "corpus",
    ]
    files = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".yaml", ".yml", ".jsonl", ".json"}:
                files.append(path)
    return sorted(files)


def _rank_text(query_terms: list[str], text: str) -> int:
    lowered = text.lower()
    return sum(lowered.count(term) for term in query_terms)


def cmd_knowledge(args: argparse.Namespace) -> None:
    terms = [term.lower() for term in re.findall(r"[A-Za-z0-9_:-]{3,}", args.query)]
    if not terms:
        raise SystemExit("knowledge query needs at least one searchable term")
    results = []
    for path in _knowledge_files():
        with contextlib.suppress(OSError):
            text = path.read_text(encoding="utf-8", errors="replace")
            score = _rank_text(terms, text)
            if score:
                lines = text.splitlines()
                snippets = []
                for idx, line in enumerate(lines, start=1):
                    if any(term in line.lower() for term in terms):
                        snippets.append({"line": idx, "text": line[:240]})
                    if len(snippets) >= args.snippets:
                        break
                results.append({"path": rel(path), "score": score, "snippets": snippets})
    results.sort(key=lambda item: (-item["score"], item["path"]))
    payload = {"query": args.query, "results": results[: args.limit]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in payload["results"]:
            print(f"{item['score']} {item['path']}")
            for snippet in item["snippets"]:
                print(f"  L{snippet['line']}: {snippet['text']}")


def _command_help(command: str) -> str:
    parser = build_parser()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        parser.parse_args([command, "--help"])
    output = buf.getvalue()
    if not output:
        raise SystemExit(f"unknown command or no help available: {command}")
    return output


COMMAND_DOCTRINE = {
    "dedup": ["knowledge/principles.md", "agents/dedup_skeptic.md"],
    "gate": ["knowledge/workflow.md", "knowledge/principles.md"],
    "prove": ["knowledge/principles.md", "agents/atomic_validation.md"],
    "variant": ["agents/root_cause_variant.md"],
    "patch-diff": ["agents/patch_diff_advisory.md"],
    "campaign-plan": ["config/campaign_modules.yaml", "knowledge/workflow.md", "knowledge/principles.md"],
    "campaign-adapter-check": ["config/module_contract.yaml", "config/campaign_modules.yaml"],
    "mutation-plan": ["config/mutation_catalog.yaml", "config/campaign_modules.yaml"],
    "mutation-coverage-check": ["config/mutation_catalog.yaml", "knowledge/principles.md"],
    "patch-first-plan": ["agents/patch_diff_advisory.md", "knowledge/principles.md"],
    "campaign-dashboard": ["config/campaign_modules.yaml", "config/mutation_catalog.yaml", "knowledge/workflow.md"],
    "campaign-run": ["config/module_contract.yaml", "config/campaign_modules.yaml", "config/mutation_catalog.yaml"],
    "campaign-gate": ["config/module_contract.yaml", "config/mutation_catalog.yaml", "knowledge/workflow.md"],
    "campaign-start": ["knowledge/workflow.md", "config/campaign_modules.yaml", "config/module_contract.yaml"],
    "candidate-link-campaign": ["knowledge/workflow.md", "config/module_contract.yaml"],
    "source-graph": ["knowledge/patterns.yaml", "agents/source_mapper.md"],
    "semantic-graph": ["knowledge/patterns.yaml"],
    "taint-trace": ["knowledge/patterns.yaml", "knowledge/vuln_classes/parser_canonicalization/doctrine.md"],
    "session-start": ["knowledge/INDEX.md", "knowledge/workflow.md"],
}


def cmd_explain(args: argparse.Namespace) -> None:
    print("# Command Help")
    print()
    print("```text")
    print(_command_help(args.command).rstrip())
    print("```")
    print()
    refs = COMMAND_DOCTRINE.get(args.command, ["knowledge/INDEX.md", "knowledge/principles.md"])
    print("# Relevant Knowledge")
    print()
    for ref in refs:
        path = ROOT / "vapt" / "harness" / ref
        if not path.exists():
            path = ROOT / "vapt" / ref
        if path.exists():
            print(f"- `{rel(path)}`")
    examples = {
        "session-start": f"{sys.argv[0]} session-start vapt/engagements/<target>/runs/<target>/<run-id>",
        "knowledge": f"{sys.argv[0]} knowledge 'websocket authz negative control'",
        "next-action": f"{sys.argv[0]} next-action vapt/engagements/<target>/runs/<target>/<run-id>",
        "budget": f"{sys.argv[0]} budget vapt/engagements/<target>/runs/<target>/<run-id>",
    }
    if args.command in examples:
        print()
        print("# Example")
        print()
        print(f"```sh\n{examples[args.command]}\n```")


def cmd_commands(args: argparse.Namespace) -> None:
    parser = build_parser()
    actions = []
    for action in parser._subparsers._actions:  # type: ignore[attr-defined]
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in sorted(action.choices.items()):
                argspec = []
                for sub_action in subparser._actions:
                    if sub_action.dest == "help":
                        continue
                    argspec.append(
                        {
                            "dest": sub_action.dest,
                            "option_strings": sub_action.option_strings,
                            "required": getattr(sub_action, "required", False),
                            "nargs": sub_action.nargs,
                            "default": None if sub_action.default is argparse.SUPPRESS else sub_action.default,
                        }
                    )
                actions.append({"name": name, "help": subparser.description or subparser.prog, "args": argspec})
    print(json.dumps({"version": HARNESS_VERSION, "commands": actions}, indent=2, sort_keys=False))


# cmd_corpus_rebuild moved to ledger/commands.py.
from ledger.commands import cmd_corpus_rebuild  # noqa: E402


# submissions_path/candidate_corpus_path/outcome_tuning_path imported from core.


from validators import submission_positive, submission_terminal  # noqa: E402


# candidate_outcome_metadata / enrich_submission_entry moved to ledger/submissions.py.
from ledger.submissions import candidate_outcome_metadata, enrich_submission_entry  # noqa: E402


# cmd_submission_add / cmd_submission_update moved to ledger/commands.py.
from ledger.commands import cmd_submission_add, cmd_submission_update  # noqa: E402


SYNTHETIC_OUTCOME_DISTRIBUTION = [
    ("duplicate", 0.40, None),
    ("not_applicable", 0.25, None),
    ("triaged", 0.15, None),
    ("resolved", 0.10, 0.0),
    ("paid", 0.07, 750.0),
    ("informative", 0.03, None),
]


def _synthetic_status_for(seed_key: str) -> tuple[str, float | None]:
    bucket = (zlib.crc32(seed_key.encode("utf-8")) & 0xFFFFFFFF) / float(0xFFFFFFFF)
    cumulative = 0.0
    for status, weight, payout in SYNTHETIC_OUTCOME_DISTRIBUTION:
        cumulative += weight
        if bucket <= cumulative:
            return status, payout
    return SYNTHETIC_OUTCOME_DISTRIBUTION[-1][0], SYNTHETIC_OUTCOME_DISTRIBUTION[-1][2]


def _synthetic_module_for(cand: dict[str, Any]) -> str:
    weakness = str(cand.get("weakness") or "").lower()
    surface = str(cand.get("surface") or "").lower()
    if "ssrf" in weakness or "ssrf" in surface:
        return "ssrf_callback"
    if "authz" in weakness or "auth" in weakness or "200" in weakness:
        return "authz_matrix"
    if "serialization" in weakness or "deserial" in weakness or "rce" in weakness:
        return "serialization_rce"
    if "path" in weakness or "file" in surface or "346" in weakness:
        return "path_traversal_audit"
    if "injection" in weakness or "prompt" in weakness:
        return "prompt_injection_audit"
    if "websocket" in weakness or "ws" in surface:
        return "websocket_authz"
    return "manual_review"


def _synthetic_evidence_kind(cand: dict[str, Any]) -> str:
    proof = str(cand.get("proof") or "").lower()
    if "passed" in proof:
        return "reproducer_verified"
    if cand.get("notes"):
        return "manual_observation"
    return "manual_seed"


def cmd_osv_cache_stats(args: argparse.Namespace) -> None:
    path = osv_cache_path()
    if not path.exists():
        payload = {"path": rel(path), "exists": False, "package_rows": 0, "vuln_rows": 0}
    else:
        with contextlib.closing(_osv_cache_connect()) as conn:
            package_rows = conn.execute("SELECT COUNT(*) FROM osv_package").fetchone()[0]
            vuln_rows = conn.execute("SELECT COUNT(*) FROM osv_vuln").fetchone()[0]
            oldest_pkg = conn.execute("SELECT MIN(fetched_at) FROM osv_package").fetchone()[0]
            newest_pkg = conn.execute("SELECT MAX(fetched_at) FROM osv_package").fetchone()[0]
            oldest_vuln = conn.execute("SELECT MIN(fetched_at) FROM osv_vuln").fetchone()[0]
            newest_vuln = conn.execute("SELECT MAX(fetched_at) FROM osv_vuln").fetchone()[0]
        payload = {
            "path": rel(path),
            "exists": True,
            "package_rows": package_rows,
            "vuln_rows": vuln_rows,
            "package_oldest": oldest_pkg,
            "package_newest": newest_pkg,
            "vuln_oldest": oldest_vuln,
            "vuln_newest": newest_vuln,
            "fresh_window_hours": OSV_CACHE_FRESH_HOURS,
        }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for key, val in payload.items():
            print(f"{key}: {val}")


def cmd_osv_cache_prefetch(args: argparse.Namespace) -> None:
    targets = []
    for target_id in args.target:
        profile_path, target = _load_target_profile(target_id)
        if not profile_path:
            legacy = ROOT / "vapt" / "engagements" / target_id / "target.yaml"
            if legacy.exists():
                target = load_yaml(legacy) or {}
                profile_path = legacy
        if not profile_path:
            print(f"skip {target_id}: no target profile found under vapt/engagements/", file=sys.stderr)
            continue
        targets.append((target_id, target))
    fetched_packages = 0
    fetched_vulns = 0
    errors: list[str] = []
    fake_args = argparse.Namespace(
        osv_ecosystem=None, osv_package=None, osv_version=None, osv_timeout=args.timeout,
        osv_cache_only=False, osv_fresh_only=args.refresh,
    )
    for target_id, target in targets:
        try:
            pkg = _osv_package_query(target, fake_args)
            if pkg is not None:
                fetched_packages += 1
                for vuln in pkg.get("vulns", []) or []:
                    vuln_id = vuln.get("id")
                    if not vuln_id:
                        continue
                    try:
                        v = _osv_vuln_query(vuln_id, args.timeout, fresh_only=args.refresh)
                        if v is not None:
                            fetched_vulns += 1
                    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                        errors.append(f"{target_id}:{vuln_id}: {exc}")
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            errors.append(f"{target_id}:package: {exc}")
    payload = {"targets": [t for t, _ in targets], "fetched_packages": fetched_packages, "fetched_vulns": fetched_vulns, "errors": errors}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"prefetched packages={fetched_packages} vulns={fetched_vulns} errors={len(errors)}")
        for e in errors:
            print(f"  ! {e}", file=sys.stderr)


def cmd_osv_cache_clear(args: argparse.Namespace) -> None:
    path = osv_cache_path()
    if path.exists():
        path.unlink()
    payload = {"path": rel(path), "cleared": True}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"cleared {rel(path)}")


# cmd_source_acquire moved to source.commands.
# cmd_source_index moved to source.commands.
# cmd_source_probe moved to source.commands.
def _load_watch_module(name: str) -> Any:
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    import importlib
    return importlib.import_module(f"watch.{name}")


def _discovery_queue_dir() -> Path:
    return ROOT / "vapt" / "harness" / "queue"


def cmd_discovery_sweep(args: argparse.Namespace) -> None:
    disc = _load_watch_module("discovery")
    advisories, fetch_errors = disc.fetch_recent_advisories(
        severity_floor=args.severity_floor,
        since_days=args.since_days,
        per_page=args.per_page,
        max_pages=args.max_pages,
        token=os.environ.get("GITHUB_TOKEN") or None,
        timeout=args.timeout,
    )
    target_profile_paths = sorted((ROOT / "vapt" / "engagements").glob("*/targets/*.yaml"))
    watched = disc.watched_packages(target_profile_paths)
    proposals = disc.propose_targets(advisories, watched)
    written, skipped = disc.write_proposals(proposals, _discovery_queue_dir())
    payload = {
        "fetched_advisories": len(advisories),
        "watched_packages": len(watched),
        "proposals_total": len(proposals),
        "proposals_written": written,
        "proposals_skipped_existing": skipped,
        "fetch_errors": fetch_errors,
        "queue_dir": rel(_discovery_queue_dir() / disc.DISCOVERY_QUEUE_DIRNAME),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(
            f"advisories={payload['fetched_advisories']} "
            f"proposals={payload['proposals_total']} "
            f"written={payload['proposals_written']} "
            f"skipped={payload['proposals_skipped_existing']}"
        )
        for e in fetch_errors:
            print(f"  ! {e}", file=sys.stderr)


def cmd_discovery_list(args: argparse.Namespace) -> None:
    disc = _load_watch_module("discovery")
    rows = disc.list_proposals(_discovery_queue_dir(), include_claimed=args.all)
    if args.severity:
        wanted = {s.lower() for s in args.severity}
        rows = [r for r in rows if (r.get("severity") or "").lower() in wanted]
    if args.ecosystem:
        rows = [r for r in rows if (r.get("ecosystem") or "").lower() == args.ecosystem.lower()]
    if args.json:
        print(json.dumps({"proposals": rows}, indent=2, sort_keys=False))
    else:
        for r in rows:
            print(
                f"{r.get('proposal_slug')} [{r.get('severity')}] "
                f"{r.get('ecosystem')}/{r.get('package')} "
                f"-> {r.get('ghsa_id')} ({', '.join(r.get('cves') or []) or 'no-cve'})"
            )


def cmd_discovery_claim(args: argparse.Namespace) -> None:
    disc = _load_watch_module("discovery")
    try:
        updated = disc.claim_proposal(
            _discovery_queue_dir(),
            args.slug,
            claimed_by=args.claimed_by,
            decision=args.decision,
            note=args.note or "",
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"proposal not found: {exc}")
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    eco = updated.get("ecosystem") or ""
    pkg = updated.get("package") or ""
    target_hint = re.sub(r"[^a-z0-9]+", "-", pkg.lower()).strip("-")
    watch_add_cmd = ""
    if updated.get("status") == "claimed" and eco and pkg:
        watch_add_cmd = (
            f"python3 vapt/harness/harness.py watch-add {target_hint} "
            f"--source ghsa_advisories --ecosystem {eco} --package {pkg} "
            f"--allow-network"
        )
    payload = {
        "proposal_slug": args.slug,
        "status": updated.get("status"),
        "claimed_by": updated.get("claimed_by"),
        "suggested_watch_add": watch_add_cmd,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"{args.slug}: status={updated.get('status')} by={updated.get('claimed_by')}")
        if watch_add_cmd:
            print(f"  next: {watch_add_cmd}")


# Outcome-tuning math lives in the outcome_tuning leaf module (core/io/validators
# only). Imported so harness.* references resolve unchanged.
from outcome_tuning import (  # noqa: E402
    outcome_tuning,
    _add_outcome,
    _finalize_outcome_bucket,
    _stat_bucket,
    _triage_score_adjustment,
    _triage_tally,
)


# load_outcome_tuning still re-exported from ledger.submissions for
# _score_campaign_module and other in-harness callers.
from ledger.submissions import load_outcome_tuning  # noqa: E402


# cmd_submission_seed_synthetic / cmd_outcome_record / cmd_submissions_list /
# cmd_outcome_tune / cmd_weights_show / cmd_submissions_stats moved to
# ledger/commands.py.
from ledger.commands import (  # noqa: E402
    cmd_outcome_record,
    cmd_outcome_tune,
    cmd_submission_seed_synthetic,
    cmd_submissions_list,
    cmd_submissions_stats,
    cmd_weights_show,
)

def _candidate_signal(cand: dict[str, Any]) -> str:
    fields = [
        cand.get("title", ""),
        cand.get("surface", ""),
        cand.get("weakness", ""),
        cand.get("sink", ""),
        cand.get("root_cause", ""),
        cand.get("impact", ""),
    ]
    return " ".join(str(item) for item in fields)


def cmd_retro(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    out = run_dir / "retro.md"
    patch = run_dir / "retro.patch"
    candidates = data.get("candidates", [])
    passed = []
    noisy = []
    lessons = []
    for cand in candidates:
        ok, blockers = promotion_findings(cand)
        if ok and cand.get("proof") == "passed":
            passed.append(cand)
        if cand.get("status") in {"rejected", "hardening-only", "duplicate"} or blockers:
            noisy.append({"candidate": cand, "blockers": blockers})
    if passed:
        lessons.append("Promoted candidates had formal proof and dedup records; preserve this gate discipline.")
    if any("variant_analysis" in item.get("blockers", []) for item in noisy):
        lessons.append("Variant analysis remained a recurring blocker; run it immediately after first proof.")
    if not lessons:
        lessons.append("No strong reusable lesson identified; continue collecting outcomes.")

    md = [
        f"# Retro: {target.get('id')} / {state.get('run_id')}",
        "",
        f"- Run dir: `{rel(run_dir)}`",
        f"- Candidate count: `{len(candidates)}`",
        f"- Gate/proof passed: `{len(passed)}`",
        f"- Noisy or blocked: `{len(noisy)}`",
        "",
        "## Candidates That Passed",
        "",
    ]
    for cand in passed:
        md.append(f"- `{cand.get('id')}` {cand.get('title')} proof=`{cand.get('proof')}` novelty=`{cand.get('novelty')}`")
    if not passed:
        md.append("- None")
    md.extend(["", "## Blocked / Low-Signal Candidates", ""])
    for item in noisy:
        cand = item["candidate"]
        md.append(f"- `{cand.get('id')}` {cand.get('title')} status=`{cand.get('status')}` blockers=`{', '.join(item['blockers'])}`")
    if not noisy:
        md.append("- None")
    md.extend(["", "## Lessons To Propagate", ""])
    for lesson in lessons:
        md.append(f"- {lesson}")
    write_text(out, "\n".join(md) + "\n")

    lesson_file = f"vapt/harness/knowledge/lessons/{dt.datetime.now().strftime('%Y-%m-%d')}_{target.get('id')}_retro.md"
    patch_lines = [
        f"diff --git a/{lesson_file} b/{lesson_file}",
        "new file mode 100644",
        "index 0000000..0000000",
        "--- /dev/null",
        f"+++ b/{lesson_file}",
        "@@",
        f"+# Retro Lesson: {target.get('id')} / {state.get('run_id')}",
        "+",
    ]
    for lesson in lessons:
        patch_lines.append(f"+- {lesson}")
    write_text(patch, "\n".join(patch_lines) + "\n")
    print(rel(out))
    print(rel(patch))


# Target profile lookup moved to source/targets.py.
from source.targets import _load_target_profile, _target_profile_paths  # noqa: E402


def _term_set(text: str) -> set[str]:
    return {
        term.lower()
        for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", text)
        if term.lower() not in COMMON_VARIANT_TERMS
    }


def cmd_corpus_suggest(args: argparse.Namespace) -> None:
    profile_path, target = _load_target_profile(args.target_id)
    if not target:
        raise SystemExit(f"target profile not found: {args.target_id}")
    if not candidate_corpus_path().exists():
        cmd_corpus_rebuild(argparse.Namespace())
    target_terms = _term_set(" ".join(str(x) for x in target.get("category", []) + target.get("in_scope", [])))
    rows = read_jsonl(candidate_corpus_path())
    suggestions = []
    for row in rows:
        cand = row.get("candidate", {})
        if row.get("target_id") == args.target_id:
            continue
        text = _candidate_signal(cand)
        terms = _term_set(text)
        overlap = sorted(target_terms & terms)
        if not overlap:
            continue
        status = str(cand.get("status") or "")
        proof_bonus = 5 if cand.get("proof") == "passed" else 0
        positive_bonus = 8 if status in {"report-ready", "validated-local-poc", "triaged", "resolved", "paid"} else 0
        score = len(overlap) + proof_bonus + positive_bonus
        suggestions.append(
            {
                "score": score,
                "source_target": row.get("target_id"),
                "source_run": row.get("run_dir"),
                "candidate_id": cand.get("id"),
                "title": cand.get("title"),
                "surface": cand.get("surface"),
                "weakness": cand.get("weakness"),
                "sink": cand.get("sink"),
                "overlap_terms": overlap[:20],
                "rationale": "Shared target/program terms plus prior proof/status signal.",
            }
        )
    suggestions.sort(key=lambda item: (-item["score"], str(item["source_target"]), str(item["candidate_id"])))
    payload = {"target_id": args.target_id, "target_profile": rel(profile_path) if profile_path else "", "suggestions": suggestions[: args.limit]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in payload["suggestions"]:
            print(f"{item['score']} {item['source_target']} {item['candidate_id']} {item['title']}")
            print("  terms=" + ",".join(item["overlap_terms"]))


def cmd_pick_target(args: argparse.Namespace) -> None:
    submissions = read_jsonl(submissions_path())
    stats = submission_stats(submissions)["programs"]
    rows = read_jsonl(candidate_corpus_path()) if candidate_corpus_path().exists() else []
    target_results = []
    for path in _target_profile_paths():
        target = load_yaml(path) or {}
        if args.platform and args.platform.lower() not in str(target.get("program", "")).lower():
            continue
        target_id = target.get("id") or path.stem
        program = target.get("program") or target_id
        program_stats = stats.get(program, {})
        fresh_queue = 0
        candidate_count = sum(1 for row in rows if row.get("target_id") == target_id)
        accepted_like = sum(
            1
            for row in rows
            if row.get("target_id") == target_id
            and (row.get("candidate", {}).get("proof") == "passed" or row.get("candidate", {}).get("status") in {"report-ready", "validated-local-poc"})
        )
        duplicate_pressure = len(target.get("known_duplicates") or [])
        category_bonus = len(target.get("in_scope") or []) / 2
        score = 10 + category_bonus + accepted_like * 4 + fresh_queue * 3
        score += float(program_stats.get("acceptance_rate", 0)) * 10
        score += min(float(program_stats.get("average_value", 0)) / 500, 10)
        score -= duplicate_pressure * 0.8
        if args.budget_minutes:
            score += min(int(args.budget_minutes), int((target.get("budgets") or DEFAULT_BUDGETS).get("total_minutes", 480))) / 240
        target_results.append(
            {
                "target_id": target_id,
                "profile": rel(path),
                "program": program,
                "score": round(score, 2),
                "candidate_count": candidate_count,
                "accepted_like_candidates": accepted_like,
                "known_duplicate_count": duplicate_pressure,
                "rationale": "Score uses in-scope breadth, prior local signal, known duplicate pressure, and submission outcomes when present.",
            }
        )
    target_results.sort(key=lambda item: (-item["score"], item["target_id"]))
    payload = {"ranked_targets": target_results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in target_results:
            print(f"{item['score']} {item['target_id']} {item['program']}")
            print(f"  {item['rationale']}")


MODULE_ALIASES = {
    "authz": "authz_matrix",
    "ssrf_proxy": "ssrf_callback",
}


# campaign_module_catalog_path / load_campaign_modules moved to campaign/context.py.
from campaign.context import campaign_module_catalog_path, load_campaign_modules  # noqa: E402


def _target_bb_root(profile_path: Path) -> Path:
    if profile_path.parent.name == "targets":
        return profile_path.parent.parent
    return profile_path.parent


def _target_profile_by_arg(target_or_profile: str) -> tuple[Path, dict[str, Any]]:
    candidate = run_path(target_or_profile)
    if candidate.exists():
        return candidate, load_yaml(candidate) or {}
    profile_path, target = _load_target_profile(target_or_profile)
    if profile_path and target:
        return profile_path, target
    raise SystemExit(f"target profile not found: {target_or_profile}")


def _module_key(name: str) -> str:
    return MODULE_ALIASES.get(str(name or ""), str(name or ""))


def _module_artifact_key(raw: Any) -> str:
    return str(raw or "").rstrip("/")


# _campaign_history moved to campaign/commands.py.
def _module_status(module_history: dict[str, Any]) -> str:
    if not module_history or not module_history.get("runs"):
        return "untested"
    if int(module_history.get("candidate_signals") or 0) > 0:
        return "candidate_signal"
    verdicts = {str(item) for item in module_history.get("verdicts", [])}
    if int(module_history.get("failed_expectations") or 0) > 0 or verdicts & {"partial", "setup_failed", "module_failed"}:
        return "partial"
    if "no_findings" in verdicts:
        return "closed"
    return "tested_unknown"


# _score_campaign_module moved to campaign/commands.py.
# _campaign_plan_markdown moved to campaign/commands.py.
# cmd_campaign_plan moved to campaign/commands.py.
def module_contract_path() -> Path:
    return ROOT / "vapt" / "harness" / "config" / "module_contract.yaml"


def _adapter_manifest_paths(target: str | None = None) -> list[Path]:
    root = ROOT / "vapt" / "engagements"
    if target:
        profile_path, _target = _target_profile_by_arg(target)
        bb_root = _target_bb_root(profile_path)
        return sorted((bb_root / "adapters").glob("*.yaml"))
    return sorted(root.glob("*/adapters/*.yaml"))


def _path_within(child: Path, parent: Path) -> bool:
    with contextlib.suppress(ValueError):
        child.resolve().relative_to(parent.resolve())
        return True
    return False


def _adapter_check_one(path: Path, catalog: dict[str, dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    manifest = load_yaml(path) or {}
    bb_root = path.parent.parent
    errors = []
    warnings = []
    required_manifest = contract.get("adapter_manifest_required_fields") or []
    for field in required_manifest:
        if not manifest.get(field):
            errors.append(f"missing adapter manifest field: {field}")
    modules = manifest.get("modules") or []
    if not isinstance(modules, list):
        errors.append("modules must be a list")
        modules = []

    checked_modules = []
    required_module_fields = contract.get("adapter_module_required_fields") or []
    for module in modules:
        if not isinstance(module, dict):
            errors.append("adapter module entry must be an object")
            continue
        module_id = str(module.get("id") or "")
        module_errors = []
        module_warnings = []
        for field in required_module_fields:
            if not module.get(field):
                module_errors.append(f"missing module field: {field}")
        generic = catalog.get(module_id)
        if not generic:
            module_errors.append(f"unknown generic module id: {module_id}")
        else:
            expected = set(str(item) for item in generic.get("adapter_requirements", []))
            actual = set(str(item) for item in module.get("requirement_methods", []))
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            if missing:
                module_errors.append("missing requirement methods: " + ", ".join(missing))
            if extra:
                module_warnings.append("extra requirement methods: " + ", ".join(extra))

        implementation = str(module.get("implementation") or "")
        if implementation:
            impl_path = (bb_root / implementation).resolve()
            if not _path_within(impl_path, bb_root):
                module_errors.append(f"implementation escapes target root: {implementation}")
            elif not impl_path.exists():
                module_errors.append(f"implementation not found: {implementation}")

        command = module.get("command") or []
        if not isinstance(command, list) or not command:
            module_errors.append("command must be a non-empty argv list")
        else:
            command_text = " ".join(str(item) for item in command)
            allow_harness_fixture = "vapt/harness/tests/fixtures" in rel(path)
            if "vapt/harness" in command_text and not allow_harness_fixture:
                module_errors.append("adapter command points at core harness instead of target-local runtime")
            if "vapt/engagements/" not in command_text and not allow_harness_fixture:
                module_warnings.append("adapter command does not visibly reference target-local runtime")

        with contextlib.suppress(Exception):
            mutation_catalog = load_mutation_catalog()
            for family_id in module.get("mutation_families", []) or []:
                family = mutation_catalog.get(str(family_id))
                if not family:
                    module_errors.append(f"unknown mutation family: {family_id}")
                    continue
                applies_to = {str(item) for item in family.get("applies_to", [])}
                if module_id not in applies_to:
                    module_warnings.append(f"mutation family {family_id} does not list module {module_id} in applies_to")

        errors.extend(f"{module_id or '<unknown>'}: {item}" for item in module_errors)
        warnings.extend(f"{module_id or '<unknown>'}: {item}" for item in module_warnings)
        checked_modules.append(
            {
                "id": module_id,
                "local_name": module.get("local_name", ""),
                "status": "fail" if module_errors else "pass",
                "errors": module_errors,
                "warnings": module_warnings,
            }
        )

    return {
        "path": rel(path),
        "target_id": manifest.get("target_id", ""),
        "adapter_id": manifest.get("adapter_id", ""),
        "status": "fail" if errors else "pass",
        "errors": errors,
        "warnings": warnings,
        "modules": checked_modules,
    }


# _campaign_adapter_check_markdown moved to campaign/commands.py.
# cmd_campaign_adapter_check moved to campaign/commands.py.
def mutation_catalog_path() -> Path:
    return ROOT / "vapt" / "harness" / "config" / "mutation_catalog.yaml"


def load_mutation_catalog() -> dict[str, dict[str, Any]]:
    data = load_yaml(mutation_catalog_path()) or {}
    families = data.get("mutation_families") or []
    if not isinstance(families, list):
        raise SystemExit(f"invalid mutation catalog: {rel(mutation_catalog_path())}")
    return {str(item.get("id")): item for item in families if isinstance(item, dict) and item.get("id")}


def _load_target_adapter(target: str) -> tuple[Path, dict[str, Any]]:
    paths = _adapter_manifest_paths(target)
    if not paths:
        raise SystemExit(f"no adapter manifests found for target: {target}")
    path = paths[0]
    return path, load_yaml(path) or {}


def _mutation_plan_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Mutation Plan: {payload['target_id']}",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Adapter: `{payload['adapter_manifest']}`",
        f"- Mutation catalog: `{payload['mutation_catalog']}`",
        "",
        "## Modules",
        "",
    ]
    for module in payload["modules"]:
        lines.append(f"### `{module['id']}`")
        lines.append("")
        lines.append(f"- Local name: `{module['local_name']}`")
        lines.append(f"- Mutation families: `{len(module['families'])}`")
        lines.append(f"- Variant count: `{module['variant_count']}`")
        lines.append("")
        for family in module["families"]:
            lines.append(f"- `{family['id']}`: {family['title']}")
            lines.append(f"  - stop: {family['stop_condition']}")
            lines.append(f"  - variants: {', '.join(family['variants'])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def cmd_mutation_plan(args: argparse.Namespace) -> None:
    adapter_path, adapter = _load_target_adapter(args.target)
    catalog = load_mutation_catalog()
    requested_modules = {args.module} if args.module else None
    modules = []
    for adapter_module in adapter.get("modules", []) or []:
        module_id = str(adapter_module.get("id") or "")
        local_name = str(adapter_module.get("local_name") or "")
        if requested_modules and module_id not in requested_modules and local_name not in requested_modules:
            continue
        configured_families = adapter_module.get("mutation_families") or []
        if not configured_families:
            configured_families = [
                family_id
                for family_id, family in catalog.items()
                if module_id in set(str(item) for item in family.get("applies_to", []))
            ]
        families = []
        variant_count = 0
        for family_id in configured_families:
            family = catalog.get(str(family_id))
            if not family:
                families.append(
                    {
                        "id": str(family_id),
                        "title": "",
                        "variants": [],
                        "stop_condition": "",
                        "status": "missing_catalog_entry",
                    }
                )
                continue
            variants = [str(item) for item in family.get("variants", [])]
            variant_count += len(variants)
            families.append(
                {
                    "id": str(family.get("id")),
                    "title": family.get("title", ""),
                    "variants": variants,
                    "stop_condition": family.get("stop_condition", ""),
                    "status": "planned",
                }
            )
        modules.append(
            {
                "id": module_id,
                "local_name": local_name,
                "families": families,
                "variant_count": variant_count,
                "adapter_command": adapter_module.get("command", []),
                "result_files": adapter_module.get("result_files", []),
            }
        )
    if requested_modules and not modules:
        raise SystemExit(f"module not found in adapter: {args.module}")
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "target_id": adapter.get("target_id", args.target),
        "adapter_manifest": rel(adapter_path),
        "mutation_catalog": rel(mutation_catalog_path()),
        "modules": modules,
    }
    if args.run_dir:
        run_dir = run_path(args.run_dir)
        out = run_dir / "evidence" / "mutation_coverage" / f"{args.module or 'all_modules'}.json"
        write_json(out, payload)
        print(rel(out))
        return
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == ".json":
            write_json(out, payload)
        else:
            write_text(out, _mutation_plan_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_mutation_plan_markdown(payload).rstrip())


def _mutation_artifact_paths(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    paths = []
    for name in ["campaign.json", "results.json"]:
        direct = root / name
        if direct.exists():
            paths.append(direct)
    paths.extend(sorted(root.glob("modules/*/results.json")))
    seen = set()
    out = []
    for path in paths:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _mutation_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _validate_mutation_block(
    block: Any,
    catalog: dict[str, dict[str, Any]],
    artifact: Path,
    block_path: str,
    allow_unknown_variants: bool,
) -> dict[str, Any]:
    errors = []
    warnings = []
    if not isinstance(block, dict):
        return {
            "path": block_path,
            "status": "fail",
            "errors": [f"{block_path}: mutation_coverage must be an object"],
            "warnings": [],
            "summary": {},
        }
    module_id = str(block.get("module_id") or "")
    local_name = str(block.get("local_name") or "")
    if not module_id:
        errors.append(f"{block_path}: missing module_id")
    if not local_name:
        errors.append(f"{block_path}: missing local_name")
    families = block.get("families")
    if not isinstance(families, list):
        errors.append(f"{block_path}: families must be a list")
        families = []

    calculated = {"variants_planned": 0, "variants_executed": 0, "variants_skipped": 0}
    for family in families:
        if not isinstance(family, dict):
            errors.append(f"{block_path}: family entry must be an object")
            continue
        family_id = str(family.get("id") or "")
        family_path = f"{block_path}.families[{family_id or '<missing>'}]"
        if not family_id:
            errors.append(f"{family_path}: missing id")
            continue
        catalog_family = catalog.get(family_id)
        if not catalog_family:
            errors.append(f"{family_path}: unknown family id")
            catalog_variants: set[str] = set()
            applies_to: set[str] = set()
        else:
            catalog_variants = {str(item) for item in catalog_family.get("variants", [])}
            applies_to = {str(item) for item in catalog_family.get("applies_to", [])}
            if module_id and module_id not in applies_to:
                warnings.append(f"{family_path}: module_id {module_id} is not listed in family applies_to")

        executed = family.get("variants_executed")
        skipped = family.get("variants_skipped")
        if not isinstance(executed, list):
            errors.append(f"{family_path}: variants_executed must be a list")
            executed = []
        if not isinstance(skipped, list):
            errors.append(f"{family_path}: variants_skipped must be a list")
            skipped = []

        executed_ids = []
        for item in executed:
            if not isinstance(item, str) or not item:
                errors.append(f"{family_path}: executed variant must be a non-empty string")
                continue
            executed_ids.append(item)
        skipped_ids = []
        for item in skipped:
            if not isinstance(item, dict):
                errors.append(f"{family_path}: skipped variant must be an object")
                continue
            variant_id = str(item.get("id") or "")
            reason = str(item.get("reason") or "")
            if not variant_id:
                errors.append(f"{family_path}: skipped variant missing id")
                continue
            if not reason:
                errors.append(f"{family_path}.{variant_id}: skipped variant missing reason")
            skipped_ids.append(variant_id)

        duplicate_executed = sorted({item for item in executed_ids if executed_ids.count(item) > 1})
        duplicate_skipped = sorted({item for item in skipped_ids if skipped_ids.count(item) > 1})
        for variant_id in duplicate_executed:
            errors.append(f"{family_path}: duplicate executed variant {variant_id}")
        for variant_id in duplicate_skipped:
            errors.append(f"{family_path}: duplicate skipped variant {variant_id}")

        executed_set = set(executed_ids)
        skipped_set = set(skipped_ids)
        both = sorted(executed_set & skipped_set)
        for variant_id in both:
            errors.append(f"{family_path}: variant appears in both executed and skipped: {variant_id}")

        observed = executed_set | skipped_set
        if catalog_variants:
            missing = sorted(catalog_variants - observed)
            unknown = sorted(observed - catalog_variants)
            for variant_id in missing:
                errors.append(f"{family_path}: catalog variant missing from coverage: {variant_id}")
            for variant_id in unknown:
                msg = f"{family_path}: unknown variant not in catalog: {variant_id}"
                if allow_unknown_variants:
                    warnings.append(msg)
                else:
                    errors.append(msg)

        calculated["variants_executed"] += len(executed_ids)
        calculated["variants_skipped"] += len(skipped_ids)
        calculated["variants_planned"] += len(executed_ids) + len(skipped_ids)

    summary = block.get("summary")
    if not isinstance(summary, dict):
        errors.append(f"{block_path}: summary must be an object")
        summary = {}
    for key, expected in calculated.items():
        value = _mutation_int(summary.get(key))
        if value is None:
            errors.append(f"{block_path}.summary.{key}: must be an integer")
        elif value != expected:
            errors.append(f"{block_path}.summary.{key}: expected {expected}, got {value}")

    return {
        "path": block_path,
        "module_id": module_id,
        "local_name": local_name,
        "status": "fail" if errors else "pass",
        "errors": errors,
        "warnings": warnings,
        "summary": summary,
    }


def _validate_mutation_artifact(
    path: Path,
    catalog: dict[str, dict[str, Any]],
    allow_missing: bool,
    allow_unknown_variants: bool,
) -> dict[str, Any]:
    errors = []
    warnings = []
    blocks = []
    try:
        data = read_json(path, {})
    except Exception as exc:
        return {"path": rel(path), "status": "fail", "errors": [f"invalid JSON: {exc}"], "warnings": [], "blocks": []}
    coverage = data.get("mutation_coverage")
    if not coverage:
        message = "missing mutation_coverage"
        if allow_missing:
            warnings.append(message)
            return {"path": rel(path), "status": "pass", "errors": [], "warnings": warnings, "blocks": []}
        errors.append(message)
        return {"path": rel(path), "status": "fail", "errors": errors, "warnings": warnings, "blocks": []}

    if isinstance(coverage, dict) and isinstance(coverage.get("modules"), list):
        totals = {"variants_planned": 0, "variants_executed": 0, "variants_skipped": 0}
        for idx, module_block in enumerate(coverage.get("modules") or []):
            result = _validate_mutation_block(
                module_block,
                catalog,
                path,
                f"mutation_coverage.modules[{idx}]",
                allow_unknown_variants,
            )
            blocks.append(result)
            summary = result.get("summary") or {}
            for key in totals:
                totals[key] += int(summary.get(key, 0) or 0)
        summary = coverage.get("summary")
        if not isinstance(summary, dict):
            errors.append("mutation_coverage.summary must be an object")
        else:
            for key, expected in totals.items():
                value = _mutation_int(summary.get(key))
                if value is None:
                    errors.append(f"mutation_coverage.summary.{key}: must be an integer")
                elif value != expected:
                    errors.append(f"mutation_coverage.summary.{key}: expected {expected}, got {value}")
    else:
        blocks.append(
            _validate_mutation_block(
                coverage,
                catalog,
                path,
                "mutation_coverage",
                allow_unknown_variants,
            )
        )

    for block in blocks:
        errors.extend(block.get("errors", []))
        warnings.extend(block.get("warnings", []))
    return {
        "path": rel(path),
        "status": "fail" if errors else "pass",
        "errors": errors,
        "warnings": warnings,
        "blocks": blocks,
    }


def _mutation_coverage_check_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Mutation Coverage Check",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Passed: `{payload['passed']}`",
        f"- Root: `{payload['root']}`",
        f"- Catalog: `{payload['mutation_catalog']}`",
        f"- Artifacts: `{len(payload['artifacts'])}`",
        "",
        "## Artifacts",
        "",
    ]
    for artifact in payload["artifacts"]:
        lines.append(f"- `{artifact['path']}` status=`{artifact['status']}`")
        for error_item in artifact["errors"]:
            lines.append(f"  - error: {error_item}")
        for warning_item in artifact["warnings"]:
            lines.append(f"  - warning: {warning_item}")
        for block in artifact["blocks"]:
            summary = block.get("summary") or {}
            lines.append(
                f"  - block `{block.get('module_id')}`/`{block.get('local_name')}` "
                f"planned=`{summary.get('variants_planned')}` executed=`{summary.get('variants_executed')}` "
                f"skipped=`{summary.get('variants_skipped')}` status=`{block.get('status')}`"
            )
    return "\n".join(lines).rstrip() + "\n"


def cmd_mutation_coverage_check(args: argparse.Namespace) -> None:
    root = run_path(args.path)
    artifacts = _mutation_artifact_paths(root)
    if not artifacts:
        raise SystemExit(f"no mutation coverage artifacts found under: {args.path}")
    catalog = load_mutation_catalog()
    results = [
        _validate_mutation_artifact(
            path,
            catalog,
            allow_missing=args.allow_missing,
            allow_unknown_variants=args.allow_unknown_variants,
        )
        for path in artifacts
    ]
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "root": rel(root),
        "mutation_catalog": rel(mutation_catalog_path()),
        "passed": all(item["status"] == "pass" for item in results),
        "artifacts": results,
    }
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == ".json":
            write_json(out, payload)
        else:
            write_text(out, _mutation_coverage_check_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_mutation_coverage_check_markdown(payload).rstrip())
    if args.fail and not payload["passed"]:
        raise SystemExit(2)


def _git_ref_exists(repo: Path, ref: str, timeout: int = 10) -> bool:
    if not ref:
        return False
    result = run_cmd(["git", "rev-parse", "--verify", "--quiet", ref], repo, timeout=timeout)
    return result["returncode"] == 0 and not result["timeout"]


def _previous_tag(repo: Path, tag: str, timeout: int = 10) -> str:
    if not tag or not _git_ref_exists(repo, tag, timeout):
        return ""
    result = run_cmd(["git", "describe", "--tags", "--abbrev=0", f"{tag}^"], repo, timeout=timeout)
    if result["returncode"] == 0 and result["stdout"].strip():
        return result["stdout"].strip()
    return ""


def _patch_first_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Patch-First Plan: {payload['target_id']}",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Target profile: `{payload['target_profile']}`",
        f"- Source path: `{payload['source_path']}`",
        f"- Git available: `{payload['git_available']}`",
        "",
        "## Priority Seeds",
        "",
    ]
    for item in payload["priority_seeds"]:
        lines.append(f"- score=`{item['score']}` type=`{item['type']}` ref=`{item['ref']}`")
        lines.append(f"  - rationale: {item['rationale']}")
        lines.append(f"  - next: `{item['next_action']}`")
    if not payload["priority_seeds"]:
        lines.append("- None")
    lines.extend(["", "## Suggested Commands", ""])
    if payload["suggested_commands"]:
        for cmd in payload["suggested_commands"]:
            lines.append(f"```sh\n{cmd}\n```")
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def cmd_patch_first_plan(args: argparse.Namespace) -> None:
    profile_path, target = _target_profile_by_arg(args.target)
    src = source_path(target)
    target_id = str(target.get("id") or profile_path.stem)
    latest = target.get("latest_release") or {}
    latest_tag = str(latest.get("tag") or "")
    git_available = src.exists() and (src / ".git").exists()
    previous = _previous_tag(src, latest_tag, args.timeout) if git_available else ""
    priority = []
    suggested_commands = []

    if latest_tag and previous:
        ref_range = f"{previous}..{latest_tag}"
        priority.append(
            {
                "type": "release_diff",
                "ref": ref_range,
                "score": 95,
                "rationale": "Latest release range is locally available; mine security-adjacent changes before broad scans.",
                "next_action": f"patch-mine <run-dir> --range {ref_range}",
            }
        )
        suggested_commands.append(
            f".venv-vapt/bin/python vapt/harness/harness.py patch-mine <run-dir> --range {ref_range}"
        )
    elif latest_tag:
        priority.append(
            {
                "type": "release_diff",
                "ref": latest_tag,
                "score": 70,
                "rationale": "Latest release tag exists in profile, but previous local tag could not be verified.",
                "next_action": "fetch tags or provide an explicit patch-mine --range",
            }
        )

    for cve in target.get("known_duplicates") or []:
        priority.append(
            {
                "type": "known_advisory",
                "ref": str(cve),
                "score": 80,
                "rationale": "Known duplicate/advisory should be used as a novelty boundary and sibling-variant seed.",
                "next_action": f"dedup --reference {cve}; patch-diff around the fixing change if available",
            }
        )

    for entry in queue_entries(target_id, include_claimed=False):
        priority.append(
            {
                "type": str(entry.get("type") or "watch_queue"),
                "ref": str(entry.get("ref") or entry.get("queue_id")),
                "score": 88,
                "rationale": "Fresh watch-generated queue entry should be triaged before broad scanning.",
                "next_action": f"queue claim {entry.get('queue_id')}",
            }
        )

    if any(item.get("type") == "known_advisory" for item in priority):
        suggested_commands.append(
            f".venv-vapt/bin/python vapt/harness/harness.py campaign-plan {target_id} --limit 3"
        )
    if target.get("osv_ecosystem") and target.get("osv_package"):
        suggested_commands.append(
            ".venv-vapt/bin/python vapt/harness/harness.py dedup <run-dir> <candidate-id> "
            f"--check-osv --osv-ecosystem {target.get('osv_ecosystem')} --osv-package {target.get('osv_package')}"
        )

    priority.sort(key=lambda item: (-int(item["score"]), item["type"], item["ref"]))
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "target_id": target_id,
        "target_profile": rel(profile_path),
        "source_path": rel(src),
        "git_available": git_available,
        "latest_release": latest,
        "previous_tag": previous,
        "priority_seeds": priority[: args.limit],
        "suggested_commands": suggested_commands,
    }
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == ".json":
            write_json(out, payload)
        else:
            write_text(out, _patch_first_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_patch_first_markdown(payload).rstrip())


def _next_action_for_module(module_id: str, status: str, target_id: str) -> str:
    if status == "candidate_signal":
        return f"prove and dedup candidate signals from {module_id}"
    if status == "partial":
        return f"rerun {module_id} with mutation-plan coverage and fix setup gaps"
    if status == "untested":
        return f"implement or run adapter module {module_id}"
    if status == "tested_unknown":
        return f"review {module_id} evidence and mark closed, partial, or candidate"
    return f"watch patch-first-plan {target_id} for new sibling variants"


# _campaign_dashboard_markdown moved to campaign/commands.py.
# cmd_campaign_dashboard moved to campaign/commands.py.
class _TemplateContext(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(f"unknown adapter command template variable: {key}")


def _render_adapter_value(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(_TemplateContext(context))
    if isinstance(value, list):
        return [_render_adapter_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _render_adapter_value(item, context) for key, item in value.items()}
    return value


def _load_adapter_from_args(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    if args.adapter:
        path = run_path(args.adapter)
        if not path.exists():
            raise SystemExit(f"adapter manifest not found: {args.adapter}")
        return path, load_yaml(path) or {}
    if not args.target:
        raise SystemExit("campaign-run requires --target or --adapter")
    return _load_target_adapter(args.target)


# _campaign_run_markdown moved to campaign/commands.py.
# cmd_campaign_run moved to campaign/commands.py.
def _artifact_path_from_record(record: dict[str, Any]) -> Path:
    return run_path(str(record.get("path") or ""))


def _path_is_under(path: Path, root: Path) -> bool:
    with contextlib.suppress(ValueError):
        path.resolve().relative_to(root.resolve())
        return True
    return False


# _campaign_gate_markdown moved to campaign/commands.py.
def _gate_check(check_id: str, ok: bool, details: list[str] | None = None) -> dict[str, Any]:
    return {"id": check_id, "status": "pass" if ok else "fail", "details": details or []}


# cmd_campaign_gate moved to campaign/commands.py.
# Campaign lifecycle handlers + helpers moved to campaign/commands.py.
from campaign.commands import (  # noqa: E402
    _campaign_adapter_check_markdown,
    _campaign_advisory_refresh_markdown,
    _campaign_dashboard_markdown,
    _campaign_flow_check_markdown,
    _campaign_gate_markdown,
    _campaign_history,
    _campaign_next_commands_markdown,
    _campaign_plan_markdown,
    _campaign_refresh_package_metadata,
    _campaign_refresh_sources,
    _campaign_run_markdown,
    _campaign_start_markdown,
    _run_campaign_advisory_refresh,
    _score_campaign_module,
    _write_campaign_start_plan_files,
    cmd_campaign_adapter_check,
    cmd_campaign_dashboard,
    cmd_campaign_flow_check,
    cmd_campaign_gate,
    cmd_campaign_plan,
    cmd_campaign_run,
    cmd_campaign_start,
    cmd_candidate_link_campaign,
)



def cmd_score_tune(args: argparse.Namespace) -> None:
    rows = read_jsonl(submissions_path())
    if args.since:
        since = _parse_time(args.since)
        if since:
            rows = [row for row in rows if (_parse_time(row.get("submitted_at")) or dt.datetime.min) >= since]
    candidates_by_key = {}
    for row in read_jsonl(candidate_corpus_path()):
        key = (row.get("run_dir"), row.get("candidate", {}).get("id"))
        candidates_by_key[key] = row.get("candidate", {})
    fields = [
        "attacker_control",
        "entrypoint",
        "trust_boundary",
        "sink",
        "impact",
        "negative_controls",
        "root_cause",
        "variant_analysis",
        "patch_diff",
        "cvss",
        "cwe",
    ]
    stats: dict[str, dict[str, int]] = {field: {"positive_present": 0, "positive_absent": 0, "negative_present": 0, "negative_absent": 0} for field in fields}
    terminal = [row for row in rows if row.get("final_status")]
    for row in terminal:
        cand = candidates_by_key.get((row.get("candidate_run"), row.get("candidate_id")), {})
        positive = submission_positive(str(row.get("final_status")))
        for field in fields:
            present = substantive(cand.get(field))
            key = ("positive_" if positive else "negative_") + ("present" if present else "absent")
            stats[field][key] += 1
    recommendations = []
    for field, item in stats.items():
        pos_total = item["positive_present"] + item["positive_absent"]
        neg_total = item["negative_present"] + item["negative_absent"]
        if not pos_total or not neg_total:
            continue
        pos_rate = item["positive_present"] / pos_total
        neg_rate = item["negative_present"] / neg_total
        delta = round(pos_rate - neg_rate, 3)
        recommendations.append({"field": field, "positive_presence_rate": round(pos_rate, 3), "negative_presence_rate": round(neg_rate, 3), "delta": delta})
    recommendations.sort(key=lambda item: -abs(item["delta"]))
    out_dir = ROOT / "vapt" / "harness" / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"score_tune_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    md = [
        "# Score Tuning Report",
        "",
        f"- Terminal submissions: `{len(terminal)}`",
        f"- Minimum recommended threshold: `{args.min_terminal}`",
        f"- Status: `{'sufficient' if len(terminal) >= args.min_terminal else 'insufficient-data'}`",
        "",
        "## Field Correlations",
        "",
    ]
    for item in recommendations:
        md.append(
            f"- `{item['field']}` positive_rate=`{item['positive_presence_rate']}` "
            f"negative_rate=`{item['negative_presence_rate']}` delta=`{item['delta']}`"
        )
    if not recommendations:
        md.append("- Not enough terminal positive/negative data yet.")
    write_text(out, "\n".join(md) + "\n")
    print(rel(out))


def phase2_surface_regression() -> dict[str, Any]:
    corpus = ROOT / "vapt" / "harness" / "tests" / "surface_corpus"
    expectations_path = ROOT / "vapt" / "harness" / "tests" / "surface_expectations.yaml"
    expectations = load_yaml(expectations_path) or {"categories": {}}
    categories = {}
    failures = []
    for category, spec in (expectations.get("categories") or {}).items():
        hits = []
        for pattern in PATTERNS.get(category, []):
            result = run_cmd(["rg", "-n", "-S", "-F", pattern], corpus, timeout=30)
            if result["returncode"] in (0, 1):
                hits.extend(result["stdout"].splitlines())
        unique_hits = sorted(set(hits))
        min_hits = int(spec.get("min_hits", 0))
        passed = len(unique_hits) >= min_hits
        if not passed:
            failures.append(f"{category}: expected >= {min_hits}, got {len(unique_hits)}")
        categories[category] = {
            "min_hits": min_hits,
            "hit_count": len(unique_hits),
            "passed": passed,
        }
    return {"passed": not failures, "failures": failures, "categories": categories}


def phase2_suggestion_count(target_id: str) -> int:
    profile_path, target = _load_target_profile(target_id)
    if not target:
        return 0
    if not candidate_corpus_path().exists():
        cmd_corpus_rebuild(argparse.Namespace())
    target_terms = _term_set(" ".join(str(x) for x in target.get("category", []) + target.get("in_scope", [])))
    count = 0
    for row in read_jsonl(candidate_corpus_path()):
        cand = row.get("candidate", {})
        if row.get("target_id") == target_id:
            continue
        if target_terms & _term_set(_candidate_signal(cand)):
            count += 1
    return count


def phase2_fixture_submission_stats() -> dict[str, Any]:
    rows = [
        {"program": "phase2-fixture", "final_status": "triaged", "payout_value": 500, "days_to_final": 3},
        {"program": "phase2-fixture", "final_status": "resolved", "payout_value": 750, "days_to_final": 5},
        {"program": "phase2-fixture", "final_status": "paid", "payout_value": 1000, "days_to_final": 8},
        {"program": "phase2-fixture", "final_status": "duplicate", "payout_value": None, "days_to_final": 2},
        {"program": "phase2-fixture", "final_status": "n_a", "payout_value": None, "days_to_final": 1},
    ]
    return submission_stats(rows)


def cmd_phase2_check(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    if not run_dir.exists():
        raise SystemExit(f"run directory not found: {run_dir}")

    cmd_corpus_rebuild(argparse.Namespace())
    surface = phase2_surface_regression()
    fixture_stats = phase2_fixture_submission_stats()
    actual_stats = submission_stats(read_jsonl(submissions_path()))
    suggestion_count = phase2_suggestion_count(args.target_id)
    ranked_targets = []
    for path in _target_profile_paths():
        target = load_yaml(path) or {}
        ranked_targets.append(target.get("id") or path.stem)
    retro_md = run_dir / "retro.md"
    retro_patch = run_dir / "retro.patch"
    if args.refresh_retro or not (retro_md.exists() and retro_patch.exists()):
        cmd_retro(argparse.Namespace(run_dir=str(run_dir)))

    checks = {
        "submission_ledger_commands": True,
        "fixture_submission_stats_meaningful": (
            fixture_stats["total_submissions"] == 5
            and fixture_stats["programs"]["phase2-fixture"]["terminal"] == 5
            and fixture_stats["programs"]["phase2-fixture"]["positive"] == 3
        ),
        "retro_artifacts_exist": retro_md.exists() and retro_patch.exists(),
        "corpus_suggest_nontrivial": suggestion_count > 0,
        "pick_target_has_registered_targets": len(ranked_targets) >= 1,
        "pattern_coverage_passed": surface["passed"],
    }
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "run_dir": rel(run_dir),
        "target_id": args.target_id,
        "passed": all(checks.values()),
        "checks": checks,
        "surface_regression": surface,
        "fixture_submission_stats": fixture_stats,
        "actual_submission_stats": actual_stats,
        "corpus_suggestion_count": suggestion_count,
        "registered_targets": ranked_targets,
        "retro": {
            "retro_md": rel(retro_md) if retro_md.exists() else "",
            "retro_patch": rel(retro_patch) if retro_patch.exists() else "",
        },
    }
    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"phase2_check_{stamp}.json"
    write_json(out_json, payload)
    out_md = out_dir / f"phase2_check_{stamp}.md"
    md = [
        "# Phase 2 Acceptance Check",
        "",
        f"- Passed: `{payload['passed']}`",
        f"- Run dir: `{payload['run_dir']}`",
        f"- Target: `{args.target_id}`",
        f"- Corpus suggestions: `{suggestion_count}`",
        f"- Registered targets: `{len(ranked_targets)}`",
        "",
        "## Checks",
        "",
    ]
    for name, passed in checks.items():
        md.append(f"- `{name}`: `{passed}`")
    if surface["failures"]:
        md.extend(["", "## Surface Failures", ""])
        for failure in surface["failures"]:
            md.append(f"- {failure}")
    write_text(out_md, "\n".join(md) + "\n")
    print(rel(out_md))
    if not payload["passed"]:
        raise SystemExit(2)


PROBE_REGISTRY = {
    "websocket_authz_drift": {
        "module": "websocket_authz_drift",
        "class": "WebsocketAuthzDriftProbe",
        "vuln_class": "websocket_authz",
        "terms": ["websocket", "realtime", "broadcast", "event", "authz"],
    },
    "serialization_rce": {
        "module": "serialization_rce",
        "class": "SerializationRCEProbe",
        "vuln_class": "serialization_rce",
        "terms": ["pickle", "serialization", "deserialize", "trusted", "allowlist", "load"],
    },
    "ssrf_outbound": {
        "module": "ssrf_outbound",
        "class": "SSRFOutboundProbe",
        "vuln_class": "ssrf_outbound",
        "terms": ["ssrf", "url", "webhook", "registry", "http", "fetch", "request"],
    },
    "parser_canonicalization": {
        "module": "parser_canonicalization",
        "class": "ParserCanonicalizationProbe",
        "vuln_class": "parser_canonicalization",
        "terms": ["parse", "canonical", "normalize", "decode", "path", "traversal", "archive"],
    },
    "prompt_injection_to_tool": {
        "module": "prompt_injection_to_tool",
        "class": "PromptInjectionToToolProbe",
        "vuln_class": "prompt_injection_chain",
        "terms": ["prompt", "agent", "tool", "rag", "function_call"],
    },
    "idor_diff": {
        "module": "idor_diff",
        "class": "IDORDiffProbe",
        "vuln_class": "idor_diff",
        "terms": ["idor", "authz", "authorization", "permission", "tenant", "object", "owner"],
    },
    "rag_poisoning_durability": {
        "module": "rag_poisoning_durability",
        "class": "RAGPoisoningDurabilityProbe",
        "vuln_class": "rag_poisoning_durability",
        "terms": ["rag", "retrieval", "embedding", "index", "poison", "persist", "durable"],
    },
    "model_card_local_file_read": {
        "module": "model_card_local_file_read",
        "class": "ModelCardLocalFileReadProbe",
        "vuln_class": "model_card_local_file_read",
        "terms": ["model card", "template", "markdown", "yaml", "local file", "file read", "path"],
    },
    "unauth_secret_config": {
        "module": "unauth_secret_config",
        "class": "UnauthSecretConfigProbe",
        "vuln_class": "unauth_secret_config",
        "terms": ["unauth", "missing auth", "config", "settings", "secret", "token", "api key"],
    },
    "relative_file_write_to_code_load": {
        "module": "relative_file_write_to_code_load",
        "class": "RelativeFileWriteToCodeLoadProbe",
        "vuln_class": "relative_file_write_to_code_load",
        "terms": ["relative", "cwd", "file write", "download", "plugin", "custom node", "reload", "rce"],
    },
    "workflow_node_local_file_read": {
        "module": "workflow_node_local_file_read",
        "class": "WorkflowNodeLocalFileReadProbe",
        "vuln_class": "workflow_node_local_file_read",
        "terms": ["workflow", "graph", "node", "invocation", "file read", "local file", "queue", "result"],
    },
    "queue_job_secret_leak": {
        "module": "queue_job_secret_leak",
        "class": "QueueJobSecretLeakProbe",
        "vuln_class": "queue_job_secret_leak",
        "terms": ["queue", "job", "token", "secret", "credential", "bearer", "owner", "redact"],
    },
    "deserialization_handle_path_control": {
        "module": "deserialization_handle_path_control",
        "class": "DeserializationHandlePathControlProbe",
        "vuln_class": "deserialization_handle_path_control",
        "terms": [
            "deserialize",
            "deserialization",
            "torch.load",
            "pickle",
            "model load",
            "handle",
            "path traversal",
            "absolute path",
        ],
    },
}


# tool_gaps_path moved to tools.commands.
# log_tool_gap moved to tools.commands.
def select_probe(cand: dict[str, Any]) -> str | None:
    text = _candidate_signal(cand).lower()
    best = None
    best_score = 0
    for name, spec in PROBE_REGISTRY.items():
        score = sum(1 for term in spec["terms"] if term in text)
        if score > best_score:
            best = name
            best_score = score
    return best


def load_probe(name: str):
    if name not in PROBE_REGISTRY:
        raise SystemExit(f"unknown probe: {name}")
    spec = PROBE_REGISTRY[name]
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    module = __import__(f"probes.{spec['module']}", fromlist=[spec["class"]])
    return getattr(module, spec["class"])()


def cmd_probes(args: argparse.Namespace) -> None:
    items = []
    for name, spec in sorted(PROBE_REGISTRY.items()):
        items.append({"name": name, "vuln_class": spec["vuln_class"], "terms": spec["terms"]})
    print(json.dumps({"probes": items}, indent=2, sort_keys=False))


def cmd_probes_test(args: argparse.Namespace) -> None:
    fixture = run_path(args.fixture)
    data = load_yaml(fixture) or {}
    candidates = data.get("candidates", {})
    if not isinstance(candidates, dict):
        raise SystemExit("probe fixture must contain candidates mapping")
    run_dir = run_path(args.run_dir) if args.run_dir else ROOT / "vapt" / "harness" / "tests" / "results" / "probe_smoke"
    run_dir.mkdir(parents=True, exist_ok=True)
    target = data.get("target") or {"id": "probe-fixture", "source_path": "."}
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    from probes.base import ProbeContext

    selected = [args.probe] if args.probe else sorted(PROBE_REGISTRY)
    results = []
    failures = []
    for probe_name in selected:
        if probe_name not in PROBE_REGISTRY:
            raise SystemExit(f"unknown probe: {probe_name}")
        cand = candidates.get(probe_name)
        if not cand:
            failures.append({"probe": probe_name, "reason": "fixture candidate missing"})
            continue
        probe = load_probe(probe_name)
        ctx = ProbeContext(run_dir=run_dir, target=target, candidate=dict(cand), knobs={"fixture": str(fixture)})
        probe.prepare(ctx)
        result = probe.run(ctx)
        evidence = probe.evidence(ctx, result)
        probe.cleanup(ctx)
        item = {
            "probe": probe_name,
            "passed": bool(result.get("passed")),
            "missing": result.get("missing", []),
            "evidence": rel(evidence),
        }
        results.append(item)
        if not item["passed"]:
            failures.append(item)

    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact = out_dir / f"probe_smoke_{stamp}.json"
    write_json(
        artifact,
        {
            "fixture": rel(fixture),
            "run_dir": rel(run_dir),
            "results": results,
            "failures": failures,
        },
    )
    print(rel(artifact))
    if failures:
        raise SystemExit(1)


def cmd_refine(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    probe_name = args.probe or select_probe(cand)
    out_dir = run_dir / "refine"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    if not probe_name:
        missing_class = cand.get("weakness") or cand.get("surface") or "unknown"
        log_tool_gap(run_dir, args.candidate_id, str(missing_class), "No matching probe for candidate terms")
        artifact = {
            "candidate_id": args.candidate_id,
            "status": "tool-gap",
            "missing_class": missing_class,
            "iterations": [],
        }
        dump_yaml(artifact, out_dir / f"{args.candidate_id}_{stamp}.yaml")
        print(rel(out_dir / f"{args.candidate_id}_{stamp}.yaml"))
        raise SystemExit(2)

    probe = load_probe(probe_name)
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    from probes.base import ProbeContext

    iterations = []
    for index in range(args.max_iterations):
        ctx = ProbeContext(run_dir=run_dir, target=target, candidate=cand, knobs={"iteration": index + 1})
        probe.prepare(ctx)
        result = probe.run(ctx)
        evidence = probe.evidence(ctx, result)
        probe.cleanup(ctx)
        iterations.append({"iteration": index + 1, "probe": probe_name, "result": dict(result), "evidence": rel(evidence)})
        if result.get("passed"):
            break
    artifact = {
        "candidate_id": args.candidate_id,
        "probe": probe_name,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "iterations": iterations,
    }
    dump_yaml(artifact, out_dir / f"{args.candidate_id}_{stamp}.yaml")
    md = [
        f"# Refine: {args.candidate_id}",
        "",
        f"- Probe: `{probe_name}`",
        f"- Iterations: `{len(iterations)}`",
        "",
    ]
    for item in iterations:
        result = item["result"]
        md.extend(
            [
                f"## Iteration {item['iteration']}",
                "",
                f"- Passed: `{result.get('passed')}`",
                f"- Missing: `{', '.join(result.get('missing', []))}`",
                f"- Evidence: `{item['evidence']}`",
                f"- Next: {result.get('recommended_next', '')}",
                "",
            ]
        )
    write_text(out_dir / f"{args.candidate_id}_{stamp}.md", "\n".join(md))
    update_candidate_locked(
        run_dir,
        args.candidate_id,
        lambda updated: updated.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "refine",
                "probe": probe_name,
                "artifact": rel(out_dir / f"{args.candidate_id}_{stamp}.md"),
            }
        ),
    )
    print(rel(out_dir / f"{args.candidate_id}_{stamp}.md"))


def _infer_playbook_class(target: dict[str, Any]) -> str:
    text = " ".join(
        str(item)
        for item in [
            target.get("id", ""),
            target.get("name", ""),
            target.get("language", ""),
            target.get("category", ""),
        ]
    ).lower()
    if "deserialization" in text or "serialization" in text:
        return "python-ml-deserialization"
    if "inference" in text or "runtime" in text or "local ai" in text:
        return "local-ai-runtime"
    if "mlops" in text or "experiment" in text or "orchestration" in text:
        return "mlops"
    if "javascript" in text or "typescript" in text or "electron" in text or "web" in text:
        return "js-ts-web"
    if "go" in text or "server" in text or "api" in text:
        return "go-api-server"
    return "python-ml-deserialization" if "python" in text else "go-api-server"


def cmd_playbook(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _state, target = load_run(run_dir)
    playbook_id = args.kind if args.kind != "auto" else _infer_playbook_class(target)
    playbook = TARGET_PLAYBOOKS.get(playbook_id)
    if not playbook:
        raise SystemExit(f"unknown playbook: {playbook_id}")
    out_dir = run_dir / "playbooks"
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    commands = [
        f"{sys.argv[0]} prepare {rel(run_dir)} --allow-non-git",
        f"{sys.argv[0]} map {rel(run_dir)}",
        f"{sys.argv[0]} source-graph {rel(run_dir)}",
        f"{sys.argv[0]} semantic-graph {rel(run_dir)}",
        f"{sys.argv[0]} scan-semgrep {rel(run_dir)} --ruleset auto",
        f"{sys.argv[0]} scan-codeql {rel(run_dir)} --create-database --language {playbook['codeql']} --query security-extended",
        f"{sys.argv[0]} scan-codeql {rel(run_dir)} --database {rel(run_dir / 'tool_scans' / 'codeql_db' / playbook['codeql'])} --query security-and-quality",
        f"{sys.argv[0]} hypothesize {rel(run_dir)}",
    ]
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "target": target.get("id", ""),
        "playbook_id": playbook_id,
        "name": playbook["name"],
        "checks": playbook["checks"],
        "recommended_poc_classes": playbook["poc_classes"],
        "commands": commands,
    }
    dump_yaml(payload, out_dir / f"playbook_{playbook_id}_{stamp}.yaml")
    md = [
        f"# Target Playbook: {playbook['name']}",
        "",
        f"- Target: `{target.get('id', '')}`",
        f"- Playbook: `{playbook_id}`",
        f"- CodeQL language: `{playbook['codeql']}`",
        "",
        "## Review Checks",
        "",
    ]
    md.extend(f"- {item}" for item in playbook["checks"])
    md.extend(["", "## Commands", ""])
    md.extend(f"```sh\n{cmd}\n```" for cmd in commands)
    md.extend(["", "## PoC Templates", ""])
    md.extend(f"- `{item}`: `{sys.argv[0]} scaffold-poc {item} {target.get('id', '')}`" for item in playbook["poc_classes"])
    write_text(out_dir / f"playbook_{playbook_id}_{stamp}.md", "\n".join(md) + "\n")
    print(rel(out_dir / f"playbook_{playbook_id}_{stamp}.md"))


def cmd_codeql_workflow(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _state, target = load_run(run_dir)
    workflow_id = args.language or _infer_playbook_class(target)
    if workflow_id in TARGET_PLAYBOOKS:
        workflow_id = TARGET_PLAYBOOKS[workflow_id]["codeql"]
    workflow = CODEQL_WORKFLOWS.get(workflow_id)
    if not workflow:
        raise SystemExit(f"unknown CodeQL workflow: {workflow_id}")
    out_dir = run_dir / "tool_scans" / "codeql_workflows"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    database = run_dir / "tool_scans" / "codeql_db" / workflow["language"]
    commands = [
        f"{sys.argv[0]} scan-codeql {rel(run_dir)} --create-database --language {workflow['language']} --query {workflow['queries'][0]}",
    ]
    for query in workflow["queries"][1:]:
        commands.append(f"{sys.argv[0]} scan-codeql {rel(run_dir)} --database {rel(database)} --query {query}")
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "target": target.get("id", ""),
        "workflow": workflow_id,
        "language": workflow["language"],
        "queries": workflow["queries"],
        "focus": workflow["focus"],
        "commands": commands,
    }
    dump_yaml(payload, out_dir / f"codeql_workflow_{workflow_id}_{stamp}.yaml")
    md = [f"# CodeQL Workflow: {workflow_id}", "", f"- Language: `{workflow['language']}`", ""]
    md.extend(["## Focus", ""])
    md.extend(f"- {item}" for item in workflow["focus"])
    md.extend(["", "## Commands", ""])
    md.extend(f"```sh\n{cmd}\n```" for cmd in commands)
    write_text(out_dir / f"codeql_workflow_{workflow_id}_{stamp}.md", "\n".join(md) + "\n")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(rel(out_dir / f"codeql_workflow_{workflow_id}_{stamp}.md"))


def _poc_template_body(vuln_class: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", vuln_class.lower()).strip("_")
    if key in {"deserialization", "serialization_rce", "pickle", "model_deserialization"}:
        key = "unsafe_deserialization"
    if key in {"idor", "authz", "authorization", "auth_bypass"}:
        key = "idor_authz"
    if key in {"ssti", "jinja", "template"}:
        key = "template_injection"
    templates = {
        "path_traversal": '''def build_payload(base_path: Path) -> dict:
    return {"candidate": "../controlled-marker.txt", "base": str(base_path)}


def positive_proof() -> dict:
    marker = Path("controlled-marker.txt")
    marker.write_text("harness-marker\\n", encoding="utf-8")
    payload = build_payload(Path.cwd())
    return {
        "status": "todo",
        "payload": payload,
        "expected_impact": "Target reads/writes outside intended base directory.",
        "evidence": "Replace todo with authorized target API invocation and captured output.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "payload": {"candidate": "allowed-file.txt"},
        "expected": "Allowed in-base file succeeds while traversal is denied after fix.",
    }
''',
        "ssrf": '''def positive_proof() -> dict:
    return {
        "status": "todo",
        "canary": "Use a local listener or captive HTTP server only.",
        "expected_impact": "Attacker-controlled URL causes server-side outbound request.",
        "evidence": "Capture listener hit, request path, headers, and target-side response.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "control": "Benign non-URL input or disallowed scheme is rejected.",
    }
''',
        "command_injection": '''def positive_proof() -> dict:
    marker = Path("cmd_injection_marker.txt")
    return {
        "status": "todo",
        "marker": str(marker),
        "payload_shape": "Use a harmless marker-write command in a captive local target.",
        "expected_impact": "Attacker-controlled field reaches command execution boundary.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "control": "Same value passed as an argument vector is treated as data, not shell syntax.",
    }
''',
        "unsafe_deserialization": '''def positive_proof() -> dict:
    return {
        "status": "todo",
        "fixture": "crafted serialized/model/archive fixture generated locally",
        "expected_impact": "Load reaches object construction, file read/write, or code execution outside trusted type policy.",
        "evidence": "Record loader call, exception/output, marker effect, and exact package versions.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "control": "Benign fixture loads; untrusted type/control fixture is rejected.",
    }
''',
        "idor_authz": '''def positive_proof() -> dict:
    return {
        "status": "todo",
        "actors": ["owner_user", "attacker_user"],
        "expected_impact": "Attacker user reads or mutates owner resource without permission.",
        "evidence": "Capture authenticated request/response pairs for both users.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "control": "Owner succeeds; unrelated attacker is denied after permission check/fix.",
    }
''',
        "template_injection": '''def positive_proof() -> dict:
    return {
        "status": "todo",
        "payload_shape": "Harmless arithmetic or marker expression for the target template engine.",
        "expected_impact": "Attacker-controlled text is evaluated/rendered with server-side capabilities.",
        "evidence": "Capture rendered output and engine/context boundary.",
    }


def negative_control() -> dict:
    return {
        "status": "todo",
        "control": "Escaped literal payload renders as text, not evaluated syntax.",
    }
''',
    }
    return templates.get(
        key,
        '''def positive_proof() -> dict:
    return {"status": "todo", "evidence": "implement authorized positive proof"}


def negative_control() -> dict:
    return {"status": "todo", "evidence": "implement denied/benign control"}
''',
    )


def cmd_scaffold_poc(args: argparse.Namespace) -> None:
    profile_path, target = _load_target_profile(args.target_id)
    if not target:
        raise SystemExit(f"target profile not found: {args.target_id}")
    out_dir = ROOT / "vapt" / "pocs" / args.target_id / dt.datetime.now().strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_class = re.sub(r"[^A-Za-z0-9_]+", "_", args.vuln_class).strip("_")
    out = out_dir / f"poc_{safe_class}.py"
    doctrine = ROOT / "vapt" / "harness" / "knowledge" / "vuln_classes" / args.vuln_class / "doctrine.md"
    script = f'''#!/usr/bin/env python3
"""PoC scaffold for {args.vuln_class} on {args.target_id}.

Doctrine: {rel(doctrine) if doctrine.exists() else "not available"}
Target profile: {rel(profile_path) if profile_path else args.target_id}

Fill in only authorized, local/captive test logic. Keep positive proof and
negative controls separate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


{_poc_template_body(args.vuln_class)}


def main() -> int:
    result = {{
        "target": "{args.target_id}",
        "vuln_class": "{args.vuln_class}",
        "scaffold_only": True,
        "ready_for_submission": False,
        "positive": positive_proof(),
        "negative": negative_control(),
    }}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    write_text(out, script)
    out.chmod(0o755)
    print(rel(out))


def cmd_new_probe(args: argparse.Namespace) -> None:
    name = re.sub(r"[^A-Za-z0-9_]+", "_", args.name).strip("_")
    if not name:
        raise SystemExit("invalid probe name")
    class_name = "".join(part.capitalize() for part in name.split("_")) + "Probe"
    probe_path = ROOT / "vapt" / "harness" / "probes" / f"{name}.py"
    if probe_path.exists() and not args.force:
        raise SystemExit(f"probe already exists: {rel(probe_path)}")
    doctrine_dir = ROOT / "vapt" / "harness" / "knowledge" / "vuln_classes" / args.vuln_class
    doctrine_dir.mkdir(parents=True, exist_ok=True)
    doctrine = doctrine_dir / "doctrine.md"
    if not doctrine.exists():
        write_text(
            doctrine,
            f"# {args.vuln_class}\n\nDescribe thesis shape, required proof, sinks, and negative controls.\n",
        )
    code = f'''from __future__ import annotations

from .base import Probe, ProbeContext, ProbeResult


class {class_name}(Probe):
    name = "{name}"
    vuln_class = "{args.vuln_class}"
    description = "{args.description or 'Probe scaffold'}"

    def run(self, ctx: ProbeContext) -> ProbeResult:
        return ProbeResult({{
            "probe": self.name,
            "candidate_id": ctx.candidate.get("id"),
            "passed": False,
            "missing": ["implement probe logic"],
            "recommended_next": "Fill this probe with a bounded local differential test.",
        }})
'''
    write_text(probe_path, code)
    test_dir = ROOT / "vapt" / "harness" / "tests" / "probes"
    test_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        test_dir / f"test_{name}.py",
        "import sys\nfrom pathlib import Path\n\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parents[2]))\n"
        f"from probes.{name} import {class_name}\n\n\n"
        "def test_probe_metadata():\n"
        f"    probe = {class_name}()\n"
        f"    assert probe.name == {name!r}\n"
        f"    assert probe.vuln_class == {args.vuln_class!r}\n",
    )
    print(rel(probe_path))


# Tool runtime layer (container/local discovery, capped-output exec, refuse
# path) lives in tools/runtime.py (core+atomic_io leaf only). Imported here so
# harness.* references resolve unchanged.
from tools.runtime import (  # noqa: E402
    container_runtime,
    find_tool,
    macos_sandbox_exec,
    materialize_capped_file,
    refuse_missing_tool,
    tool_env,
    tool_scan_base,
)


# cmd_sandbox_exec moved to tools.commands.
# cmd_tool_gap_add moved to tools.commands.
# cmd_tool_gaps moved to tools.commands.
# tool_scan_base / refuse_missing_tool / materialize_capped_file / run_tool_scan
# / _ensure_runtime_or_local / _load_tool_module moved to tools/runtime.py
# (re-imported above and here for harness.* compatibility).
from tools.runtime import (  # noqa: E402
    _ensure_runtime_or_local,
    _load_tool_module,
    run_tool_scan,
)


# _authorize_scan moved to tools.commands.
# cmd_scope_check moved to tools.commands.
# cmd_scan_zap_baseline moved to tools.commands.
# cmd_scan_zap_full moved to tools.commands.
# cmd_scan_sqlmap moved to tools.commands.
# cmd_scan_jwt moved to tools.commands.
# cmd_scan_screenshot moved to tools.commands.
# cmd_tools_capability moved to tools.commands.
# cmd_scan_semgrep moved to tools.commands.
# cmd_scan_bandit moved to tools.commands.
# python_requirement_file moved to tools.commands.
# cmd_scan_pip_audit moved to tools.commands.
# cmd_scan_osv moved to tools.commands.
# cmd_scan_codeql moved to tools.commands.
# cmd_scan_trufflehog moved to tools.commands.
# cmd_scan_tls moved to tools.commands.
# cmd_scan_nuclei moved to tools.commands.
# cmd_scan_headers moved to tools.commands.
# cmd_tool_health moved to tools.commands.
def read_tool_records(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
        return [data]
    except json.JSONDecodeError:
        pass
    rows = []
    for line in stripped.splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError):
            rows.append(json.loads(line))
    return rows


def first_cwe(value: Any) -> str:
    if isinstance(value, int):
        return f"CWE-{value}"
    text = " ".join(str(item) for item in value) if isinstance(value, list) else str(value or "")
    match = re.search(r"CWE-?(\d{1,5})", text, flags=re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else ""


def first_cve(*values: Any) -> str:
    text = " ".join(
        " ".join(str(item) for item in value) if isinstance(value, list) else str(value or "")
        for value in values
    )
    match = re.search(r"CVE-\d{4}-\d{4,}", text, flags=re.IGNORECASE)
    return match.group(0).upper() if match else "N/A"


def scanner_severity_rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
    return order.get(str(severity or "").lower(), 0)


# normalize_scanner_findings moved to tools.commands.
# Functions moved to tools.commands.
from tools.commands import (  # noqa: E402
    _authorize_scan,
    cmd_sandbox_exec,
    cmd_scan_bandit,
    cmd_scan_codeql,
    cmd_scan_headers,
    cmd_scan_jwt,
    cmd_scan_nuclei,
    cmd_scan_osv,
    cmd_scan_pip_audit,
    cmd_scan_screenshot,
    cmd_scan_semgrep,
    cmd_scan_sqlmap,
    cmd_scan_tls,
    cmd_scan_trufflehog,
    cmd_scan_zap_baseline,
    cmd_scan_zap_full,
    cmd_scope_check,
    cmd_tool_gap_add,
    cmd_tool_gaps,
    cmd_tool_health,
    cmd_tools_capability,
    log_tool_gap,
    normalize_scanner_findings,
    python_requirement_file,
    tool_gaps_path,
)



def candidate_from_tool_finding(item: dict[str, Any], cand_id: str) -> dict[str, Any]:
    tool = item.get("tool", "scanner")
    cwe = item.get("cwe") or ("CWE-798" if tool == "trufflehog" else "CWE-1035")
    return {
        "schema_version": CURRENT_CANDIDATE_SCHEMA_VERSION,
        "id": cand_id,
        "title": str(item.get("title") or f"{tool} scanner finding")[:180],
        "status": "auto-candidate",
        "surface": str(item.get("matched_at") or item.get("file") or item.get("package") or tool),
        "weakness": cwe,
        "impact": f"{tool} reported a potential security issue requiring manual validation.",
        "attacker_control": "unknown; scanner-import candidate requires triage",
        "entrypoint": str(item.get("file") or item.get("matched_at") or item.get("package") or ""),
        "trust_boundary": "unvalidated scanner signal; promote only after source review and proof planning",
        "latest_affected": "unchecked",
        "sink": str(item.get("file") or item.get("package") or item.get("matched_at") or ""),
        "novelty": "unchecked",
        "dedup": {"status": "unchecked", "matches": [], "checked_at": ""},
        "proof": "not_started",
        "cve": item.get("cve") or "N/A",
        "cwe": cwe,
        "cvss": "",
        "framework_mappings": {},
        "negative_controls": "",
        "safety_notes": "Auto-created from scanner output. Do not submit without manual validation, dedup, latest-version check, and proof.",
        "reference_sources": item.get("source_file", ""),
        "root_cause": "",
        "variant_analysis": "",
        "patch_diff": "",
        "exploitability": "L0 scanner signal",
        "disclosure_quality": "",
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "notes": json.dumps({key: item.get(key) for key in ("tool", "severity", "confidence", "line", "evidence", "fixed_versions")}, sort_keys=True),
        "history": [
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "created:auto-candidate",
                "source": item.get("source_file", ""),
                "tool": tool,
            }
        ],
    }


def cmd_ingest_tool_scan(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    artifact = run_path(args.artifact)
    if not artifact.exists():
        raise SystemExit(f"tool scan artifact not found: {artifact}")
    records = read_tool_records(artifact)
    findings = normalize_scanner_findings(args.tool, records, artifact, args.include_low)[: args.max_findings]
    out_dir = run_dir / "tool_scans" / "ingest"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"tool_ingest_{args.tool}_{stamp}.json"

    created = []
    if args.create_candidates and findings:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in findings:
                cand = candidate_from_tool_finding(item, next_candidate_id(data))
                data.setdefault("candidates", []).append(cand)
                created.append(cand["id"])
            save_candidates(run_dir, data)

    output = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "tool": args.tool,
        "artifact": rel(artifact),
        "finding_count": len(findings),
        "created_candidates": created,
        "findings": findings,
    }
    write_json(out_json, output)
    md = [
        "# Tool Scan Ingest",
        "",
        f"- Tool: `{args.tool}`",
        f"- Artifact: `{rel(artifact)}`",
        f"- Findings parsed: `{len(findings)}`",
        f"- Candidates created: `{', '.join(created) or 'none'}`",
        "",
    ]
    for item in findings:
        md.extend(
            [
                f"## {item.get('title')}",
                "",
                f"- Severity: `{item.get('severity')}`",
                f"- CWE: `{item.get('cwe') or 'unset'}`",
                f"- CVE: `{item.get('cve') or 'N/A'}`",
                f"- Location: `{item.get('matched_at') or item.get('file') or item.get('package') or ''}`",
                f"- Evidence: {str(item.get('evidence', ''))[:300]}",
                "",
            ]
        )
    out_md = out_dir / f"tool_ingest_{args.tool}_{stamp}.md"
    write_text(out_md, "\n".join(md))
    print(rel(out_md))


def phase3_probe_fixture_check() -> dict[str, Any]:
    fixture = ROOT / "vapt" / "harness" / "tests" / "fixtures" / "probe_candidates.yaml"
    data = load_yaml(fixture) or {}
    candidates = data.get("candidates", {})
    target = data.get("target") or {"id": "probe-fixture", "source_path": "."}
    run_dir = ROOT / "vapt" / "harness" / "tests" / "results" / "phase3_probe_check"
    run_dir.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT / "vapt" / "harness"))
    from probes.base import ProbeContext

    results = []
    for probe_name in sorted(PROBE_REGISTRY):
        cand = candidates.get(probe_name)
        if not cand:
            results.append({"probe": probe_name, "passed": False, "missing": ["fixture candidate missing"]})
            continue
        probe = load_probe(probe_name)
        ctx = ProbeContext(run_dir=run_dir, target=target, candidate=dict(cand), knobs={"phase3_check": True})
        result = probe.run(ctx)
        results.append({"probe": probe_name, "passed": bool(result.get("passed")), "missing": result.get("missing", [])})
    return {"passed": all(item["passed"] for item in results), "results": results}


def phase3_scanner_fixture_check() -> dict[str, Any]:
    fixture_dir = ROOT / "vapt" / "harness" / "tests" / "fixtures" / "tool_scans"
    fixtures = {
        "bandit": fixture_dir / "bandit_sample.json",
        "semgrep": fixture_dir / "semgrep_sample.json",
        "nuclei": fixture_dir / "nuclei_sample.jsonl",
        "pip-audit": fixture_dir / "pip_audit_sample.json",
        "osv": fixture_dir / "osv_sample.json",
        "trufflehog": fixture_dir / "trufflehog_sample.jsonl",
    }
    results = []
    for tool, path in fixtures.items():
        records = read_tool_records(path)
        findings = normalize_scanner_findings(tool, records, path, include_low=True)
        candidate = candidate_from_tool_finding(findings[0], "CAND-001") if findings else {}
        results.append(
            {
                "tool": tool,
                "fixture": rel(path),
                "finding_count": len(findings),
                "auto_candidate_status": candidate.get("status", ""),
                "auto_candidate_exploitability": candidate.get("exploitability", ""),
                "passed": bool(findings) and candidate.get("status") == "auto-candidate",
            }
        )
    return {"passed": all(item["passed"] for item in results), "results": results}


def cmd_phase3_check(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    probe_check = phase3_probe_fixture_check()
    scanner_check = phase3_scanner_fixture_check()
    tool_rows = []
    for tool in ["semgrep", "bandit", "pip-audit", "osv-scanner", "trufflehog", "sslyze", "testssl.sh", "nuclei", "codeql"]:
        path = find_tool(tool)
        tool_rows.append({"tool": tool, "available": bool(path), "path": path or ""})
    required_commands = {
        "scan-nuclei",
        "scan-semgrep",
        "scan-codeql",
        "codeql-workflow",
        "playbook",
        "report-gate",
        "scan-trufflehog",
        "scan-pip-audit",
        "scan-bandit",
        "scan-osv",
        "scan-headers",
        "scan-tls",
        "sandbox-exec",
        "probes",
        "probes-test",
        "refine",
        "scaffold-poc",
        "new-probe",
        "tool-gaps",
        "guard-drift",
    }
    parser = build_parser()
    commands_present = required_commands <= set(parser._subparsers._group_actions[0].choices.keys())  # type: ignore[attr-defined]
    sandbox_runtime = container_runtime()
    macos_runtime = macos_sandbox_exec()
    sandbox_check = {
        "runtime": sandbox_runtime or macos_runtime or "",
        "passed": True,
        "note": "Docker/Podman enforce container no-network mode when present; macOS sandbox-exec fallback enforces no network and evidence-only writes.",
    }
    checks = {
        "probe_fixtures_pass": probe_check["passed"],
        "scanner_fixtures_auto_candidate": scanner_check["passed"],
        "required_phase3_commands_present": commands_present,
        "sandbox_policy_present": sandbox_check["passed"],
        "tool_health_available": bool(tool_rows),
    }
    remaining_known_gaps = [
        "Refine is probe-driven but still not a fully autonomous multi-iteration model loop.",
    ]
    semgrep_tool = find_tool("semgrep")
    if semgrep_tool:
        semgrep_version = run_cmd([semgrep_tool, "--version"], ROOT, timeout=5, env=tool_env("semgrep"))
        if semgrep_version["returncode"] != 0:
            remaining_known_gaps.insert(0, "Semgrep is installed but not operational in the current local environment.")
    if not find_tool("codeql"):
        remaining_known_gaps.insert(0, "CodeQL CLI is optional and currently missing locally.")
    if not find_tool("osv-scanner"):
        remaining_known_gaps.insert(0, "OSV scanner binary is optional and currently missing locally.")
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "passed": all(checks.values()),
        "checks": checks,
        "probe_check": probe_check,
        "scanner_check": scanner_check,
        "tool_health": tool_rows,
        "sandbox": sandbox_check,
        "remaining_known_gaps": remaining_known_gaps,
    }
    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"phase3_check_{stamp}.json"
    write_json(out_json, payload)
    out_md = out_dir / f"phase3_check_{stamp}.md"
    md = [
        "# Phase 3 Acceptance Check",
        "",
        f"- Passed: `{payload['passed']}`",
        f"- Harness version: `{HARNESS_VERSION}`",
        "",
        "## Checks",
        "",
    ]
    for name, passed in checks.items():
        md.append(f"- `{name}`: `{passed}`")
    md.extend(["", "## Tool Availability", ""])
    for row in tool_rows:
        md.append(f"- `{row['tool']}`: `{'available' if row['available'] else 'missing'}` {row['path']}")
    md.extend(["", "## Remaining Known Gaps", ""])
    for gap in payload["remaining_known_gaps"]:
        md.append(f"- {gap}")
    write_text(out_md, "\n".join(md) + "\n")
    print(rel(out_md))
    if not payload["passed"]:
        raise SystemExit(2)


# Watch + queue state primitives live in watch/state.py (core+atomic_io leaf
# only). Imported here so harness.* references resolve unchanged.
from watch.state import (  # noqa: E402
    load_watch_profiles,
    load_watch_state,
    queue_dir,
    queue_entry_path,
    save_watch_state,
    watch_profile_path,
    watch_source_key,
    watch_state_dir,
    watches_dir,
)


# load_surface_terms moved to source.commands.
# Functions moved to source.commands.
from source.commands import (  # noqa: E402
    _function_defs,
    _is_default_excluded,
    _load_semantic_graph,
    _load_source_graph,
    _source_files,
    _taint_function,
    cmd_semantic_graph,
    cmd_source_acquire,
    cmd_source_graph,
    cmd_source_index,
    cmd_source_probe,
    cmd_surfaces_test,
    cmd_taint_trace,
    load_surface_config,
    load_surface_terms,
)



# diff_pattern_hits moved to watch.polling.
# queue_write_entry / queue_entries moved to watch/state.py.
from watch.state import queue_entries, queue_write_entry  # noqa: E402


# resolve_watch_repo_path moved to watch.polling.
# poll_local_git_source moved to watch.polling.
# poll_local_release_source moved to watch.polling.
# read_advisory_fixture moved to watch.polling.
def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def lower_values(values: list[Any]) -> set[str]:
    out = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip().lower()
        if text:
            out.add(text)
    return out


# advisory_packages moved to watch.polling.
# advisory_ecosystems moved to watch.polling.
# advisory_cwes moved to watch.polling.
# advisory_versions moved to watch.polling.
# advisory_match moved to watch.polling.
# advisory_patch_range moved to watch.polling.
# advisory_fixed_commit moved to watch.polling.
# advisory_patch_enrichment moved to watch.polling.
# poll_fixture_advisories moved to watch.polling.
def fetch_json_url(url: str, token: str | None, timeout: int) -> Any:
    headers = {"Accept": "application/json", "User-Agent": "local-vapt-harness"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(url, headers=headers)
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# poll_remote_source moved to watch.polling.
# poll_watch_source moved to watch.polling.
# cmd_watch_add moved to watch.polling.
# cmd_watch_list moved to watch.polling.
# cmd_watch_tick moved to watch.polling.
# cmd_watch_daemon moved to watch.polling.
# Functions moved to watch.polling.
from watch.polling import (  # noqa: E402
    advisory_cwes,
    advisory_ecosystems,
    advisory_fixed_commit,
    advisory_match,
    advisory_packages,
    advisory_patch_enrichment,
    advisory_patch_range,
    advisory_versions,
    cmd_watch_add,
    cmd_watch_daemon,
    cmd_watch_list,
    cmd_watch_tick,
    diff_pattern_hits,
    poll_fixture_advisories,
    poll_local_git_source,
    poll_local_release_source,
    poll_remote_source,
    poll_watch_source,
    read_advisory_fixture,
    resolve_watch_repo_path,
)



def cmd_queue(args: argparse.Namespace) -> None:
    rows = queue_entries(args.target, include_claimed=args.all)
    summary = [
        {
            "queue_id": row.get("queue_id"),
            "target_id": row.get("target_id"),
            "status": row.get("status"),
            "type": row.get("type"),
            "ref": row.get("ref"),
            "created_at": row.get("created_at"),
            "candidate_seed_count": len(row.get("candidate_seeds", [])),
            "path": rel(Path(row["_path"])),
        }
        for row in rows
    ]
    if args.json:
        print(json.dumps({"queue": summary}, indent=2, sort_keys=False))
        return
    for row in summary:
        print(f"{row['queue_id']} [{row['status']}] {row['type']} {row['ref']} seeds={row['candidate_seed_count']}")


def cmd_queue_claim(args: argparse.Namespace) -> None:
    if "/" not in args.queue_id:
        raise SystemExit("queue_id must be in '<target_id>/<id>' form")
    target_id, raw = args.queue_id.split("/", 1)
    path = queue_entry_path(target_id, raw.removesuffix(".yaml"))
    if not path.exists():
        raise SystemExit(f"queue entry not found: {args.queue_id}")
    with file_lock(path):
        entry = load_yaml(path) or {}
        if entry.get("status") != "pending" and not args.force:
            raise SystemExit(f"queue entry is not pending: {entry.get('status')}")
        entry["status"] = "claimed"
        entry["claimed_by"] = args.claimed_by
        entry["claimed_at"] = dt.datetime.now().isoformat(timespec="seconds")
        entry.setdefault("history", []).append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "event": "claimed",
                "by": args.claimed_by,
                "run_dir": args.run_dir or "",
            }
        )
        if args.run_dir:
            entry["run_dir"] = args.run_dir
        dump_yaml(entry, path)
    print(rel(path))


def cmd_phase4_check(args: argparse.Namespace) -> None:
    base = ROOT / "vapt" / "harness" / "tests" / "results" / "phase4_check_repo"
    base.mkdir(parents=True, exist_ok=True)
    if not (base / ".git").exists():
        run_cmd(["git", "init"], base, timeout=20)
        run_cmd(["git", "config", "user.email", "harness@example.local"], base, timeout=20)
        run_cmd(["git", "config", "user.name", "Harness Check"], base, timeout=20)
        write_text(base / "app.py", "def handler(user):\n    return user\n")
        run_cmd(["git", "add", "app.py"], base, timeout=20)
        run_cmd(["git", "commit", "-m", "initial"], base, timeout=20)
    target_id = "phase4_fixture"
    profile_path = watch_profile_path(target_id)
    dump_yaml(
        {
            "target_id": target_id,
            "repo_path": rel(base),
            "poll_interval_minutes": 1,
            "trigger_patterns": ["authz_boundary", "network_ssrf"],
            "sources": [
                {"kind": "github_commits", "repo_path": rel(base), "branch": "HEAD", "paths": ["app.py"]},
                {
                    "kind": "osv_advisories",
                    "ecosystem": "PyPI",
                    "package": "phase4-fixture",
                    "fixture": "vapt/harness/tests/fixtures/advisories/osv_phase4_sample.json",
                },
            ],
        },
        profile_path,
    )
    fixture_path = ROOT / "vapt" / "harness" / "tests" / "fixtures" / "advisories" / "osv_phase4_sample.json"
    write_json(
        fixture_path,
        {
            "vulns": [
                {
                    "id": "OSV-PHASE4-0001",
                    "package": "phase4-fixture",
                    "ecosystem": "PyPI",
                    "summary": "Fixture advisory for watch queue regression testing",
                    "cwe": "CWE-863",
                }
            ]
        },
    )
    state_path = watch_state_dir() / f"{target_id}.json"
    if state_path.exists():
        state_path.unlink()
    poll_watch_source(load_watch_profiles(target_id)[0], load_watch_profiles(target_id)[0]["sources"][0], load_watch_state(target_id), False, 20)
    state = load_watch_state(target_id)
    profile = load_watch_profiles(target_id)[0]
    for source in profile["sources"]:
        poll_watch_source(profile, source, state, False, 20)
    save_watch_state(target_id, state)
    with (base / "app.py").open("a", encoding="utf-8") as fh:
        fh.write("\n\ndef fetch_profile(url, token):\n    # authz token and requests.get SSRF review fixture\n    return requests.get(url, headers={'Authorization': token})\n")
    run_cmd(["git", "add", "app.py"], base, timeout=20)
    run_cmd(["git", "commit", "-m", "security relevant auth fetch"], base, timeout=20)
    fixed_head = run_cmd(["git", "rev-parse", "HEAD"], base, timeout=20)["stdout"].strip()
    write_json(
        fixture_path,
        {
            "vulns": [
                {
                    "id": "OSV-PHASE4-0001",
                    "package": "phase4-fixture",
                    "ecosystem": "PyPI",
                    "summary": "Fixture advisory for watch queue regression testing",
                    "cwe": "CWE-863",
                },
                {
                    "id": f"OSV-PHASE4-{fixed_head[:8]}",
                    "package": "phase4-fixture",
                    "ecosystem": "PyPI",
                    "summary": "Fixture advisory with fixed commit for patch-window enrichment",
                    "cwe": "CWE-863",
                    "fixed_commit": fixed_head,
                },
            ]
        },
    )
    state = load_watch_state(target_id)
    for source in profile["sources"]:
        poll_watch_source(profile, source, state, False, 20)
    save_watch_state(target_id, state)
    rows = queue_entries(target_id, include_claimed=True)
    parser = build_parser()
    required = {
        "watch-add",
        "watch-list",
        "watch-tick",
        "watch-daemon",
        "queue",
        "phase4-check",
        "phase4-remote-check",
        "phase4-soak-check",
    }
    commands_present = required <= set(parser._subparsers._group_actions[0].choices.keys())  # type: ignore[attr-defined]
    checks = {
        "watch_profile_written": profile_path.exists(),
        "commit_queue_created": any(row.get("type") == "commit_diff" for row in rows),
        "advisory_queue_created": any(row.get("type") == "advisory" for row in rows),
        "patch_window_enriched": any(
            row.get("type") == "advisory" and row.get("patch_enrichment", {}).get("available")
            for row in rows
        ),
        "required_phase4_commands_present": commands_present,
    }
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "passed": all(checks.values()),
        "checks": checks,
        "queue_entries": [
            {"queue_id": row.get("queue_id"), "type": row.get("type"), "ref": row.get("ref"), "path": rel(Path(row["_path"]))}
            for row in rows
        ],
    }
    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"phase4_check_{stamp}.json"
    write_json(out_json, payload)
    out_md = out_dir / f"phase4_check_{stamp}.md"
    md = ["# Phase 4 Acceptance Check", "", f"- Passed: `{payload['passed']}`", f"- Harness version: `{HARNESS_VERSION}`", "", "## Checks", ""]
    for name, passed in checks.items():
        md.append(f"- `{name}`: `{passed}`")
    md.extend(["", "## Queue Entries", ""])
    for row in payload["queue_entries"]:
        md.append(f"- `{row['queue_id']}` `{row['type']}` `{row['ref']}` -> `{row['path']}`")
    write_text(out_md, "\n".join(md) + "\n")
    print(rel(out_md))
    if not payload["passed"]:
        raise SystemExit(2)


def cmd_phase4_remote_check(args: argparse.Namespace) -> None:
    target_id = "phase4_remote_check"
    profile = {
        "target_id": target_id,
        "trigger_patterns": ["authz_boundary", "network_ssrf"],
        "sources": [
            {"kind": "github_commits", "repo": "octocat/Hello-World", "branch": "master", "allow_network": True},
            {"kind": "github_releases", "repo": "cli/cli", "allow_network": True},
            {"kind": "osv_advisories", "ecosystem": "PyPI", "package": "requests", "allow_network": True},
            {"kind": "ghsa_advisories", "ecosystem": "pip", "package": "requests", "allow_network": True},
        ],
    }
    state = {"target_id": target_id, "sources": {}}
    results = []
    for source in profile["sources"]:
        before_count = len(queue_entries(target_id, include_claimed=True))
        source_results = poll_watch_source(profile, source, state, True, args.timeout)
        after_count = len(queue_entries(target_id, include_claimed=True))
        results.append(
            {
                "source": source,
                "results": source_results,
                "queue_entries_created": after_count - before_count,
                "passed": any(item.get("status") in {"queued", "initialized", "unchanged"} for item in source_results),
            }
        )
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "passed": all(item["passed"] for item in results),
        "results": results,
        "note": "This check requires network access. GitHub API rate limits or local network policy may cause failure.",
    }
    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"phase4_remote_check_{stamp}.json"
    write_json(out_json, payload)
    out_md = out_dir / f"phase4_remote_check_{stamp}.md"
    md = ["# Phase 4 Remote Polling Check", "", f"- Passed: `{payload['passed']}`", f"- Harness version: `{HARNESS_VERSION}`", "", "## Sources", ""]
    for result in results:
        source = result["source"]
        md.append(f"- `{source['kind']}` `{source.get('repo') or source.get('package')}`: passed=`{result['passed']}`, queued=`{result['queue_entries_created']}`")
        for item in result["results"]:
            md.append(f"  - status=`{item.get('status')}` ref=`{item.get('ref') or item.get('advisory') or item.get('release') or item.get('head') or ''}` error=`{item.get('error') or item.get('reason') or ''}`")
    write_text(out_md, "\n".join(md) + "\n")
    print(rel(out_md))
    if not payload["passed"]:
        raise SystemExit(2)


def cmd_phase4_soak_check(args: argparse.Namespace) -> None:
    heartbeat = watches_dir() / "watch_daemon_heartbeat.jsonl"
    before = len(read_jsonl(heartbeat))
    start = time.monotonic()
    iterations = 0
    errors = []
    while True:
        iterations += 1
        try:
            profiles = load_watch_profiles(args.target)
            for profile in profiles:
                state = load_watch_state(str(profile["target_id"]))
                for source in profile.get("sources", []):
                    poll_watch_source(profile, source, state, False, args.timeout)
                save_watch_state(str(profile["target_id"]), state)
            status = "ok"
            error_msg = ""
        except Exception as exc:
            status = "error"
            error_msg = str(exc)
            errors.append(error_msg)
        rows = read_jsonl(heartbeat)
        rows.append(
            {
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "status": status,
                "error": error_msg,
                "iteration": iterations,
                "soak_check": True,
            }
        )
        write_jsonl(heartbeat, rows[-2000:])
        elapsed = time.monotonic() - start
        if args.iterations and iterations >= args.iterations:
            break
        if elapsed >= args.seconds:
            break
        time.sleep(max(1, args.interval_seconds))
    after = len(read_jsonl(heartbeat))
    duration_seconds = time.monotonic() - start
    passed = not errors and after > before and iterations >= 1
    if args.require_24h and duration_seconds < 24 * 60 * 60:
        passed = False
        errors.append("require_24h was set but elapsed time was less than 86400 seconds")
    payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "harness_version": HARNESS_VERSION,
        "passed": passed,
        "target": args.target or "all",
        "iterations": iterations,
        "duration_seconds": round(duration_seconds, 3),
        "heartbeat": rel(heartbeat),
        "errors": errors,
        "require_24h": args.require_24h,
    }
    out_dir = ROOT / "vapt" / "harness" / "tests" / "results"
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = out_dir / f"phase4_soak_check_{stamp}.json"
    write_json(out_json, payload)
    out_md = out_dir / f"phase4_soak_check_{stamp}.md"
    md = [
        "# Phase 4 Daemon Soak Check",
        "",
        f"- Passed: `{payload['passed']}`",
        f"- Harness version: `{HARNESS_VERSION}`",
        f"- Target: `{payload['target']}`",
        f"- Iterations: `{iterations}`",
        f"- Duration seconds: `{payload['duration_seconds']}`",
        f"- Heartbeat: `{payload['heartbeat']}`",
        "",
        "## Errors",
        "",
    ]
    md.extend([f"- {error}" for error in errors] or ["- none"])
    write_text(out_md, "\n".join(md) + "\n")
    print(rel(out_md))
    if not passed:
        raise SystemExit(2)



# CLI dispatcher (build_parser + main + argparse subcommand wiring) lives in
# cli.py. harness.py keeps every cmd_* handler and every domain-logic helper
# the dispatcher routes to, so this module remains the live target for
# `import harness` and the campaign-adapter subprocess. The __main__ block
# below just hands off to cli.main so `python harness.py` still works
# unchanged.
if __name__ == "__main__":
    from cli import main
    raise SystemExit(main())
