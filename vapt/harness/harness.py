#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
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


# run_cmd moved to helpers.
# rel/run_path/source_path/now_id are imported from core (above).


# load_run moved to helpers.
# save_stage moved to helpers.
# cmd_init moved to commands_lifecycle.
# cmd_prepare moved to commands_lifecycle.
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


# artifact_exists moved to helpers.
# candidate_reference_text moved to ledger.workflow.
# duplicate_source_coverage moved to helpers.
# dedup_checked/workflow_blockers imported from gates.promotion (above).


# load_surface_config moved to source.commands.
# cmd_map moved to commands_lifecycle.
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


# queue_entry_by_id moved to helpers.
# first_valid_cwe moved to helpers.
# queue_entry_cwe moved to helpers.
# queue_entry_references moved to helpers.
# candidate_from_queue_entry moved to ledger.workflow.
# next_candidate_id moved to ledger/candidates.py.
from ledger.candidates import next_candidate_id  # noqa: E402


# cmd_candidate_add moved to ledger.workflow.
# cmd_candidate_from_queue moved to ledger.workflow.
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


# cmd_dedup moved to ledger.workflow.
# promotion_findings, candidate_requires_queue_gate, queue_evidence_findings,
# candidate_requires_campaign_gate, campaign_evidence_findings imported from
# gates.promotion (above).


# report_readiness_findings moved to helpers.
# cmd_report_gate moved to ledger.workflow.
# cmd_gate moved to ledger.workflow.
# find_candidate / update_candidate_locked moved to ledger/candidates.py.
from ledger.candidates import find_candidate, update_candidate_locked  # noqa: E402


# cmd_candidate_link_campaign moved to campaign/commands.py.
# _campaign_start_markdown moved to campaign/commands.py.
# _campaign_next_commands_markdown moved to campaign/commands.py.
# _write_campaign_start_plan_files moved to campaign/commands.py.
# _github_repo_from_url moved to helpers.
# _campaign_refresh_package_metadata moved to campaign/commands.py.
# _ghsa_ecosystem moved to helpers.
# _campaign_refresh_sources moved to campaign/commands.py.
# _campaign_advisory_refresh_markdown moved to campaign/commands.py.
# _run_campaign_advisory_refresh moved to campaign/commands.py.
# cmd_campaign_start moved to campaign/commands.py.
# _campaign_flow_check_markdown moved to campaign/commands.py.
# _flow_args moved to helpers.
# cmd_campaign_flow_check moved to campaign/commands.py.
# cmd_outcome_tune_check moved to checks.
# cmd_candidate_set moved to ledger.workflow.
# cmd_candidates moved to ledger.workflow.
# cmd_prove moved to ledger.workflow.
# COMMON_VARIANT_TERMS moved to gates/osv.py (imported at the OSV re-export block above).


# _candidate_variant_patterns moved to ledger.workflow.
# cmd_variant moved to ledger.workflow.
# cmd_patch_diff moved to ledger.workflow.
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

# PATTERNS / GRAPH_QUERIES default to the in-file dicts above. Operators can
# override them through the surface config consumed by
# source.commands.load_surface_config. The override is applied below, AFTER
# every helper module is imported, so source.commands is fully loadable by
# the time we reach back into it.
_PATTERNS_LOADED = False


def _apply_surface_config_override() -> None:
    global PATTERNS, GRAPH_QUERIES, _PATTERNS_LOADED
    if _PATTERNS_LOADED:
        return
    from source.commands import load_surface_config
    PATTERNS, GRAPH_QUERIES = load_surface_config()
    _PATTERNS_LOADED = True


# cmd_source_graph moved to source.commands.
# _load_latest_variant_yaml moved to helpers.
# _hit_file moved to helpers.
# _hit_symbol moved to helpers.
# cmd_cluster_variants moved to ledger.workflow.
# _intent_tokens moved to helpers.
# _candidate_intent_match moved to ledger.workflow.
# _score_candidate moved to ledger.workflow.
# _quality_band moved to helpers.
# cmd_score moved to commands_lifecycle.
# _load_source_graph moved to source.commands.
# _top_files moved to helpers.
# _build_hypotheses moved to helpers.
# _order_hypotheses_by_intent moved to helpers.
# cmd_hypothesize moved to ledger.workflow.
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


# cmd_patch_mine moved to ledger.workflow.
# cmd_proof_plan moved to ledger.workflow.
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
# _calls_in_body moved to helpers.
# _semantic_categories moved to helpers.
# cmd_semantic_graph moved to source.commands.
# _load_semantic_graph moved to source.commands.
# _terms_from_candidate moved to ledger.workflow.
# _function_for_hit moved to helpers.
# cmd_flow_trace moved to ledger.workflow.
# cmd_test_skeleton moved to commands_lifecycle.
# cmd_ledger_sqlite moved to commands_auxiliary.
# _candidate_from_blackbox moved to ledger.workflow.
# _parse_blackbox_json moved to helpers.
# _parse_blackbox_text moved to helpers.
# cmd_ingest_blackbox_run moved to ledger.workflow.
TAINT_SOURCE_RE = r"(\br\b\.(URL|Body|Header|Form|PostForm)|c\.Params|request\.(args|form|json|headers|cookies|body)|req\.(body|query|params|headers|cookies)|URL\.Query|FormValue|Query\(|\b(argv|args|input|param|params|query|body|url)\b)"
# "Strong" sources unambiguously denote externally-controlled request data. The
# bare-name tokens (argv/args/input/param/params/query/body/url) in the full
# source regex are "weak": a local variable that happens to be named `params`
# is not request data. STRONG_SOURCE_RE is used for the same-line source check so
# a shadowed local does not register as a source reaching the sink.
STRONG_SOURCE_RE = r"(\br\b\.(URL|Body|Header|Form|PostForm)|c\.Params|request\.(args|form|json|headers|cookies|body)|req\.(body|query|params|headers|cookies)|URL\.Query|FormValue|Query\()"
WEAK_SOURCE_NAMES = {"argv", "args", "input", "param", "params", "query", "body", "url"}
TAINT_ASSIGN_RE = re.compile(r"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)")


# _function_body moved to helpers.
# Guards that constrain a tainted value before it reaches a sink. When a flow is
# guarded the value is no longer attacker-controlled in the dangerous position, so
# the flow is annotated and downranked rather than dropped (recall is preserved —
# the guard heuristic can be wrong, so true positives must stay in the report).
GUARD_WHITELIST_RE = re.compile(
    r"(\.include\?\(|\.member\?\(|%i\[|%w\[|allow_?list|white_?list|ALLOWED_|PERMITTED|\.to_sym\b)"
)


# _flow_guard moved to helpers.
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


# _active_code_lines moved to helpers.
# _line_hits moved to helpers.
# _guard_drift_functions moved to helpers.
# _sibling_guarded_examples moved to helpers.
# _guard_drift_candidate moved to helpers.
# cmd_guard_drift moved to ledger.workflow.
# cmd_report moved to commands_lifecycle.
# cmd_reference_add moved to commands_lifecycle.
# cmd_dashboard moved to commands_lifecycle.
# cmd_status moved to commands_lifecycle.
# _parse_time moved to core.py (leaf datetime utility).
from core import _parse_time  # noqa: E402


# _run_elapsed_minutes moved to helpers.
# budget_status moved to helpers.
# _latest_artifact moved to helpers.
# recommend_next_action moved to ledger.workflow.
# cmd_next_action moved to ledger.workflow.
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


# _recommendation_verb moved to helpers.
# _recommendation_signature moved to helpers.
# _loop_state moved to helpers.
# _required_result moved to helpers.
# _step_gate moved to helpers.
# _build_step moved to helpers.
# _load_cursor moved to helpers.
# _persist_cursor moved to helpers.
# cmd_orient moved to ledger.workflow.
# cmd_submit moved to ledger.workflow.
# cmd_intent_set moved to commands_lifecycle.
# cmd_intent_show moved to commands_lifecycle.
# _loop_integrity_violations moved to helpers.
# cmd_intent_ordering_check moved to checks.
# cmd_loop_integrity_check moved to checks.
# cmd_budget moved to commands_lifecycle.
# _candidate_summary moved to ledger.workflow.
# cmd_session_start moved to commands_lifecycle.
# _knowledge_files moved to helpers.
# _rank_text moved to helpers.
# cmd_knowledge moved to commands_lifecycle.
# _command_help moved to helpers.
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


# cmd_explain moved to commands_lifecycle.
# cmd_commands moved to commands_lifecycle.
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


# _synthetic_status_for moved to helpers.
# _synthetic_module_for moved to helpers.
# _synthetic_evidence_kind moved to helpers.
# cmd_osv_cache_stats moved to commands_auxiliary.
# cmd_osv_cache_prefetch moved to commands_auxiliary.
# cmd_osv_cache_clear moved to commands_auxiliary.
# cmd_source_acquire moved to source.commands.
# cmd_source_index moved to source.commands.
# cmd_source_probe moved to source.commands.
# _load_watch_module moved to helpers.
# _discovery_queue_dir moved to helpers.
# cmd_discovery_sweep moved to commands_auxiliary.
# cmd_discovery_list moved to commands_auxiliary.
# cmd_discovery_claim moved to commands_auxiliary.
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

# _candidate_signal moved to ledger.workflow.
# cmd_retro moved to commands_lifecycle.
# Target profile lookup moved to source/targets.py.
from source.targets import _load_target_profile, _target_profile_paths  # noqa: E402


# _term_set moved to ledger.workflow.
# cmd_corpus_suggest moved to commands_auxiliary.
# cmd_pick_target moved to commands_auxiliary.
MODULE_ALIASES = {
    "authz": "authz_matrix",
    "ssrf_proxy": "ssrf_callback",
}


# campaign_module_catalog_path / load_campaign_modules moved to campaign/context.py.
from campaign.context import campaign_module_catalog_path, load_campaign_modules  # noqa: E402


# _target_bb_root moved to helpers.
# _target_profile_by_arg moved to helpers.
# _module_key moved to helpers.
# _module_artifact_key moved to helpers.
# _campaign_history moved to campaign/commands.py.
# _module_status moved to helpers.
# _score_campaign_module moved to campaign/commands.py.
# _campaign_plan_markdown moved to campaign/commands.py.
# cmd_campaign_plan moved to campaign/commands.py.
# module_contract_path moved to helpers.
# _adapter_manifest_paths moved to helpers.
# _path_within moved to helpers.
# _adapter_check_one moved to helpers.
# _campaign_adapter_check_markdown moved to campaign/commands.py.
# cmd_campaign_adapter_check moved to campaign/commands.py.
# mutation_catalog_path moved to mutation.
# load_mutation_catalog moved to mutation.
# _load_target_adapter moved to helpers.
# _mutation_plan_markdown moved to mutation.
# cmd_mutation_plan moved to commands_auxiliary.
# _mutation_artifact_paths moved to mutation.
# _mutation_int moved to mutation.
# _validate_mutation_block moved to mutation.
# _validate_mutation_artifact moved to mutation.
# _mutation_coverage_check_markdown moved to mutation.
# Functions moved to mutation.
from mutation import (  # noqa: E402
    _mutation_artifact_paths,
    _mutation_coverage_check_markdown,
    _mutation_int,
    _mutation_plan_markdown,
    _validate_mutation_artifact,
    _validate_mutation_block,
    load_mutation_catalog,
    mutation_catalog_path,
)



# cmd_mutation_coverage_check moved to checks.
# _git_ref_exists moved to helpers.
# _previous_tag moved to helpers.
# _patch_first_markdown moved to helpers.
# cmd_patch_first_plan moved to commands_auxiliary.
# _next_action_for_module moved to helpers.
# _campaign_dashboard_markdown moved to campaign/commands.py.
# cmd_campaign_dashboard moved to campaign/commands.py.
class _TemplateContext(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(f"unknown adapter command template variable: {key}")


# _render_adapter_value moved to helpers.
# _load_adapter_from_args moved to helpers.
# _campaign_run_markdown moved to campaign/commands.py.
# cmd_campaign_run moved to campaign/commands.py.
# _artifact_path_from_record moved to helpers.
# _path_is_under moved to helpers.
# _campaign_gate_markdown moved to campaign/commands.py.
# _gate_check moved to helpers.
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



# cmd_score_tune moved to ledger.workflow.
# phase2_surface_regression moved to helpers.
# phase2_suggestion_count moved to helpers.
# phase2_fixture_submission_stats moved to helpers.
# cmd_phase2_check moved to checks.
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
# select_probe moved to helpers.
# load_probe moved to helpers.
# cmd_probes moved to commands_lifecycle.
# cmd_probes_test moved to commands_lifecycle.
# cmd_refine moved to ledger.workflow.
# _infer_playbook_class moved to helpers.
# cmd_playbook moved to commands_lifecycle.
# cmd_codeql_workflow moved to commands_lifecycle.
# _poc_template_body moved to helpers.
# cmd_scaffold_poc moved to commands_lifecycle.
# cmd_new_probe moved to commands_lifecycle.
# Functions moved to commands_lifecycle.
from commands_lifecycle import (  # noqa: E402
    cmd_budget,
    cmd_codeql_workflow,
    cmd_commands,
    cmd_dashboard,
    cmd_explain,
    cmd_init,
    cmd_intent_set,
    cmd_intent_show,
    cmd_knowledge,
    cmd_map,
    cmd_new_probe,
    cmd_playbook,
    cmd_prepare,
    cmd_probes,
    cmd_probes_test,
    cmd_reference_add,
    cmd_report,
    cmd_retro,
    cmd_scaffold_poc,
    cmd_score,
    cmd_session_start,
    cmd_status,
    cmd_test_skeleton,
)



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
# read_tool_records moved to helpers.
# first_cwe moved to helpers.
# first_cve moved to helpers.
# scanner_severity_rank moved to helpers.
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



# candidate_from_tool_finding moved to helpers.
# cmd_ingest_tool_scan moved to ledger.workflow.
# Functions moved to ledger.workflow.
from ledger.workflow import (  # noqa: E402
    _candidate_from_blackbox,
    _candidate_intent_match,
    _candidate_signal,
    _candidate_summary,
    _candidate_variant_patterns,
    _score_candidate,
    _term_set,
    _terms_from_candidate,
    candidate_from_queue_entry,
    candidate_reference_text,
    cmd_candidate_add,
    cmd_candidate_from_queue,
    cmd_candidate_set,
    cmd_candidates,
    cmd_cluster_variants,
    cmd_dedup,
    cmd_flow_trace,
    cmd_gate,
    cmd_guard_drift,
    cmd_hypothesize,
    cmd_ingest_blackbox_run,
    cmd_ingest_tool_scan,
    cmd_next_action,
    cmd_orient,
    cmd_patch_diff,
    cmd_patch_mine,
    cmd_proof_plan,
    cmd_prove,
    cmd_refine,
    cmd_report_gate,
    cmd_score_tune,
    cmd_submit,
    cmd_variant,
    recommend_next_action,
)



# phase3_probe_fixture_check moved to helpers.
# phase3_scanner_fixture_check moved to helpers.
# cmd_phase3_check moved to checks.
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
# as_list moved to helpers.
# lower_values moved to helpers.
# advisory_packages moved to watch.polling.
# advisory_ecosystems moved to watch.polling.
# advisory_cwes moved to watch.polling.
# advisory_versions moved to watch.polling.
# advisory_match moved to watch.polling.
# advisory_patch_range moved to watch.polling.
# advisory_fixed_commit moved to watch.polling.
# advisory_patch_enrichment moved to watch.polling.
# poll_fixture_advisories moved to watch.polling.
# fetch_json_url moved to helpers.
# Functions moved to helpers.
from helpers import (  # noqa: E402
    _active_code_lines,
    _adapter_check_one,
    _adapter_manifest_paths,
    _artifact_path_from_record,
    _build_hypotheses,
    _build_step,
    _calls_in_body,
    _command_help,
    _discovery_queue_dir,
    _flow_args,
    _flow_guard,
    _function_body,
    _function_for_hit,
    _gate_check,
    _ghsa_ecosystem,
    _git_ref_exists,
    _github_repo_from_url,
    _guard_drift_candidate,
    _guard_drift_functions,
    _hit_file,
    _hit_symbol,
    _infer_playbook_class,
    _intent_tokens,
    _knowledge_files,
    _latest_artifact,
    _line_hits,
    _load_adapter_from_args,
    _load_cursor,
    _load_latest_variant_yaml,
    _load_target_adapter,
    _load_watch_module,
    _loop_integrity_violations,
    _loop_state,
    _module_artifact_key,
    _module_key,
    _module_status,
    _next_action_for_module,
    _order_hypotheses_by_intent,
    _parse_blackbox_json,
    _parse_blackbox_text,
    _patch_first_markdown,
    _path_is_under,
    _path_within,
    _persist_cursor,
    _poc_template_body,
    _previous_tag,
    _quality_band,
    _rank_text,
    _recommendation_signature,
    _recommendation_verb,
    _render_adapter_value,
    _required_result,
    _run_elapsed_minutes,
    _semantic_categories,
    _sibling_guarded_examples,
    _step_gate,
    _synthetic_evidence_kind,
    _synthetic_module_for,
    _synthetic_status_for,
    _target_bb_root,
    _target_profile_by_arg,
    _top_files,
    artifact_exists,
    as_list,
    budget_status,
    candidate_from_tool_finding,
    duplicate_source_coverage,
    fetch_json_url,
    first_cve,
    first_cwe,
    first_valid_cwe,
    load_probe,
    load_run,
    lower_values,
    module_contract_path,
    phase2_fixture_submission_stats,
    phase2_suggestion_count,
    phase2_surface_regression,
    phase3_probe_fixture_check,
    phase3_scanner_fixture_check,
    queue_entry_by_id,
    queue_entry_cwe,
    queue_entry_references,
    read_tool_records,
    report_readiness_findings,
    run_cmd,
    save_stage,
    scanner_severity_rank,
    select_probe,
)



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



# cmd_queue moved to commands_auxiliary.
# cmd_queue_claim moved to commands_auxiliary.
# Functions moved to commands_auxiliary.
from commands_auxiliary import (  # noqa: E402
    cmd_corpus_suggest,
    cmd_discovery_claim,
    cmd_discovery_list,
    cmd_discovery_sweep,
    cmd_ledger_sqlite,
    cmd_mutation_plan,
    cmd_osv_cache_clear,
    cmd_osv_cache_prefetch,
    cmd_osv_cache_stats,
    cmd_patch_first_plan,
    cmd_pick_target,
    cmd_queue,
    cmd_queue_claim,
)



# cmd_phase4_check moved to checks.
# cmd_phase4_remote_check moved to checks.
# cmd_phase4_soak_check moved to checks.
# Functions moved to checks.
from checks import (  # noqa: E402
    cmd_intent_ordering_check,
    cmd_loop_integrity_check,
    cmd_mutation_coverage_check,
    cmd_outcome_tune_check,
    cmd_phase2_check,
    cmd_phase3_check,
    cmd_phase4_check,
    cmd_phase4_remote_check,
    cmd_phase4_soak_check,
)




# Now that every helper module is imported and load_run / friends resolve on
# this module, ask source.commands to apply the operator-configured surface
# override (if any) on top of the in-file PATTERNS / GRAPH_QUERIES defaults.
_apply_surface_config_override()


# CLI dispatcher (build_parser + main + argparse subcommand wiring) lives in
# cli.py. harness.py keeps every cmd_* handler and every domain-logic helper
# the dispatcher routes to, so this module remains the live target for
# `import harness` and the campaign-adapter subprocess. The __main__ block
# below just hands off to cli.main so `python harness.py` still works
# unchanged.
if __name__ == "__main__":
    from cli import main
    raise SystemExit(main())
