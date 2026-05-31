"""Remaining utility + workflow helpers. These are the back-end functions the extracted cmd_* modules and probes reach through the harness module's namespace (via the dual sys.modules _h lookup). Grouped together as the last stop on the strangler-fig decomposition before harness.py becomes a thin entrypoint.

The handlers are registered through cli.py via the harness module's namespace, so harness.py re-imports each one.
The `_h` lookup below is the same dual sys.modules pattern cli.py uses.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import shlex
import shutil
import sys
import time
import uuid
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib import error, request

from atomic_io import load_yaml, read_json, read_jsonl, write_json
from campaign.context import find_campaign_context
from core import CURRENT_CANDIDATE_SCHEMA_VERSION, ROOT, _parse_time, candidate_corpus_path, rel, run_path, source_path
from gates.promotion import campaign_evidence_findings, queue_evidence_findings, workflow_blockers
from ledger.candidates import load_candidates
from ledger.submissions import submission_stats
from source.targets import _load_target_profile
from validators import exact_affected_version, substantive, validate_cwe
from watch.state import queue_entry_path


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def run_cmd(cmd: list[str], cwd: Path, timeout: int=30, env: dict[str, str] | None=None) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True, timeout=timeout, check=False)
        return {'cmd': cmd, 'cwd': str(cwd), 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr, 'timeout': False}
    except subprocess.TimeoutExpired as exc:
        return {'cmd': cmd, 'cwd': str(cwd), 'returncode': 124, 'stdout': exc.stdout or '', 'stderr': exc.stderr or '', 'timeout': True}

def load_run(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    state = read_json(run_dir / 'state.json', {})
    target_path = run_dir / 'target.yaml'
    if target_path.exists():
        target = load_yaml(target_path)
    else:
        context = find_campaign_context(run_dir)
        snapshot = run_path(str(context.get('campaign_dir') or '')) / 'target_snapshot.json' if context else None
        if snapshot and snapshot.exists():
            target = read_json(snapshot, {})
            state.setdefault('target_id', target.get('id') or context.get('target_id') or '')
            state.setdefault('run_id', run_dir.name)
        else:
            raise SystemExit(f'target.yaml not found and no campaign target snapshot available: {rel(run_dir)}')
    return (state, target)

def save_stage(run_dir: Path, state: dict[str, Any], stage: str) -> None:
    current = read_json(run_dir / 'state.json', {})
    current.update(state)
    state = current
    state.setdefault('stages', {})[stage] = {'completed_at': dt.datetime.now().isoformat(timespec='seconds')}
    write_json(run_dir / 'state.json', state)

def artifact_exists(rel_path: Any) -> bool:
    if not substantive(rel_path):
        return False
    path = run_path(str(rel_path))
    return path.exists() and path.is_file()

def duplicate_source_coverage(cand: dict[str, Any]) -> dict[str, bool]:
    text = _h.candidate_reference_text(cand)
    return {'cve_or_ghsa': bool(re.search('(cve-\\d{4}-\\d{4,}|ghsa-|github advisory|github security advisory)', text)), 'osv': 'osv' in text, 'huntr': 'huntr' in text, 'github': 'github' in text or 'ghsa' in text}

def queue_entry_by_id(queue_id: str) -> tuple[Path, dict[str, Any]]:
    if '/' not in queue_id:
        raise SystemExit("queue_id must be in '<target_id>/<id>' form")
    target_id, raw = queue_id.split('/', 1)
    path = queue_entry_path(target_id, raw.removesuffix('.yaml'))
    if not path.exists():
        raise SystemExit(f'queue entry not found: {queue_id}')
    entry = load_yaml(path) or {}
    entry['_path'] = path
    return (path, entry)

def first_valid_cwe(*values: Any) -> str:
    for value in values:
        for item in as_list(value):
            text = str(item or '').strip().upper()
            if validate_cwe(text):
                return text
    return ''

def queue_entry_cwe(entry: dict[str, Any], seed: dict[str, Any]) -> str:
    affected = entry.get('affected') if isinstance(entry.get('affected'), dict) else {}
    advisory = entry.get('advisory') if isinstance(entry.get('advisory'), dict) else {}
    db = advisory.get('database_specific') if isinstance(advisory.get('database_specific'), dict) else {}
    return first_valid_cwe(seed.get('cwe'), seed.get('weakness'), affected.get('cwes'), advisory.get('cwe'), advisory.get('cwes'), advisory.get('cwe_ids'), db.get('cwe_ids'), db.get('cwe'))

def queue_entry_references(entry: dict[str, Any]) -> str:
    refs = []
    ref = str(entry.get('ref') or '')
    if ref:
        refs.append(ref)
    advisory = entry.get('advisory') if isinstance(entry.get('advisory'), dict) else {}
    for key in ('id', 'ghsa_id', 'cve'):
        value = advisory.get(key)
        if value:
            refs.extend((str(item) for item in as_list(value)))
    for item in as_list(advisory.get('aliases')):
        refs.append(str(item))
    return ', '.join(sorted(set((item for item in refs if item))))

def report_readiness_findings(cand: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    blockers = workflow_blockers(cand, 'report_ready')
    warnings: list[str] = []
    strict_fields = [('attacker_control', 24), ('entrypoint', 12), ('trust_boundary', 24), ('sink', 12), ('impact', 32), ('root_cause', 32), ('negative_controls', 24), ('variant_analysis', 24), ('patch_diff', 12)]
    for field, min_chars in strict_fields:
        if not _h.substantive_text(cand.get(field), min_chars):
            blockers.append(f'strict:{field}_too_shallow')
    if not exact_affected_version(cand.get('latest_affected')):
        blockers.append('strict:latest_affected_not_exact_version_or_commit')
    if cand.get('proof') != 'passed':
        blockers.append('strict:proof_not_passed')
    last_proof = cand.get('last_proof') if isinstance(cand.get('last_proof'), dict) else {}
    if not last_proof:
        blockers.append('strict:last_proof_missing')
    elif int(last_proof.get('returncode', -1)) != 0:
        blockers.append('strict:last_proof_nonzero')
    else:
        for artifact_key in ('stdout', 'stderr', 'status', 'command_record'):
            if not artifact_exists(last_proof.get(artifact_key)):
                blockers.append(f'strict:last_proof_{artifact_key}_missing')
    coverage = duplicate_source_coverage(cand)
    if not coverage['osv']:
        blockers.append('strict:osv_dedup_missing')
    if not (coverage['cve_or_ghsa'] or coverage['github']):
        blockers.append('strict:cve_ghsa_or_github_reference_missing')
    if not coverage['huntr']:
        warnings.append('huntr_duplicate_reference_missing')
    if str(cand.get('novelty', '')) == 'possible-regression' and (not _h.substantive_text((cand.get('dedup') or {}).get('manual_notes', '') if isinstance(cand.get('dedup'), dict) else '', 24)):
        blockers.append('strict:possible_regression_without_manual_dedup_note')
    campaign_ok, campaign_blockers, campaign_warnings = campaign_evidence_findings(cand)
    if not campaign_ok:
        blockers.extend((f'strict:{item}' for item in campaign_blockers))
    warnings.extend(campaign_warnings)
    queue_ok, queue_blockers, queue_warnings = queue_evidence_findings(cand)
    if not queue_ok:
        blockers.extend((f'strict:{item}' for item in queue_blockers))
    warnings.extend(queue_warnings)
    return (not blockers, sorted(set(blockers)), sorted(set(warnings)))

def _github_repo_from_url(url: str) -> str:
    raw = str(url or '').strip().removesuffix('.git')
    match = re.search('github\\.com[:/]+([^/]+)/([^/#?]+)', raw)
    if not match:
        return ''
    return f'{match.group(1)}/{match.group(2)}'

def _ghsa_ecosystem(ecosystem: str) -> str:
    mapping = {'pypi': 'pip', 'pip': 'pip', 'python': 'pip', 'go': 'go', 'golang': 'go', 'npm': 'npm', 'node': 'npm', 'nodejs': 'npm', 'javascript': 'npm', 'typescript': 'npm', 'maven': 'maven', 'rubygems': 'rubygems', 'ruby': 'rubygems', 'cargo': 'rust', 'crates.io': 'rust', 'rust': 'rust', 'nuget': 'nuget', 'composer': 'composer', 'pub': 'pub', 'erlang': 'erlang', 'actions': 'actions'}
    return mapping.get(str(ecosystem or '').strip().lower(), str(ecosystem or '').strip().lower())

def _flow_args(**kwargs: Any) -> argparse.Namespace:
    defaults = {'seed_index': 0, 'claim': False, 'claimed_by': os.environ.get('USER', 'operator'), 'force': False, 'title': None, 'surface': None, 'weakness': None, 'impact': None, 'attacker_control': None, 'sink': None, 'entrypoint': None, 'trust_boundary': None, 'latest_affected': None, 'novelty': None, 'cve': None, 'cwe': None, 'cvss': None, 'mitre_attack': None, 'mitre_atlas': None, 'd3fend': None, 'nist_csf': None, 'nist_ai_rmf': None, 'negative_controls': None, 'safety_notes': None, 'reference_sources': None, 'root_cause': None, 'variant_analysis': None, 'patch_diff': None, 'campaign_dir': None, 'campaign_module': None, 'campaign_run': None, 'campaign_gate': None, 'no_campaign_context': False, 'exploitability': None, 'disclosure_quality': None, 'notes': None, 'json': False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)

def _load_latest_variant_yaml(run_dir: Path, candidate_id: str) -> dict[str, Any]:
    variants = sorted((run_dir / 'variant_analysis').glob(f'{candidate_id}_*.yaml'))
    if not variants:
        raise SystemExit(f'no variant analysis yaml found for {candidate_id}')
    return load_yaml(variants[-1]) or {}

def _hit_file(hit: str) -> str:
    return hit.split(':', 1)[0] if ':' in hit else hit

def _hit_symbol(hit: str) -> str:
    text = hit.split(':', 2)[-1] if ':' in hit else hit
    for regex in ('\\bfunc\\s+(?:\\([^)]+\\)\\s*)?([A-Za-z_][A-Za-z0-9_]*)', '\\bdef\\s+([A-Za-z_][A-Za-z0-9_]*)', '\\bclass\\s+([A-Za-z_][A-Za-z0-9_]*)', '\\b([A-Za-z_][A-Za-z0-9_]*)\\s*[:=]\\s*function\\b', '\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\('):
        match = re.search(regex, text)
        if match:
            return match.group(1)
    return '<unknown>'

def _intent_tokens(state: dict[str, Any]) -> list[str]:
    intent = state.get('intent') or {}
    tokens = intent.get('threat_model') or []
    return [t for t in tokens if t in _h.INTENT_VOCAB]

def _quality_band(score: int) -> str:
    if score >= 85:
        return 'report-ready-shape'
    if score >= 70:
        return 'strong-candidate'
    if score >= 50:
        return 'needs-more-proof'
    return 'early-or-weak'

def _top_files(graph: dict[str, Any], category: str, limit: int) -> list[str]:
    query = graph.get('queries', {}).get(category, {})
    return list((query.get('top_files') or {}).keys())[:limit]

def _build_hypotheses(graph: dict[str, Any], files_per: int) -> list[dict[str, Any]]:
    hypotheses: list[dict[str, Any]] = []

    def add(kind: str, title: str, files: list[str], rationale: str, next_step: str) -> None:
        if not files:
            return
        hypotheses.append({'id': f'HYP-{len(hypotheses) + 1:03d}', 'kind': kind, 'title': title, 'files': files[:files_per], 'rationale': rationale, 'next_step': next_step, 'status': 'hypothesis'})
    event_files = set(_top_files(graph, 'events_broadcasts', files_per * 2))
    authz_files = set(_top_files(graph, 'authz_checks', files_per * 2))
    route_files = set(_top_files(graph, 'routes_handlers', files_per * 2))
    parser_files = set(_top_files(graph, 'parsers_decoders', files_per * 2))
    storage_files = set(_top_files(graph, 'file_storage', files_per * 2))
    network_files = set(_top_files(graph, 'network_clients', files_per * 2))
    exec_files = set(_top_files(graph, 'process_execution', files_per * 2))
    native_files = set(_top_files(graph, 'native_unsafe', files_per * 2))
    add('realtime_authz_drift', 'Compare websocket/event broadcasts against REST permission checks', sorted(event_files & authz_files or event_files)[:files_per], 'Realtime event publishers and permission checks are high-yield for authz drift.', 'For each event payload, identify equivalent REST/API read path and build a denied-receiver negative control.')
    add('route_authz_gap', 'Review route handlers that may depend on missing or inconsistent authz checks', sorted(route_files & authz_files or route_files)[:files_per], 'Endpoint handlers are externally reachable and must consistently enforce permission boundaries.', 'Trace handler -> app method -> store call and compare positive user, denied user, guest, and admin behavior.')
    add('parser_storage_boundary', 'Review parser and file/storage boundaries for traversal or canonicalization drift', sorted(parser_files & storage_files or parser_files | storage_files)[:files_per], 'Parser/storage intersections often expose path traversal, archive handling, and content confusion issues.', 'Create benign and malicious path/canonicalization controls, then verify write/read target boundaries.')
    add('ssrf_outbound_boundary', 'Review outbound network clients for SSRF and internal network guard coverage', sorted(network_files)[:files_per], 'Network client surfaces must distinguish trusted admin URLs from attacker-controlled URLs.', 'Trace caller-controlled URL sources into HTTP clients and verify reserved-IP, redirect, DNS, and scheme handling.')
    add('command_execution_boundary', 'Review process execution surfaces for shell or argument injection', sorted(exec_files)[:files_per], 'Process execution is high-impact when attacker-controlled data reaches command, args, env, or cwd.', 'Prove attacker control over command/argument/env separately before building any execution PoC.')
    add('native_memory_boundary', 'Review native unsafe code for parser or FFI memory-safety candidates', sorted(native_files)[:files_per], 'Native and unsafe surfaces need sanitizer/fuzz harness review before exploitability claims.', 'Identify parser entrypoint, input format, ownership/lifetime model, and available sanitizer or fuzz harness.')
    return hypotheses

def _order_hypotheses_by_intent(hypotheses: list[dict[str, Any]], intent_tokens: list[str]) -> list[dict[str, Any]]:
    intent_kinds = set().union(*(_h.INTENT_VOCAB[t]['kinds'] for t in intent_tokens)) if intent_tokens else set()
    for hyp in hypotheses:
        hyp['intent_priority'] = hyp['kind'] in intent_kinds
    hypotheses.sort(key=lambda h: 0 if h['intent_priority'] else 1)
    return hypotheses

def _calls_in_body(body: str) -> list[str]:
    names = re.findall('(?:\\.|\\b)([A-Za-z_][A-Za-z0-9_]*)\\s*\\(', body)
    seen: set[str] = set()
    calls: list[str] = []
    for name in names:
        if name in _h.CALL_STOPWORDS or name.lower() in _h.CALL_STOPWORDS:
            continue
        if name not in seen:
            seen.add(name)
            calls.append(name)
    return calls[:80]

def _semantic_categories(body: str) -> list[str]:
    by_pattern: dict[str, str] = {}
    for category, pattern in _h.GRAPH_QUERIES.items():
        if category == 'functions':
            continue
        if re.search(pattern, body, flags=re.IGNORECASE):
            by_pattern[pattern] = category
    return list(by_pattern.values())

def _function_for_hit(functions: list[dict[str, Any]], file_name: str, line_no: int) -> dict[str, Any] | None:
    candidates = [fn for fn in functions if fn.get('file') == file_name and int(fn.get('line', 0)) <= line_no <= int(fn.get('end_line', 0))]
    if candidates:
        return sorted(candidates, key=lambda fn: int(fn.get('line', 0)), reverse=True)[0]
    return None

def _parse_blackbox_json(path: Path, include_info: bool) -> list[dict[str, Any]]:
    findings = []
    try:
        text = path.read_text(encoding='utf-8', errors='replace').strip()
    except OSError:
        return findings
    if not text:
        return findings
    records = []
    if path.suffix == '.jsonl':
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
        info = record.get('info') if isinstance(record.get('info'), dict) else {}
        severity = str(record.get('severity') or info.get('severity') or '').lower()
        if severity in {'info', 'unknown', ''} and (not include_info):
            continue
        title = info.get('name') or record.get('name') or record.get('template-id') or record.get('id')
        findings.append({'title': title, 'severity': severity or 'unknown', 'template_id': record.get('template-id') or record.get('id'), 'matched_at': record.get('matched-at') or record.get('url') or record.get('host'), 'evidence': record.get('extracted-results') or record.get('curl-command') or '', 'source_file': rel(path), 'raw': record})
    return findings

def _parse_blackbox_text(path: Path, include_info: bool) -> list[dict[str, Any]]:
    findings = []
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return findings
    for line in lines:
        lowered = line.lower()
        severity = ''
        for candidate in ('critical', 'high', 'medium', 'low', 'info'):
            if candidate in lowered:
                severity = candidate
                break
        if severity in {'', 'info', 'low'} and (not include_info):
            continue
        if not re.search('(cve-\\d{4}-\\d{4,}|vulnerab|weak|expos|misconfig|tls|ssl|xss|ssrf|injection)', lowered):
            continue
        findings.append({'title': line.strip()[:180], 'severity': severity or 'unknown', 'matched_at': '', 'evidence': line.strip(), 'source_file': rel(path)})
    return findings

def _function_body(src: Path, fn: dict[str, Any]) -> list[str]:
    path = src / str(fn.get('file', ''))
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    return lines[int(fn.get('line', 1)) - 1:int(fn.get('end_line', fn.get('line', 1)))]

def _flow_guard(lines: list[str], fn_start: int, sink_offset: int, tainted: list[str], sink_line: str) -> str | None:
    """Return a guard reason if the tainted value is constrained before/at the sink, else None."""
    if re.search('(?:public_send|send|__send__)\\(\\s*[\\"\'][^\\"\']*=[\\"\']', sink_line):
        return 'constrained_setter_dispatch'
    if re.search('(?:public_send|send|__send__)\\(\\s*[\\"\'][^\\"\'#]+[\\"\']\\s*[,)]', sink_line):
        return 'literal_method_dispatch'
    if re.search('(DB\\.exec|\\.exec\\(|exec_query|find_by_sql|count_by_sql|\\.(?:where|update_all|delete_all|order|group|having|pluck)\\b)', sink_line):
        interpolated = any((re.search('#\\{[^}]*\\b' + re.escape(v) + '\\b[^}]*\\}', sink_line) for v in tainted))
        concatenated = any((re.search('(?:\\+|<<)\\s*' + re.escape(v) + '\\b|\\b' + re.escape(v) + '\\s*(?:\\+|<<)', sink_line) for v in tainted))
        if not interpolated and (not concatenated):
            return 'parameterized_bind'
    window = lines[:sink_offset - fn_start + 1]
    for ln in window:
        refs = any((re.search(f'\\b{re.escape(v)}\\b', ln) for v in tainted))
        if refs and _h.GUARD_WHITELIST_RE.search(ln):
            return 'whitelist_check'
        if refs and re.search(_h.DEFAULT_GUARD_DRIFT_REGEX, ln, flags=re.IGNORECASE):
            return 'validation_guard'
        for v in tainted:
            if re.search(f"""\\b{re.escape(v)}\\s*=.*\\?\\s*[\\"'][^\\"']*[\\"']\\s*:\\s*[\\"'][^\\"']*[\\"']""", ln):
                return 'literal_ternary'
    for ln in window:
        if re.search('raise\\b.*[Ss]ignature', ln) or (re.search('\\bsign\\b', ln) and '!=' in ln):
            return 'signature_gate'
    return None

def _active_code_lines(lines: list[str]) -> list[str]:
    active = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if in_block:
            active.append('')
            if '*/' in stripped:
                in_block = False
            continue
        if stripped.startswith(('/*', '*', '//', '#')):
            active.append('')
            if stripped.startswith('/*') and '*/' not in stripped:
                in_block = True
            continue
        active.append(line)
    return active

def _line_hits(lines: list[str], regex: str, start_line: int, max_hits: int=8) -> list[dict[str, Any]]:
    hits = []
    for offset, line in enumerate(lines, start=start_line):
        if re.search(regex, line, flags=re.IGNORECASE):
            hits.append({'line': offset, 'text': line.strip()[:260]})
            if len(hits) >= max_hits:
                break
    return hits

def _guard_drift_functions(src: Path, include_tests: bool, paths: list[str] | None, max_files: int, max_functions: int) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for path in _h._source_files(src, include_tests, paths, max_files):
        rel_name = rel(path).removeprefix(rel(src) + '/')
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        lines = text.splitlines()
        defs = _h._function_defs(rel_name, text)
        if not defs:
            defs = [{'file': rel_name, 'line': 1, 'end_line': len(lines), 'name': '<module>', 'kind': 'module', 'signature': rel_name}]
        for fn in defs:
            body_lines = lines[int(fn['line']) - 1:int(fn['end_line'])]
            item = dict(fn)
            item['body_lines'] = body_lines
            functions.append(item)
            if len(functions) >= max_functions:
                return functions
    return functions

def _sibling_guarded_examples(record: dict[str, Any], guarded: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    same_category = [item for item in guarded if item['category'] == record['category']]
    same_dir = [item for item in same_category if str(Path(item['file']).parent) == str(Path(record['file']).parent)]
    same_file = [item for item in same_category if item['file'] == record['file']]
    ranked = []
    seen = set()
    for bucket in (same_file, same_dir, same_category):
        for item in bucket:
            key = (item['file'], item['function'], item['line'])
            if key in seen:
                continue
            seen.add(key)
            ranked.append({'file': item['file'], 'function': item['function'], 'line': item['line'], 'guard_hits': item['guard_hits'][:2], 'sink_hits': item['sink_hits'][:2]})
            if len(ranked) >= limit:
                return ranked
    return ranked

def _guard_drift_candidate(item: dict[str, Any], cand_id: str, artifact_md: Path) -> dict[str, Any]:
    category = item.get('category', 'sink')
    file_name = item.get('file', '')
    function = item.get('function', '')
    guarded = item.get('guarded_examples', [])
    guarded_summary = ''
    if guarded:
        first = guarded[0]
        guarded_summary = f" guarded sibling `{first.get('file')}:{first.get('line')} {first.get('function')}` applies a guard before a comparable `{category}` sink."
    return {'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'id': cand_id, 'title': f'Possible guard drift: unguarded {category} sink in {function}', 'status': 'auto-candidate', 'surface': f"{file_name}:{item.get('line')} {function}", 'weakness': 'CWE-693', 'impact': 'A security guard appears inconsistently applied across sibling sink paths; prove whether attacker-controlled input reaches the unguarded path.', 'attacker_control': 'unknown; trace route/API input into the unguarded sink before promotion', 'entrypoint': f"{file_name}:{item.get('line')}", 'trust_boundary': 'security guard drift across comparable source-to-sink paths', 'latest_affected': 'unchecked', 'sink': '; '.join((hit.get('text', '') for hit in item.get('sink_hits', [])[:2])), 'novelty': 'unchecked', 'dedup': {'status': 'unchecked', 'matches': [], 'checked_at': ''}, 'proof': 'not_started', 'cve': 'N/A', 'cwe': 'CWE-693', 'cvss': '', 'framework_mappings': {}, 'negative_controls': 'Required: guarded sibling path rejects or constrains the same class of input while this path reaches the sink.', 'safety_notes': 'Auto-created from guard-drift analysis. Do not submit without route reachability, attacker control, duplicate check, and runtime proof.', 'reference_sources': rel(artifact_md), 'root_cause': f'Comparable `{category}` sinks do not all apply the same guard.{guarded_summary}', 'variant_analysis': rel(artifact_md), 'patch_diff': '', 'exploitability': 'L1 source signal', 'disclosure_quality': '', 'created_at': dt.datetime.now().isoformat(timespec='seconds'), 'notes': json.dumps({'guard_drift': item}, sort_keys=True), 'history': [{'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'created:auto-candidate', 'source': rel(artifact_md), 'tool': 'guard-drift'}]}

def _run_elapsed_minutes(state: dict[str, Any], candidates: list[dict[str, Any]]) -> int:
    starts = [_parse_time(state.get('created_at'))]
    for cand in candidates:
        starts.append(_parse_time(cand.get('created_at')))
        for item in cand.get('history', []) if isinstance(cand.get('history'), list) else []:
            starts.append(_parse_time(item.get('at')))
    clean = [item for item in starts if item]
    if not clean:
        return 0
    return max(0, int((dt.datetime.now() - min(clean)).total_seconds() // 60))

def budget_status(run_dir: Path) -> dict[str, Any]:
    state, target = load_run(run_dir)
    data = load_candidates(run_dir)
    budgets = {**_h.DEFAULT_BUDGETS, **(target.get('budgets') or {})}
    elapsed = _run_elapsed_minutes(state, data.get('candidates', []))
    overruns = [key for key, value in budgets.items() if key == 'total_minutes' and elapsed > int(value)]
    return {'elapsed_minutes': elapsed, 'budgets': budgets, 'overruns': overruns, 'within_total_budget': 'total_minutes' not in overruns}

def _latest_artifact(run_dir: Path, subdir: str, pattern: str='*.md') -> str:
    path = run_dir / subdir
    if not path.exists():
        return ''
    items = sorted(path.rglob(pattern))
    return rel(items[-1]) if items else ''

def _recommendation_verb(rec: dict[str, Any]) -> str:
    command = str(rec.get('command') or '')
    tokens = shlex.split(command) if command else []
    for tok in tokens[1:]:
        if tok.startswith('-'):
            continue
        return tok
    return ''

def _recommendation_signature(rec: dict[str, Any]) -> str:
    return f"{rec.get('priority') or ''}::{_recommendation_verb(rec)}::{rec.get('candidate_id') or ''}"

def _loop_state(rec: dict[str, Any]) -> str:
    priority = str(rec.get('priority') or '')
    verb = _recommendation_verb(rec)
    if priority == 'setup':
        return {'prepare': 'recon', 'map': 'map', 'source-graph': 'reachability', 'semantic-graph': 'reachability'}.get(verb, 'recon')
    if priority == 'triage':
        return 'triage' if rec.get('candidate_id') else 'hypothesize'
    if priority == 'novelty':
        return 'triage'
    if priority in {'gate', 'proof'}:
        return 'proof'
    if priority in {'root-cause', 'variant', 'patch-review', 'report'}:
        return 'enrich'
    if priority == 'reporting':
        return 'report'
    return priority or 'recon'

def _required_result(rec: dict[str, Any]) -> str:
    return {'setup': 'Stage artifact written to state.json.', 'triage': 'Candidate(s) created or triage_verdict recorded.', 'novelty': 'OSV novelty check recorded on the candidate.', 'gate': 'Promotion-gate blockers cleared.', 'proof': 'Proof plan executed and proof=passed.', 'root-cause': 'Substantive root_cause recorded.', 'variant': 'Sibling-surface variant_analysis recorded.', 'patch-review': 'Patch/advisory diff recorded or scoped out.', 'report': 'Report-ready blockers cleared.', 'reporting': 'Report and dashboard regenerated.'}.get(str(rec.get('priority') or ''), 'Advance the loop to the next state.')

def _step_gate(rec: dict[str, Any]) -> str:
    if str(rec.get('priority')) == 'triage' and rec.get('candidate_id'):
        return 'triage_verdict in {needs_proof,defended,false_positive}'
    return ''

def _build_step(rec: dict[str, Any], step_id: int) -> dict[str, Any]:
    return {'step_id': step_id, 'state': _loop_state(rec), 'priority': rec.get('priority', ''), 'candidate_id': rec.get('candidate_id', ''), 'task': rec.get('reason', ''), 'command': rec.get('command', ''), 'required_result': _required_result(rec), 'gate': _step_gate(rec), 'signature': _recommendation_signature(rec)}

def _load_cursor(state: dict[str, Any]) -> dict[str, Any]:
    cursor = dict(state.get('loop_cursor') or {})
    cursor.setdefault('step_counter', 0)
    cursor.setdefault('pending_step', None)
    cursor.setdefault('history', [])
    cursor.setdefault('states_seen', [])
    return cursor

def _persist_cursor(run_dir: Path, cursor: dict[str, Any]) -> None:
    state = read_json(run_dir / 'state.json', {})
    state['loop_cursor'] = cursor
    write_json(run_dir / 'state.json', state)

def _loop_integrity_violations(state: dict[str, Any], candidates: list[dict[str, Any]]) -> list[str]:
    violations: list[str] = []
    cursor = state.get('loop_cursor') or {}
    seen = list(cursor.get('states_seen') or [])
    idx = -1
    for st in seen:
        if st not in _h.LOOP_STATE_ORDER:
            violations.append(f'unknown loop state recorded: {st}')
            continue
        pos = _h.LOOP_STATE_ORDER.index(st)
        if pos <= idx:
            violations.append(f'loop state out of order: {st}')
        else:
            idx = pos
    if 'report' in seen:
        missing = [s for s in _h.LOOP_STATE_ORDER if s != 'report' and s not in seen]
        if missing:
            violations.append('report reached but prior states missing: ' + ','.join(missing))
    for entry in cursor.get('history') or []:
        if not entry.get('outcome_id'):
            violations.append(f"history step {entry.get('step_id')} missing outcome_id")
    for cand in candidates:
        proven = cand.get('proof') == 'passed' or substantive(cand.get('root_cause')) or substantive(cand.get('variant_analysis'))
        if proven and str(cand.get('triage_verdict') or '') != 'needs_proof':
            violations.append(f"candidate {cand.get('id')} advanced to proof without needs_proof verdict")
    return violations

def _knowledge_files() -> list[Path]:
    roots = [ROOT / 'vapt' / 'harness' / 'knowledge', ROOT / 'vapt' / 'harness' / 'agents', ROOT / 'vapt' / 'management', ROOT / 'vapt' / 'harness' / 'corpus']
    files = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob('*'):
            if path.is_file() and path.suffix.lower() in {'.md', '.yaml', '.yml', '.jsonl', '.json'}:
                files.append(path)
    return sorted(files)

def _rank_text(query_terms: list[str], text: str) -> int:
    lowered = text.lower()
    return sum((lowered.count(term) for term in query_terms))

def _command_help(command: str) -> str:
    parser = _h.build_parser()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        parser.parse_args([command, '--help'])
    output = buf.getvalue()
    if not output:
        raise SystemExit(f'unknown command or no help available: {command}')
    return output

def _synthetic_status_for(seed_key: str) -> tuple[str, float | None]:
    bucket = (zlib.crc32(seed_key.encode('utf-8')) & 4294967295) / float(4294967295)
    cumulative = 0.0
    for status, weight, payout in _h.SYNTHETIC_OUTCOME_DISTRIBUTION:
        cumulative += weight
        if bucket <= cumulative:
            return (status, payout)
    return (_h.SYNTHETIC_OUTCOME_DISTRIBUTION[-1][0], _h.SYNTHETIC_OUTCOME_DISTRIBUTION[-1][2])

def _synthetic_module_for(cand: dict[str, Any]) -> str:
    weakness = str(cand.get('weakness') or '').lower()
    surface = str(cand.get('surface') or '').lower()
    if 'ssrf' in weakness or 'ssrf' in surface:
        return 'ssrf_callback'
    if 'authz' in weakness or 'auth' in weakness or '200' in weakness:
        return 'authz_matrix'
    if 'serialization' in weakness or 'deserial' in weakness or 'rce' in weakness:
        return 'serialization_rce'
    if 'path' in weakness or 'file' in surface or '346' in weakness:
        return 'path_traversal_audit'
    if 'injection' in weakness or 'prompt' in weakness:
        return 'prompt_injection_audit'
    if 'websocket' in weakness or 'ws' in surface:
        return 'websocket_authz'
    return 'manual_review'

def _synthetic_evidence_kind(cand: dict[str, Any]) -> str:
    proof = str(cand.get('proof') or '').lower()
    if 'passed' in proof:
        return 'reproducer_verified'
    if cand.get('notes'):
        return 'manual_observation'
    return 'manual_seed'

def _load_watch_module(name: str) -> Any:
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    import importlib
    return importlib.import_module(f'watch.{name}')

def _discovery_queue_dir() -> Path:
    return ROOT / 'vapt' / 'harness' / 'queue'

def _target_bb_root(profile_path: Path) -> Path:
    if profile_path.parent.name == 'targets':
        return profile_path.parent.parent
    return profile_path.parent

def _target_profile_by_arg(target_or_profile: str) -> tuple[Path, dict[str, Any]]:
    candidate = run_path(target_or_profile)
    if candidate.exists():
        return (candidate, load_yaml(candidate) or {})
    profile_path, target = _load_target_profile(target_or_profile)
    if profile_path and target:
        return (profile_path, target)
    raise SystemExit(f'target profile not found: {target_or_profile}')

def _module_key(name: str) -> str:
    return _h.MODULE_ALIASES.get(str(name or ''), str(name or ''))

def _module_artifact_key(raw: Any) -> str:
    return str(raw or '').rstrip('/')

def _module_status(module_history: dict[str, Any]) -> str:
    if not module_history or not module_history.get('runs'):
        return 'untested'
    if int(module_history.get('candidate_signals') or 0) > 0:
        return 'candidate_signal'
    verdicts = {str(item) for item in module_history.get('verdicts', [])}
    if int(module_history.get('failed_expectations') or 0) > 0 or verdicts & {'partial', 'setup_failed', 'module_failed'}:
        return 'partial'
    if 'no_findings' in verdicts:
        return 'closed'
    return 'tested_unknown'

def module_contract_path() -> Path:
    return ROOT / 'vapt' / 'harness' / 'config' / 'module_contract.yaml'

def _adapter_manifest_paths(target: str | None=None) -> list[Path]:
    root = ROOT / 'vapt' / 'engagements'
    if target:
        profile_path, _target = _target_profile_by_arg(target)
        bb_root = _target_bb_root(profile_path)
        return sorted((bb_root / 'adapters').glob('*.yaml'))
    return sorted(root.glob('*/adapters/*.yaml'))

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
    required_manifest = contract.get('adapter_manifest_required_fields') or []
    for field in required_manifest:
        if not manifest.get(field):
            errors.append(f'missing adapter manifest field: {field}')
    modules = manifest.get('modules') or []
    if not isinstance(modules, list):
        errors.append('modules must be a list')
        modules = []
    checked_modules = []
    required_module_fields = contract.get('adapter_module_required_fields') or []
    for module in modules:
        if not isinstance(module, dict):
            errors.append('adapter module entry must be an object')
            continue
        module_id = str(module.get('id') or '')
        module_errors = []
        module_warnings = []
        for field in required_module_fields:
            if not module.get(field):
                module_errors.append(f'missing module field: {field}')
        generic = catalog.get(module_id)
        if not generic:
            module_errors.append(f'unknown generic module id: {module_id}')
        else:
            expected = set((str(item) for item in generic.get('adapter_requirements', [])))
            actual = set((str(item) for item in module.get('requirement_methods', [])))
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            if missing:
                module_errors.append('missing requirement methods: ' + ', '.join(missing))
            if extra:
                module_warnings.append('extra requirement methods: ' + ', '.join(extra))
        implementation = str(module.get('implementation') or '')
        if implementation:
            impl_path = (bb_root / implementation).resolve()
            if not _path_within(impl_path, bb_root):
                module_errors.append(f'implementation escapes target root: {implementation}')
            elif not impl_path.exists():
                module_errors.append(f'implementation not found: {implementation}')
        command = module.get('command') or []
        if not isinstance(command, list) or not command:
            module_errors.append('command must be a non-empty argv list')
        else:
            command_text = ' '.join((str(item) for item in command))
            allow_harness_fixture = 'vapt/harness/tests/fixtures' in rel(path)
            if 'vapt/harness' in command_text and (not allow_harness_fixture):
                module_errors.append('adapter command points at core harness instead of target-local runtime')
            if 'vapt/engagements/' not in command_text and (not allow_harness_fixture):
                module_warnings.append('adapter command does not visibly reference target-local runtime')
        with contextlib.suppress(Exception):
            mutation_catalog = _h.load_mutation_catalog()
            for family_id in module.get('mutation_families', []) or []:
                family = mutation_catalog.get(str(family_id))
                if not family:
                    module_errors.append(f'unknown mutation family: {family_id}')
                    continue
                applies_to = {str(item) for item in family.get('applies_to', [])}
                if module_id not in applies_to:
                    module_warnings.append(f'mutation family {family_id} does not list module {module_id} in applies_to')
        errors.extend((f"{module_id or '<unknown>'}: {item}" for item in module_errors))
        warnings.extend((f"{module_id or '<unknown>'}: {item}" for item in module_warnings))
        checked_modules.append({'id': module_id, 'local_name': module.get('local_name', ''), 'status': 'fail' if module_errors else 'pass', 'errors': module_errors, 'warnings': module_warnings})
    return {'path': rel(path), 'target_id': manifest.get('target_id', ''), 'adapter_id': manifest.get('adapter_id', ''), 'status': 'fail' if errors else 'pass', 'errors': errors, 'warnings': warnings, 'modules': checked_modules}

def _load_target_adapter(target: str) -> tuple[Path, dict[str, Any]]:
    paths = _adapter_manifest_paths(target)
    if not paths:
        raise SystemExit(f'no adapter manifests found for target: {target}')
    path = paths[0]
    return (path, load_yaml(path) or {})

def _git_ref_exists(repo: Path, ref: str, timeout: int=10) -> bool:
    if not ref:
        return False
    result = run_cmd(['git', 'rev-parse', '--verify', '--quiet', ref], repo, timeout=timeout)
    return result['returncode'] == 0 and (not result['timeout'])

def _previous_tag(repo: Path, tag: str, timeout: int=10) -> str:
    if not tag or not _git_ref_exists(repo, tag, timeout):
        return ''
    result = run_cmd(['git', 'describe', '--tags', '--abbrev=0', f'{tag}^'], repo, timeout=timeout)
    if result['returncode'] == 0 and result['stdout'].strip():
        return result['stdout'].strip()
    return ''

def _patch_first_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Patch-First Plan: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Target profile: `{payload['target_profile']}`", f"- Source path: `{payload['source_path']}`", f"- Git available: `{payload['git_available']}`", '', '## Priority Seeds', '']
    for item in payload['priority_seeds']:
        lines.append(f"- score=`{item['score']}` type=`{item['type']}` ref=`{item['ref']}`")
        lines.append(f"  - rationale: {item['rationale']}")
        lines.append(f"  - next: `{item['next_action']}`")
    if not payload['priority_seeds']:
        lines.append('- None')
    lines.extend(['', '## Suggested Commands', ''])
    if payload['suggested_commands']:
        for cmd in payload['suggested_commands']:
            lines.append(f'```sh\n{cmd}\n```')
    else:
        lines.append('- None')
    return '\n'.join(lines).rstrip() + '\n'

def _next_action_for_module(module_id: str, status: str, target_id: str) -> str:
    if status == 'candidate_signal':
        return f'prove and dedup candidate signals from {module_id}'
    if status == 'partial':
        return f'rerun {module_id} with mutation-plan coverage and fix setup gaps'
    if status == 'untested':
        return f'implement or run adapter module {module_id}'
    if status == 'tested_unknown':
        return f'review {module_id} evidence and mark closed, partial, or candidate'
    return f'watch patch-first-plan {target_id} for new sibling variants'

def _render_adapter_value(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(_h._TemplateContext(context))
    if isinstance(value, list):
        return [_render_adapter_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _render_adapter_value(item, context) for key, item in value.items()}
    return value

def _load_adapter_from_args(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    if args.adapter:
        path = run_path(args.adapter)
        if not path.exists():
            raise SystemExit(f'adapter manifest not found: {args.adapter}')
        return (path, load_yaml(path) or {})
    if not args.target:
        raise SystemExit('campaign-run requires --target or --adapter')
    return _load_target_adapter(args.target)

def _artifact_path_from_record(record: dict[str, Any]) -> Path:
    return run_path(str(record.get('path') or ''))

def _path_is_under(path: Path, root: Path) -> bool:
    with contextlib.suppress(ValueError):
        path.resolve().relative_to(root.resolve())
        return True
    return False

def _gate_check(check_id: str, ok: bool, details: list[str] | None=None) -> dict[str, Any]:
    return {'id': check_id, 'status': 'pass' if ok else 'fail', 'details': details or []}

def phase2_surface_regression() -> dict[str, Any]:
    corpus = ROOT / 'vapt' / 'harness' / 'tests' / 'surface_corpus'
    expectations_path = ROOT / 'vapt' / 'harness' / 'tests' / 'surface_expectations.yaml'
    expectations = load_yaml(expectations_path) or {'categories': {}}
    categories = {}
    failures = []
    for category, spec in (expectations.get('categories') or {}).items():
        hits = []
        for pattern in _h.PATTERNS.get(category, []):
            result = run_cmd(['rg', '-n', '-S', '-F', pattern], corpus, timeout=30)
            if result['returncode'] in (0, 1):
                hits.extend(result['stdout'].splitlines())
        unique_hits = sorted(set(hits))
        min_hits = int(spec.get('min_hits', 0))
        passed = len(unique_hits) >= min_hits
        if not passed:
            failures.append(f'{category}: expected >= {min_hits}, got {len(unique_hits)}')
        categories[category] = {'min_hits': min_hits, 'hit_count': len(unique_hits), 'passed': passed}
    return {'passed': not failures, 'failures': failures, 'categories': categories}

def phase2_suggestion_count(target_id: str) -> int:
    profile_path, target = _load_target_profile(target_id)
    if not target:
        return 0
    if not candidate_corpus_path().exists():
        _h.cmd_corpus_rebuild(argparse.Namespace())
    target_terms = _h._term_set(' '.join((str(x) for x in target.get('category', []) + target.get('in_scope', []))))
    count = 0
    for row in read_jsonl(candidate_corpus_path()):
        cand = row.get('candidate', {})
        if row.get('target_id') == target_id:
            continue
        if target_terms & _h._term_set(_h._candidate_signal(cand)):
            count += 1
    return count

def phase2_fixture_submission_stats() -> dict[str, Any]:
    rows = [{'program': 'phase2-fixture', 'final_status': 'triaged', 'payout_value': 500, 'days_to_final': 3}, {'program': 'phase2-fixture', 'final_status': 'resolved', 'payout_value': 750, 'days_to_final': 5}, {'program': 'phase2-fixture', 'final_status': 'paid', 'payout_value': 1000, 'days_to_final': 8}, {'program': 'phase2-fixture', 'final_status': 'duplicate', 'payout_value': None, 'days_to_final': 2}, {'program': 'phase2-fixture', 'final_status': 'n_a', 'payout_value': None, 'days_to_final': 1}]
    return submission_stats(rows)

def select_probe(cand: dict[str, Any]) -> str | None:
    text = _h._candidate_signal(cand).lower()
    best = None
    best_score = 0
    for name, spec in _h.PROBE_REGISTRY.items():
        score = sum((1 for term in spec['terms'] if term in text))
        if score > best_score:
            best = name
            best_score = score
    return best

def load_probe(name: str):
    if name not in _h.PROBE_REGISTRY:
        raise SystemExit(f'unknown probe: {name}')
    spec = _h.PROBE_REGISTRY[name]
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    module = __import__(f"probes.{spec['module']}", fromlist=[spec['class']])
    return getattr(module, spec['class'])()

def _infer_playbook_class(target: dict[str, Any]) -> str:
    text = ' '.join((str(item) for item in [target.get('id', ''), target.get('name', ''), target.get('language', ''), target.get('category', '')])).lower()
    if 'deserialization' in text or 'serialization' in text:
        return 'python-ml-deserialization'
    if 'inference' in text or 'runtime' in text or 'local ai' in text:
        return 'local-ai-runtime'
    if 'mlops' in text or 'experiment' in text or 'orchestration' in text:
        return 'mlops'
    if 'javascript' in text or 'typescript' in text or 'electron' in text or ('web' in text):
        return 'js-ts-web'
    if 'go' in text or 'server' in text or 'api' in text:
        return 'go-api-server'
    return 'python-ml-deserialization' if 'python' in text else 'go-api-server'

def _poc_template_body(vuln_class: str) -> str:
    key = re.sub('[^a-z0-9]+', '_', vuln_class.lower()).strip('_')
    if key in {'deserialization', 'serialization_rce', 'pickle', 'model_deserialization'}:
        key = 'unsafe_deserialization'
    if key in {'idor', 'authz', 'authorization', 'auth_bypass'}:
        key = 'idor_authz'
    if key in {'ssti', 'jinja', 'template'}:
        key = 'template_injection'
    templates = {'path_traversal': 'def build_payload(base_path: Path) -> dict:\n    return {"candidate": "../controlled-marker.txt", "base": str(base_path)}\n\n\ndef positive_proof() -> dict:\n    marker = Path("controlled-marker.txt")\n    marker.write_text("harness-marker\\n", encoding="utf-8")\n    payload = build_payload(Path.cwd())\n    return {\n        "status": "todo",\n        "payload": payload,\n        "expected_impact": "Target reads/writes outside intended base directory.",\n        "evidence": "Replace todo with authorized target API invocation and captured output.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "payload": {"candidate": "allowed-file.txt"},\n        "expected": "Allowed in-base file succeeds while traversal is denied after fix.",\n    }\n', 'ssrf': 'def positive_proof() -> dict:\n    return {\n        "status": "todo",\n        "canary": "Use a local listener or captive HTTP server only.",\n        "expected_impact": "Attacker-controlled URL causes server-side outbound request.",\n        "evidence": "Capture listener hit, request path, headers, and target-side response.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "control": "Benign non-URL input or disallowed scheme is rejected.",\n    }\n', 'command_injection': 'def positive_proof() -> dict:\n    marker = Path("cmd_injection_marker.txt")\n    return {\n        "status": "todo",\n        "marker": str(marker),\n        "payload_shape": "Use a harmless marker-write command in a captive local target.",\n        "expected_impact": "Attacker-controlled field reaches command execution boundary.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "control": "Same value passed as an argument vector is treated as data, not shell syntax.",\n    }\n', 'unsafe_deserialization': 'def positive_proof() -> dict:\n    return {\n        "status": "todo",\n        "fixture": "crafted serialized/model/archive fixture generated locally",\n        "expected_impact": "Load reaches object construction, file read/write, or code execution outside trusted type policy.",\n        "evidence": "Record loader call, exception/output, marker effect, and exact package versions.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "control": "Benign fixture loads; untrusted type/control fixture is rejected.",\n    }\n', 'idor_authz': 'def positive_proof() -> dict:\n    return {\n        "status": "todo",\n        "actors": ["owner_user", "attacker_user"],\n        "expected_impact": "Attacker user reads or mutates owner resource without permission.",\n        "evidence": "Capture authenticated request/response pairs for both users.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "control": "Owner succeeds; unrelated attacker is denied after permission check/fix.",\n    }\n', 'template_injection': 'def positive_proof() -> dict:\n    return {\n        "status": "todo",\n        "payload_shape": "Harmless arithmetic or marker expression for the target template engine.",\n        "expected_impact": "Attacker-controlled text is evaluated/rendered with server-side capabilities.",\n        "evidence": "Capture rendered output and engine/context boundary.",\n    }\n\n\ndef negative_control() -> dict:\n    return {\n        "status": "todo",\n        "control": "Escaped literal payload renders as text, not evaluated syntax.",\n    }\n'}
    return templates.get(key, 'def positive_proof() -> dict:\n    return {"status": "todo", "evidence": "implement authorized positive proof"}\n\n\ndef negative_control() -> dict:\n    return {"status": "todo", "evidence": "implement denied/benign control"}\n')

def read_tool_records(path: Path) -> list[Any]:
    text = path.read_text(encoding='utf-8', errors='replace')
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
        return f'CWE-{value}'
    text = ' '.join((str(item) for item in value)) if isinstance(value, list) else str(value or '')
    match = re.search('CWE-?(\\d{1,5})', text, flags=re.IGNORECASE)
    return f'CWE-{match.group(1)}' if match else ''

def first_cve(*values: Any) -> str:
    text = ' '.join((' '.join((str(item) for item in value)) if isinstance(value, list) else str(value or '') for value in values))
    match = re.search('CVE-\\d{4}-\\d{4,}', text, flags=re.IGNORECASE)
    return match.group(0).upper() if match else 'N/A'

def scanner_severity_rank(severity: str) -> int:
    order = {'info': 0, 'low': 1, 'medium': 2, 'moderate': 2, 'high': 3, 'critical': 4}
    return order.get(str(severity or '').lower(), 0)

def candidate_from_tool_finding(item: dict[str, Any], cand_id: str) -> dict[str, Any]:
    tool = item.get('tool', 'scanner')
    cwe = item.get('cwe') or ('CWE-798' if tool == 'trufflehog' else 'CWE-1035')
    return {'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'id': cand_id, 'title': str(item.get('title') or f'{tool} scanner finding')[:180], 'status': 'auto-candidate', 'surface': str(item.get('matched_at') or item.get('file') or item.get('package') or tool), 'weakness': cwe, 'impact': f'{tool} reported a potential security issue requiring manual validation.', 'attacker_control': 'unknown; scanner-import candidate requires triage', 'entrypoint': str(item.get('file') or item.get('matched_at') or item.get('package') or ''), 'trust_boundary': 'unvalidated scanner signal; promote only after source review and proof planning', 'latest_affected': 'unchecked', 'sink': str(item.get('file') or item.get('package') or item.get('matched_at') or ''), 'novelty': 'unchecked', 'dedup': {'status': 'unchecked', 'matches': [], 'checked_at': ''}, 'proof': 'not_started', 'cve': item.get('cve') or 'N/A', 'cwe': cwe, 'cvss': '', 'framework_mappings': {}, 'negative_controls': '', 'safety_notes': 'Auto-created from scanner output. Do not submit without manual validation, dedup, latest-version check, and proof.', 'reference_sources': item.get('source_file', ''), 'root_cause': '', 'variant_analysis': '', 'patch_diff': '', 'exploitability': 'L0 scanner signal', 'disclosure_quality': '', 'created_at': dt.datetime.now().isoformat(timespec='seconds'), 'notes': json.dumps({key: item.get(key) for key in ('tool', 'severity', 'confidence', 'line', 'evidence', 'fixed_versions')}, sort_keys=True), 'history': [{'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'created:auto-candidate', 'source': item.get('source_file', ''), 'tool': tool}]}

def phase3_probe_fixture_check() -> dict[str, Any]:
    fixture = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'probe_candidates.yaml'
    data = load_yaml(fixture) or {}
    candidates = data.get('candidates', {})
    target = data.get('target') or {'id': 'probe-fixture', 'source_path': '.'}
    run_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results' / 'phase3_probe_check'
    run_dir.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from probes.base import ProbeContext
    results = []
    for probe_name in sorted(_h.PROBE_REGISTRY):
        cand = candidates.get(probe_name)
        if not cand:
            results.append({'probe': probe_name, 'passed': False, 'missing': ['fixture candidate missing']})
            continue
        probe = load_probe(probe_name)
        ctx = ProbeContext(run_dir=run_dir, target=target, candidate=dict(cand), knobs={'phase3_check': True})
        result = probe.run(ctx)
        results.append({'probe': probe_name, 'passed': bool(result.get('passed')), 'missing': result.get('missing', [])})
    return {'passed': all((item['passed'] for item in results)), 'results': results}

def phase3_scanner_fixture_check() -> dict[str, Any]:
    fixture_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'tool_scans'
    fixtures = {'bandit': fixture_dir / 'bandit_sample.json', 'semgrep': fixture_dir / 'semgrep_sample.json', 'nuclei': fixture_dir / 'nuclei_sample.jsonl', 'pip-audit': fixture_dir / 'pip_audit_sample.json', 'osv': fixture_dir / 'osv_sample.json', 'trufflehog': fixture_dir / 'trufflehog_sample.jsonl'}
    results = []
    for tool, path in fixtures.items():
        records = read_tool_records(path)
        findings = _h.normalize_scanner_findings(tool, records, path, include_low=True)
        candidate = candidate_from_tool_finding(findings[0], 'CAND-001') if findings else {}
        results.append({'tool': tool, 'fixture': rel(path), 'finding_count': len(findings), 'auto_candidate_status': candidate.get('status', ''), 'auto_candidate_exploitability': candidate.get('exploitability', ''), 'passed': bool(findings) and candidate.get('status') == 'auto-candidate'})
    return {'passed': all((item['passed'] for item in results)), 'results': results}

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

def fetch_json_url(url: str, token: str | None, timeout: int) -> Any:
    headers = {'Accept': 'application/json', 'User-Agent': 'local-vapt-harness'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = request.Request(url, headers=headers)
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))
