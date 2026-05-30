"""Candidate workflow handlers: add / dedup / gate / prove / variant / patch-diff / cluster / refine / score-tune / submit / orient / next-action + the scoring math (_score_candidate), candidate-from-queue parsing, and recommend_next_action advisory.

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
import shutil
import sys
import time
import uuid
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib import error, request

from atomic_io import candidate_ledger_lock, dump_yaml, file_lock, load_yaml, read_jsonl, write_json, write_text
from campaign.context import find_campaign_context, infer_campaign_dir_from_artifact
from core import CURRENT_CANDIDATE_SCHEMA_VERSION, ROOT, TRIAGE_VERDICTS, _parse_time, candidate_corpus_path, rel, run_path, source_path, submissions_path
from gates.osv import COMMON_VARIANT_TERMS, _osv_dedup
from gates.promotion import dedup_checked, promotion_findings, workflow_blockers
from ledger.candidates import _normalize_candidate, find_candidate, load_candidates, next_candidate_id, save_candidates, update_candidate_locked
from ledger.outcomes import _append_step_outcome
from ledger.submissions import load_outcome_tuning
from validators import cvss3_base_score, exact_affected_version, submission_positive, substantive, validate_cwe


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def candidate_reference_text(cand: dict[str, Any]) -> str:
    dedup = cand.get('dedup') if isinstance(cand.get('dedup'), dict) else {}
    parts = [cand.get('reference_sources', ''), cand.get('cve', ''), cand.get('notes', ''), dedup.get('manual_notes', ''), ' '.join((str(item) for item in dedup.get('sources_checked', []) or [])), ' '.join((str(item) for item in dedup.get('matches', []) or []))]
    osv = dedup.get('osv') if isinstance(dedup.get('osv'), dict) else {}
    if osv:
        parts.append('osv.dev')
        parts.append(str(osv.get('artifact', '')))
    return ' '.join((str(part) for part in parts)).lower()

def candidate_from_queue_entry(data: dict[str, Any], entry: dict[str, Any], path: Path, run_dir: Path, args: argparse.Namespace, campaign_context: dict[str, Any]) -> dict[str, Any]:
    seeds = entry.get('candidate_seeds') or []
    if not seeds:
        seeds = [{}]
    try:
        seed = seeds[int(args.seed_index)]
    except (IndexError, ValueError):
        raise SystemExit(f'seed index out of range: {args.seed_index}')
    if not isinstance(seed, dict):
        raise SystemExit(f'queue seed is not an object: {args.seed_index}')
    cwe = args.cwe or _h.queue_entry_cwe(entry, seed)
    references = _h.queue_entry_references(entry)
    queue_id = str(entry.get('queue_id') or args.queue_id)
    queue_kind = str(entry.get('type') or 'queue')
    queue_ref = str(entry.get('ref') or queue_id)
    now = dt.datetime.now().isoformat(timespec='seconds')
    novelty = str(args.novelty or seed.get('novelty') or 'unchecked')
    dedup_status = 'unchecked'
    checked_at = ''
    matches: list[str] = []
    if novelty in {'possible-regression', 'advisory-known'} or queue_kind == 'advisory':
        dedup_status = 'advisory-seed'
        checked_at = now
        matches = [item.strip() for item in references.split(',') if item.strip()]
        novelty = 'possible-regression' if novelty == 'advisory-known' else novelty
    cand = {'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'id': next_candidate_id(data), 'title': args.title or seed.get('title') or f'Review {queue_ref} from {queue_kind} queue', 'status': 'candidate', 'surface': args.surface or seed.get('surface') or queue_kind, 'weakness': args.weakness or cwe or seed.get('weakness') or 'unchecked', 'impact': args.impact or seed.get('impact') or f'Queue seed from {queue_kind} {queue_ref}; concrete impact must be proven before promotion.', 'attacker_control': args.attacker_control or seed.get('attacker_control') or 'Queue seed only; attacker-control path must be verified before promotion.', 'entrypoint': args.entrypoint or seed.get('entrypoint') or '', 'trust_boundary': args.trust_boundary or seed.get('trust_boundary') or '', 'latest_affected': args.latest_affected or 'unchecked', 'sink': args.sink or seed.get('sink') or 'TBD', 'novelty': novelty, 'dedup': {'status': dedup_status, 'matches': matches, 'checked_at': checked_at, 'manual_notes': f'Created from queue seed {queue_id}; verify manually before reporting.', 'sources_checked': ['watch_queue']}, 'proof': 'not_started', 'cve': args.cve or 'N/A', 'cwe': cwe or args.weakness or seed.get('weakness') or '', 'cvss': args.cvss or '', 'framework_mappings': {'mitre_attack': args.mitre_attack or '', 'mitre_atlas': args.mitre_atlas or '', 'd3fend': args.d3fend or '', 'nist_csf': args.nist_csf or '', 'nist_ai_rmf': args.nist_ai_rmf or ''}, 'negative_controls': args.negative_controls or '', 'safety_notes': args.safety_notes or '', 'reference_sources': args.reference_sources or references, 'root_cause': args.root_cause or '', 'variant_analysis': args.variant_analysis or '', 'patch_diff': args.patch_diff or '', 'evidence_kind': 'queue_seed', 'queue_id': queue_id, 'queue_entry': rel(path), 'queue_evidence': {'created_from_queue': True, 'queue_id': queue_id, 'queue_entry': rel(path), 'queue_type': queue_kind, 'queue_ref': queue_ref, 'seed_index': int(args.seed_index), 'source_kind': entry.get('source_kind') or '', 'created_at': now}, 'campaign_run': '', 'campaign_gate': '', 'campaign_module': args.campaign_module or '', 'campaign_evidence': {}, 'exploitability': args.exploitability or '', 'disclosure_quality': args.disclosure_quality or '', 'created_at': now, 'notes': args.notes or seed.get('next_action') or '', 'history': [{'at': now, 'event': 'created-from-queue', 'queue_id': queue_id, 'queue_entry': rel(path)}]}
    if campaign_context:
        cand['evidence_kind'] = 'queue_campaign_seed'
        if args.campaign_run:
            cand['campaign_run'] = rel(run_path(args.campaign_run))
        elif campaign_context.get('campaign_run'):
            cand['campaign_run'] = campaign_context['campaign_run']
        if args.campaign_gate:
            cand['campaign_gate'] = rel(run_path(args.campaign_gate))
        elif campaign_context.get('campaign_gate'):
            cand['campaign_gate'] = campaign_context['campaign_gate']
        cand['campaign_evidence'] = {'created_in_campaign': True, 'campaign_dir': campaign_context.get('campaign_dir', ''), 'campaign_start': campaign_context.get('campaign_start', ''), 'target_id': campaign_context.get('target_id', ''), 'detected_at': campaign_context.get('detected_at', ''), 'campaign_run': cand['campaign_run'], 'campaign_gate': cand['campaign_gate'], 'campaign_module': cand['campaign_module']}
        cand['history'].append({'at': now, 'event': 'campaign-context-attached', 'campaign_start': campaign_context.get('campaign_start', '')})
    return cand

def cmd_candidate_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    campaign_context = {}
    if not args.no_campaign_context:
        explicit_campaign_dir = args.campaign_dir or infer_campaign_dir_from_artifact(args.campaign_run) or infer_campaign_dir_from_artifact(args.campaign_gate)
        campaign_context = find_campaign_context(run_dir, explicit_campaign_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = {'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'id': next_candidate_id(data), 'title': args.title, 'status': 'candidate', 'surface': args.surface, 'weakness': args.weakness, 'impact': args.impact, 'attacker_control': args.attacker_control, 'entrypoint': args.entrypoint or '', 'trust_boundary': args.trust_boundary or '', 'latest_affected': args.latest_affected or 'unchecked', 'sink': args.sink, 'novelty': 'unchecked', 'dedup': {'status': 'unchecked', 'matches': [], 'checked_at': ''}, 'proof': 'not_started', 'cve': args.cve or 'N/A', 'cwe': args.cwe or args.weakness, 'cvss': args.cvss or '', 'framework_mappings': {'mitre_attack': args.mitre_attack or '', 'mitre_atlas': args.mitre_atlas or '', 'd3fend': args.d3fend or '', 'nist_csf': args.nist_csf or '', 'nist_ai_rmf': args.nist_ai_rmf or ''}, 'negative_controls': args.negative_controls or '', 'safety_notes': args.safety_notes or '', 'reference_sources': args.reference_sources or '', 'root_cause': args.root_cause or '', 'variant_analysis': args.variant_analysis or '', 'patch_diff': args.patch_diff or '', 'evidence_kind': '', 'campaign_run': '', 'campaign_gate': '', 'campaign_module': args.campaign_module or '', 'campaign_evidence': {}, 'exploitability': args.exploitability or '', 'disclosure_quality': args.disclosure_quality or '', 'created_at': dt.datetime.now().isoformat(timespec='seconds'), 'notes': args.notes or '', 'history': [{'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'created'}]}
        if campaign_context:
            cand['evidence_kind'] = 'campaign_seed'
            if args.campaign_module:
                cand['campaign_module'] = args.campaign_module
            if args.campaign_run:
                cand['campaign_run'] = rel(run_path(args.campaign_run))
            elif campaign_context.get('campaign_run'):
                cand['campaign_run'] = campaign_context['campaign_run']
            if args.campaign_gate:
                cand['campaign_gate'] = rel(run_path(args.campaign_gate))
            elif campaign_context.get('campaign_gate'):
                cand['campaign_gate'] = campaign_context['campaign_gate']
            cand['campaign_evidence'] = {'created_in_campaign': True, 'campaign_dir': campaign_context.get('campaign_dir', ''), 'campaign_start': campaign_context.get('campaign_start', ''), 'target_id': campaign_context.get('target_id', ''), 'detected_at': campaign_context.get('detected_at', ''), 'campaign_run': cand['campaign_run'], 'campaign_gate': cand['campaign_gate'], 'campaign_module': cand['campaign_module']}
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'campaign-context-attached', 'campaign_start': campaign_context.get('campaign_start', '')})
        data.setdefault('candidates', []).append(cand)
        save_candidates(run_dir, data)
    print(cand['id'])

def cmd_candidate_from_queue(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    queue_path, entry = _h.queue_entry_by_id(args.queue_id)
    with file_lock(queue_path):
        entry = load_yaml(queue_path) or {}
        entry['_path'] = queue_path
        status = str(entry.get('status') or 'pending')
        if status == 'pending':
            if not args.claim and (not args.force):
                raise SystemExit('queue entry is pending; rerun with --claim or claim it first')
            entry['status'] = 'claimed'
            entry['claimed_by'] = args.claimed_by
            entry['claimed_at'] = dt.datetime.now().isoformat(timespec='seconds')
            entry.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'claimed', 'by': args.claimed_by, 'run_dir': rel(run_dir)})
        elif status not in {'claimed', 'converted'} and (not args.force):
            raise SystemExit(f'queue entry status is not convertible: {status}')
        elif status == 'converted' and (not args.force):
            raise SystemExit(f"queue entry already converted: {entry.get('candidate_id') or ''}")
        campaign_context = {}
        if not args.no_campaign_context:
            explicit_campaign_dir = args.campaign_dir or infer_campaign_dir_from_artifact(args.campaign_run) or infer_campaign_dir_from_artifact(args.campaign_gate)
            campaign_context = find_campaign_context(run_dir, explicit_campaign_dir)
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            cand = candidate_from_queue_entry(data, entry, queue_path, run_dir, args, campaign_context)
            data.setdefault('candidates', []).append(cand)
            save_candidates(run_dir, data)
        entry['status'] = 'converted'
        entry['candidate_id'] = cand['id']
        entry['run_dir'] = rel(run_dir)
        entry['converted_at'] = dt.datetime.now().isoformat(timespec='seconds')
        entry.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'converted-to-candidate', 'candidate_id': cand['id'], 'run_dir': rel(run_dir)})
        dump_yaml({key: value for key, value in entry.items() if key != '_path'}, queue_path)
    payload = {'candidate_id': cand['id'], 'run_dir': rel(run_dir), 'queue_id': entry.get('queue_id') or args.queue_id, 'queue_entry': rel(queue_path), 'campaign_attached': bool(cand.get('campaign_evidence'))}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(cand['id'])

def cmd_dedup(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    duplicate_seen = False
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get('candidates', [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]
        known = [str(item).lower() for item in target.get('known_duplicates', [])]
        target_terms = [str(target.get('id', '')), str(target.get('name', '')), str(target.get('repo_url', ''))]
        for cand in candidates:
            haystack = ' '.join((str(cand.get(key, '')) for key in ('title', 'surface', 'weakness', 'impact', 'sink', 'cve', 'notes'))).lower()
            matches = [item for item in known if item and item in haystack]
            cve = str(cand.get('cve', '')).lower()
            if cve and cve != 'n/a' and (cve in known) and (cve not in matches):
                matches.append(cve)
            osv_result = None
            if args.check_osv:
                osv_result = _osv_dedup(args, target, cand, run_dir)
                if osv_result['exact_alias_matches']:
                    matches.extend(osv_result['exact_alias_matches'])
            status = 'possible-regression' if args.regression else 'no-known-duplicate'
            if matches:
                status = 'known-duplicate'
            elif osv_result and osv_result['possible_text_matches']:
                status = 'possible-regression'
            elif args.check_osv and osv_result and osv_result.get('errors'):
                status = 'dedup-incomplete'
            if args.status:
                status = args.status
            duplicate_seen = duplicate_seen or status in {'known-duplicate', 'possible-regression'}
            cand['novelty'] = status
            sources_checked = ['target.known_duplicates', 'candidate.cve', 'candidate text fields']
            if args.check_osv:
                sources_checked.append('osv.dev')
            if args.reference:
                sources_checked.extend((str(item) for item in args.reference))
            cand['dedup'] = {'status': status, 'matches': sorted(set((str(match) for match in matches))), 'checked_at': dt.datetime.now().isoformat(timespec='seconds'), 'sources_checked': sources_checked, 'osv': osv_result, 'manual_notes': args.notes or '', 'suggested_queries': [' '.join([term for term in [target_terms[0], cand.get('weakness', ''), cand.get('sink', '')] if term]), ' '.join([term for term in [target_terms[1], cand.get('title', '')] if term]), ' '.join([term for term in [target_terms[2], cand.get('cve', '')] if term and term != 'N/A']), ' '.join([term for term in ['site:huntr.com', target_terms[2] or target_terms[0], cand.get('weakness', '')] if term]), ' '.join([term for term in ['site:github.com/advisories', target_terms[1], cand.get('cwe', '')] if term]), ' '.join([term for term in ['site:github.com', target_terms[2] or target_terms[1], cand.get('title', '')] if term])]}
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': f'dedup:{status}', 'matches': sorted(set((str(match) for match in matches)))})
            print(f"{cand['id']} duplicate_status={status} matches={','.join(sorted(set((str(match) for match in matches)))) or 'none'}")
        save_candidates(run_dir, data)
    if duplicate_seen:
        raise SystemExit(3)

def cmd_report_gate(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    out_dir = run_dir / 'readiness'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    results = []
    fail_seen = False
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get('candidates', [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]
        for cand in candidates:
            ok, blockers, warnings = _h.report_readiness_findings(cand)
            result = {'candidate_id': cand['id'], 'title': cand.get('title', ''), 'passed': ok, 'blockers': blockers, 'warnings': warnings}
            cand['report_readiness'] = result
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'report-readiness', 'passed': ok, 'blockers': blockers})
            if ok and args.mark_ready:
                cand['status'] = 'report-ready'
            results.append(result)
            fail_seen = fail_seen or not ok
            print(f"{cand['id']} report_gate={('pass' if ok else 'fail')}")
            if blockers:
                print('blocking=' + ','.join(blockers))
            if warnings:
                print('warnings=' + ','.join(warnings))
        save_candidates(run_dir, data)
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'results': results}
    dump_yaml(payload, out_dir / f'report_gate_{stamp}.yaml')
    md = ['# Report Readiness Gate', '']
    for result in results:
        md.extend([f"## {result['candidate_id']}: {result['title']}", '', f"- Passed: `{result['passed']}`", f"- Blockers: `{', '.join(result['blockers']) or 'none'}`", f"- Warnings: `{', '.join(result['warnings']) or 'none'}`", ''])
    write_text(out_dir / f'report_gate_{stamp}.md', '\n'.join(md))
    if fail_seen and args.fail:
        raise SystemExit(2)

def cmd_gate(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        ok, missing = promotion_findings(cand)
        score, err = cvss3_base_score(str(cand.get('cvss', '')))
        cand['promotion_gate'] = {'passed': ok, 'checked_at': dt.datetime.now().isoformat(timespec='seconds'), 'missing_or_blocking': missing, 'cvss_base_score': score, 'cvss_error': err}
        if ok and args.promote:
            cand['status'] = 'promoted'
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'status:promoted', 'reason': 'promotion gate passed'})
        if ok and args.report_ready:
            ready, report_blockers, report_warnings = _h.report_readiness_findings(cand)
            cand['report_readiness'] = {'passed': ready, 'checked_at': dt.datetime.now().isoformat(timespec='seconds'), 'blockers': report_blockers, 'warnings': report_warnings}
            if ready:
                cand['status'] = 'report-ready'
                cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'status:report-ready', 'reason': 'promotion gate passed and proof passed'})
            else:
                cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'report-ready-blocked', 'reason': 'strict report-readiness blockers remain: ' + ','.join(report_blockers)})
                missing.extend(report_blockers)
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} gate={('pass' if ok else 'fail')}")
    if missing:
        print('blocking=' + ','.join(missing))
        raise SystemExit(2)

def cmd_candidate_set(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        if args.status is None and getattr(args, 'triage_verdict', None) is None:
            raise SystemExit('candidate-set requires --status and/or --triage-verdict')
        if args.status is not None:
            if args.status in _h.WORKFLOW_ORDER or args.status in _h.WORKFLOW_TERMINAL:
                blockers = workflow_blockers(cand, args.status)
                if blockers and (not args.force):
                    print(json.dumps({'candidate_id': args.candidate_id, 'target_status': args.status, 'blockers': blockers}, sort_keys=True))
                    raise SystemExit(2)
            cand['status'] = args.status
        if getattr(args, 'triage_verdict', None) is not None:
            cand['triage_verdict'] = args.triage_verdict
        for key, value in (('entrypoint', args.entrypoint), ('trust_boundary', args.trust_boundary), ('latest_affected', args.latest_affected), ('novelty', args.novelty), ('impact', args.impact), ('attacker_control', args.attacker_control), ('sink', args.sink), ('cve', args.cve), ('cwe', args.cwe), ('cvss', args.cvss), ('negative_controls', args.negative_controls), ('root_cause', args.root_cause), ('variant_analysis', args.variant_analysis), ('patch_diff', args.patch_diff), ('exploitability', args.exploitability), ('disclosure_quality', args.disclosure_quality), ('safety_notes', args.safety_notes), ('proof', args.proof)):
            if value is not None:
                cand[key] = value
        if args.reason:
            cand['decision_reason'] = args.reason
        event = f'status:{args.status}' if args.status is not None else f'triage_verdict:{args.triage_verdict}'
        cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': event, 'reason': args.reason or ''})
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} -> {(args.status if args.status is not None else 'triage:' + str(args.triage_verdict))}")

def cmd_candidates(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    for cand in data.get('candidates', []):
        print(f"{cand['id']} [{cand.get('status')}] {cand.get('title')} (proof={cand.get('proof')}, novelty={cand.get('novelty')}, cve={cand.get('cve')})")

def cmd_prove(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    proof_dir = run_dir / 'evidence' / args.candidate_id / stamp
    proof_dir.mkdir(parents=True, exist_ok=True)
    base = proof_dir / 'proof'
    cwd = run_path(args.cwd).resolve() if args.cwd else proof_dir.resolve()
    if not cwd.exists() or not cwd.is_dir():
        raise SystemExit(f'proof cwd does not exist or is not a directory: {cwd}')
    if args.shell:
        popen_args: str | list[str] = args.cmd
    else:
        popen_args = shlex.split(args.cmd)
        if not popen_args:
            raise SystemExit('empty proof command')

    def limit_child() -> None:
        try:
            import resource
            if args.cpu_seconds:
                _h.resource.setrlimit(_h.resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 1))
            if args.memory_mb:
                limit = args.memory_mb * 1024 * 1024
                _h.resource.setrlimit(_h.resource.RLIMIT_AS, (limit, limit))
            if args.file_mb:
                limit = args.file_mb * 1024 * 1024
                _h.resource.setrlimit(_h.resource.RLIMIT_FSIZE, (limit, limit))
        except Exception:
            pass
    timed_out = False
    try:
        raw_out = base.with_suffix('.out.raw')
        raw_err = base.with_suffix('.err.raw')
        with raw_out.open('wb') as out_fh, raw_err.open('wb') as err_fh:
            proc = subprocess.Popen(popen_args, cwd=str(cwd), shell=args.shell, text=False, stdout=out_fh, stderr=err_fh, start_new_session=True, preexec_fn=limit_child if sys.platform != 'win32' else None)
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
        raw_out = base.with_suffix('.out.raw')
        raw_err = base.with_suffix('.err.raw')
        raw_out.write_bytes(b'')
        raw_err.write_bytes(str(exc).encode('utf-8'))
        returncode = 127

    def materialize_capped(raw_path: Path, text_path: Path) -> bool:
        truncated = False
        written = 0
        with raw_path.open('rb') as src_fh, text_path.open('wb') as dst_fh:
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
                dst_fh.write(b'\n[truncated]\n')
                truncated = True
        return truncated
    stdout_truncated = materialize_capped(base.with_suffix('.out.raw'), base.with_suffix('.out'))
    stderr_truncated = materialize_capped(base.with_suffix('.err.raw'), base.with_suffix('.err'))
    command_record = {'cmd': args.cmd, 'argv_mode': not args.shell, 'shell': args.shell, 'cwd': str(cwd), 'timeout_seconds': args.timeout, 'cpu_seconds': args.cpu_seconds, 'memory_mb': args.memory_mb, 'file_mb': args.file_mb, 'timed_out': timed_out, 'returncode': returncode}
    write_json(base.with_suffix('.cmd.json'), command_record)
    write_text(base.with_suffix('.status'), str(returncode) + '\n')
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        cand = find_candidate(data, args.candidate_id)
        cand['proof'] = 'passed' if returncode == 0 else 'failed'
        cand['last_proof'] = {**command_record, 'stdout': rel(base.with_suffix('.out')), 'stderr': rel(base.with_suffix('.err')), 'stdout_raw': rel(base.with_suffix('.out.raw')), 'stderr_raw': rel(base.with_suffix('.err.raw')), 'status': rel(base.with_suffix('.status')), 'command_record': rel(base.with_suffix('.cmd.json')), 'stdout_truncated': stdout_truncated, 'stderr_truncated': stderr_truncated}
        cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': f"prove:{cand['proof']}"})
        save_candidates(run_dir, data)
    print(f"{args.candidate_id} proof={('passed' if returncode == 0 else 'failed')} status={returncode}")
    if returncode != 0:
        raise SystemExit(returncode if 0 < returncode < 126 else 1)

def _candidate_variant_patterns(cand: dict[str, Any], supplied: list[str] | None) -> list[str]:
    patterns: list[str] = []
    if supplied:
        patterns.extend(supplied)
    for key in ('sink', 'entrypoint', 'surface', 'root_cause', 'title', 'trust_boundary', 'negative_controls'):
        value = str(cand.get(key, '') or '').strip()
        if value and len(value) <= 120:
            patterns.append(value)
    seed_text = ' '.join((str(cand.get(key, '') or '') for key in ('title', 'surface', 'sink', 'root_cause', 'trust_boundary')))
    for term in re.findall('[A-Za-z_][A-Za-z0-9_]{3,}', seed_text):
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
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    patterns = _candidate_variant_patterns(cand, args.pattern)
    if not patterns:
        raise SystemExit('no variant search patterns available; pass --pattern')
    out_dir = run_dir / 'variant_analysis'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'{args.candidate_id}_{stamp}'
    paths = args.path or []
    searches: list[dict[str, Any]] = []
    for pattern in patterns:
        cmd = ['rg', '-n', '-S', '-F', pattern]
        cmd.extend(paths)
        result = _h.run_cmd(cmd, src, timeout=args.timeout)
        hits = result['stdout'].splitlines()[:args.max_hits] if result['returncode'] in (0, 1) else []
        searches.append({'pattern': pattern, 'paths': paths, 'returncode': result['returncode'], 'timeout': result['timeout'], 'hit_count_capped': len(hits), 'hits': hits, 'stderr': result['stderr'].strip()})
    artifact = {'candidate_id': args.candidate_id, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'purpose': 'Find sibling surfaces by root-cause terms, sinks, event names, and shared helpers.', 'manual_notes': args.notes or '', 'searches': searches}
    dump_yaml(artifact, base.with_suffix('.yaml'))
    md = [f'# Variant Analysis: {args.candidate_id}', '', f'- Source: `{rel(src)}`', f"- Candidate: `{cand.get('title', '')}`", f"- Notes: {args.notes or ''}", '', '## Search Results', '']
    for item in searches:
        md.extend([f"### `{item['pattern']}`", '', f"- Return code: `{item['returncode']}`", f"- Timeout: `{item['timeout']}`", f"- Hits captured: `{item['hit_count_capped']}`", ''])
        if item['stderr']:
            md.append(f"- Stderr: `{item['stderr']}`")
            md.append('')
        if item['hits']:
            for hit in item['hits']:
                md.append(f'- `{hit}`')
        else:
            md.append('- No hits')
        md.append('')
    write_text(base.with_suffix('.md'), '\n'.join(md))

    def mark_variant(updated: dict[str, Any]) -> None:
        updated['variant_analysis'] = rel(base.with_suffix('.md'))
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'variant-analysis', 'artifact': rel(base.with_suffix('.md'))})
    update_candidate_locked(run_dir, args.candidate_id, mark_variant)
    print(rel(base.with_suffix('.md')))

def cmd_patch_diff(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    out_dir = run_dir / 'patch_diff'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'{args.candidate_id}_{stamp}'
    paths = args.path or []
    refs = f'{args.base}..{args.head}'
    ref_checks = {'base': _h.run_cmd(['git', 'rev-parse', '--verify', args.base], src, timeout=15), 'head': _h.run_cmd(['git', 'rev-parse', '--verify', args.head], src, timeout=15)}
    missing_refs = [name for name, result in ref_checks.items() if result['returncode'] != 0]
    if missing_refs:
        hint = 'Missing git ref(s): ' + ', '.join(missing_refs) + '. Fetch tags/history first, e.g. `git fetch --tags --prune --unshallow` or use refs present in this checkout.'
        artifact = {'candidate_id': args.candidate_id, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'base': args.base, 'head': args.head, 'ref_checks': ref_checks, 'error': hint}
        dump_yaml(artifact, base.with_suffix('.yaml'))
        write_text(base.with_suffix('.md'), f'# Patch Diff Review: {args.candidate_id}\n\n{hint}\n')
        print(rel(base.with_suffix('.md')))
        raise SystemExit(2)
    stat = _h.run_cmd(['git', 'diff', '--stat', refs, '--', *paths], src, timeout=args.timeout)
    names = _h.run_cmd(['git', 'diff', '--name-status', refs, '--', *paths], src, timeout=args.timeout)
    patch = _h.run_cmd(['git', 'diff', f'--unified={args.context}', refs, '--', *paths], src, timeout=args.timeout)
    grep_results = []
    for pattern in args.grep or []:
        grep_results.append({'pattern': pattern, 'result': _h.run_cmd(['git', 'diff', '-G', pattern, '--name-only', refs, '--', *paths], src, timeout=args.timeout)})
    patch_text = patch['stdout']
    if len(patch_text) > args.max_patch_chars:
        patch_text = patch_text[:args.max_patch_chars] + '\n\n[truncated]\n'
    artifact = {'candidate_id': args.candidate_id, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'base': args.base, 'head': args.head, 'paths': paths, 'manual_notes': args.notes or '', 'stat': stat, 'name_status': names, 'grep_results': grep_results, 'patch_truncated_to_chars': args.max_patch_chars, 'patch_returncode': patch['returncode'], 'patch_timeout': patch['timeout'], 'patch_stderr': patch['stderr']}
    dump_yaml(artifact, base.with_suffix('.yaml'))
    write_text(base.with_suffix('.diff'), patch_text)
    md = [f'# Patch Diff Review: {args.candidate_id}', '', f'- Source: `{rel(src)}`', f'- Range: `{refs}`', f"- Paths: `{(', '.join(paths) if paths else '<all>')}`", f"- Notes: {args.notes or ''}", '', '## Diff Stat', '', '```text', stat['stdout'].strip() or stat['stderr'].strip() or '<empty>', '```', '', '## Changed Files', '', '```text', names['stdout'].strip() or names['stderr'].strip() or '<empty>', '```', '', '## Patch', '', f"Patch saved to `{rel(base.with_suffix('.diff'))}`.", '']
    if grep_results:
        md.extend(['## Grep Diffs', ''])
        for item in grep_results:
            result = item['result']
            md.extend([f"### `{item['pattern']}`", '', '```text', result['stdout'].strip() or result['stderr'].strip() or '<empty>', '```', ''])
    write_text(base.with_suffix('.md'), '\n'.join(md))

    def mark_patch_diff(updated: dict[str, Any]) -> None:
        updated['patch_diff'] = rel(base.with_suffix('.md'))
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'patch-diff', 'artifact': rel(base.with_suffix('.md')), 'range': refs})
    update_candidate_locked(run_dir, args.candidate_id, mark_patch_diff)
    print(rel(base.with_suffix('.md')))

def cmd_cluster_variants(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    variant = _h._load_latest_variant_yaml(run_dir, args.candidate_id)
    out_dir = run_dir / 'variant_clusters'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'{args.candidate_id}_{stamp}'
    clusters: dict[str, dict[str, Any]] = {}
    for search in variant.get('searches', []):
        pattern = search.get('pattern', '')
        for hit in search.get('hits', []):
            file_name = _h._hit_file(hit)
            cluster = clusters.setdefault(file_name, {'file': file_name, 'patterns': set(), 'symbols': set(), 'hits': []})
            cluster['patterns'].add(pattern)
            cluster['symbols'].add(_h._hit_symbol(hit))
            cluster['hits'].append(hit)
    serializable = []
    for item in clusters.values():
        serializable.append({'file': item['file'], 'patterns': sorted(item['patterns']), 'symbols': sorted(item['symbols']), 'hit_count': len(item['hits']), 'hits': item['hits'][:args.max_hits]})
    serializable.sort(key=lambda item: (-item['hit_count'], item['file']))
    artifact = {'candidate_id': args.candidate_id, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_variant_artifact': variant.get('generated_at', ''), 'cluster_count': len(serializable), 'clusters': serializable}
    dump_yaml(artifact, base.with_suffix('.yaml'))
    md = [f'# Variant Clusters: {args.candidate_id}', '', f"- Candidate: `{cand.get('title', '')}`", f'- Clusters: `{len(serializable)}`', '']
    for cluster in serializable[:args.max_clusters]:
        md.extend([f"## `{cluster['file']}`", '', f"- Hit count: `{cluster['hit_count']}`", f"- Patterns: `{', '.join(cluster['patterns'])}`", f"- Symbols: `{', '.join(cluster['symbols'])}`", ''])
        for hit in cluster['hits']:
            md.append(f'- `{hit}`')
        md.append('')
    write_text(base.with_suffix('.md'), '\n'.join(md))

    def mark_clusters(updated: dict[str, Any]) -> None:
        updated['variant_clusters'] = rel(base.with_suffix('.md'))
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'variant-clusters', 'artifact': rel(base.with_suffix('.md')), 'cluster_count': len(serializable)})
    update_candidate_locked(run_dir, args.candidate_id, mark_clusters)
    print(rel(base.with_suffix('.md')))

def _candidate_intent_match(cand: dict[str, Any], tokens: list[str]) -> str:
    if not tokens:
        return ''
    blob = ' '.join((str(cand.get(field) or '').lower() for field in ('kind', 'weakness', 'cwe', 'surface', 'title', 'impact')))
    for token in tokens:
        spec = _h.INTENT_VOCAB.get(token, {})
        if token in blob or any((kw in blob for kw in spec.get('keywords', set()))):
            return token
    return ''

def _score_candidate(cand: dict[str, Any], intent_tokens: list[str] | None=None) -> tuple[int, list[str], list[str]]:
    score = 0
    strengths: list[str] = []
    gaps: list[str] = []
    checks = [('attacker_control', 8, 24, 'attacker control described with substance'), ('entrypoint', 8, 12, 'entrypoint described'), ('trust_boundary', 9, 24, 'trust boundary described with substance'), ('sink', 8, 12, 'sink described'), ('impact', 10, 32, 'impact described as concrete security consequence'), ('negative_controls', 10, 24, 'negative control recorded'), ('root_cause', 10, 32, 'root cause recorded as invariant'), ('variant_analysis', 8, 24, 'variant analysis artifact recorded'), ('patch_diff', 8, 12, 'patch/advisory artifact recorded')]
    for field, points, min_chars, label in checks:
        value = cand.get(field)
        if _h.substantive_text(value, min_chars):
            score += points
            strengths.append(label)
        else:
            gaps.append(f'{field}_substance')
    if validate_cwe(str(cand.get('cwe', ''))):
        score += 4
        strengths.append('CWE validated')
    else:
        gaps.append('valid_cwe')
    cvss_score, cvss_error = cvss3_base_score(str(cand.get('cvss', '')))
    if cvss_score is not None:
        score += 4
        strengths.append(f'CVSS validated ({cvss_score})')
    else:
        gaps.append(f'valid_cvss:{cvss_error}')
    proof = cand.get('proof')
    if proof == 'passed':
        score += 12
        strengths.append('proof passed')
        last_proof = cand.get('last_proof') if isinstance(cand.get('last_proof'), dict) else {}
        if last_proof and all((_h.artifact_exists(last_proof.get(key)) for key in ('stdout', 'stderr', 'status', 'command_record'))):
            score += 5
            strengths.append('proof artifacts present')
        else:
            gaps.append('proof_artifacts')
    else:
        gaps.append('proof_passed')
    if exact_affected_version(cand.get('latest_affected')):
        score += 8
        strengths.append('exact affected version/commit confirmed')
    else:
        gaps.append('exact_latest_affected')
    novelty = cand.get('novelty')
    coverage = _h.duplicate_source_coverage(cand)
    if novelty in {'no-known-duplicate', 'low-public-footprint'}:
        score += 6
        strengths.append(f'novelty status: {novelty}')
    elif novelty == 'possible-regression':
        score += 4
        strengths.append('possible regression status')
    else:
        gaps.append('novelty')
    coverage_points = sum((1 for ok in coverage.values() if ok))
    if coverage_points >= 3:
        score += 6
        strengths.append('multi-source duplicate/advisory coverage')
    elif coverage_points >= 2:
        score += 3
        strengths.append('partial duplicate/advisory coverage')
    else:
        gaps.append('multi_source_dedup')
    if _h.substantive_text(cand.get('proof_plan'), 6) or _h.artifact_exists(cand.get('proof_plan')):
        score += 2
        strengths.append('proof plan recorded')
    ready, strict_blockers, _warnings = _h.report_readiness_findings(cand)
    if ready:
        score += 8
        strengths.append('strict report gate clean')
    else:
        gaps.extend(strict_blockers[:8])
    tuning = load_outcome_tuning()
    candidate_adjustment = 0.0
    for section, key in (('weakness_adjustments', str(cand.get('cwe') or cand.get('weakness') or '')), ('evidence_kind_adjustments', str(cand.get('evidence_kind') or '')), ('module_adjustments', str(cand.get('campaign_module') or ''))):
        item = (tuning.get(section) or {}).get(key, {})
        if item:
            candidate_adjustment += float(item.get('score_adjustment') or 0) / 6
    if candidate_adjustment:
        bounded = max(-6, min(6, round(candidate_adjustment, 2)))
        score += int(round(bounded))
        strengths.append(f'outcome tuning adjustment {bounded}') if bounded > 0 else gaps.append(f'outcome_tuning_adjustment_{bounded}')
    intent_match = _candidate_intent_match(cand, intent_tokens or [])
    if intent_match:
        score += 5
        strengths.append(f'intent-aligned ({intent_match})')
    if 'proof_passed' in gaps:
        score = min(score, 84)
    if 'exact_latest_affected' in gaps:
        score = min(score, 80)
    if 'novelty' in gaps:
        score = min(score, 76)
    if strict_blockers:
        score = min(score, 88)
    return (min(score, 100), strengths, gaps)

def cmd_hypothesize(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    graph = _h._load_source_graph(run_dir)
    out_dir = run_dir / 'hypotheses'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    hypotheses = _h._build_hypotheses(graph, args.files_per_hypothesis)
    intent_tokens = _h._intent_tokens(state)
    _h._order_hypotheses_by_intent(hypotheses, intent_tokens)
    artifact = {'target_id': target['id'], 'run_id': state.get('run_id'), 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_graph': rel(run_dir / 'source_graph' / 'source_graph.yaml'), 'intent': intent_tokens, 'hypotheses': hypotheses[:args.max_hypotheses]}
    dump_yaml(artifact, out_dir / f'hypotheses_{stamp}.yaml')
    md = [f"# Research Hypotheses: {target['id']}", '']
    if intent_tokens:
        md.append(f"- Intent (threat model): `{', '.join(intent_tokens)}`")
    md.extend([f"- Run: `{state.get('run_id')}`", ''])
    for hyp in artifact['hypotheses']:
        marker = ' (intent-priority)' if hyp.get('intent_priority') else ''
        md.extend([f"## {hyp['id']}: {hyp['title']}{marker}", '', f"- Kind: `{hyp['kind']}`", f"- Rationale: {hyp['rationale']}", f"- Next step: {hyp['next_step']}", '', '### Files', ''])
        for file_name in hyp['files']:
            md.append(f'- `{file_name}`')
        md.append('')
    write_text(out_dir / f'hypotheses_{stamp}.md', '\n'.join(md))
    print(rel(out_dir / f'hypotheses_{stamp}.md'))

def cmd_patch_mine(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    ranges = args.range or ['HEAD..HEAD']
    patterns = args.grep or _h.SECURITY_DIFF_PATTERNS
    paths = args.path or []
    out_dir = run_dir / 'patch_mining'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    range_results = []
    for ref_range in ranges:
        stat = _h.run_cmd(['git', 'diff', '--stat', ref_range, '--', *paths], src, timeout=args.timeout)
        names = _h.run_cmd(['git', 'diff', '--name-status', ref_range, '--', *paths], src, timeout=args.timeout)
        pattern_results = []
        for pattern in patterns:
            result = _h.run_cmd(['git', 'diff', '-G', pattern, '--name-status', ref_range, '--', *paths], src, timeout=args.timeout)
            pattern_results.append({'pattern': pattern, 'returncode': result['returncode'], 'timeout': result['timeout'], 'matches': result['stdout'].splitlines()[:args.max_matches], 'stderr': result['stderr'].strip()})
        range_results.append({'range': ref_range, 'stat': stat, 'name_status': names, 'patterns': pattern_results})
    artifact = {'target_id': target['id'], 'run_id': state.get('run_id'), 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'paths': paths, 'ranges': range_results}
    dump_yaml(artifact, out_dir / f'patch_mining_{stamp}.yaml')
    md = [f"# Patch Mining: {target['id']}", '', f'- Source: `{rel(src)}`', '']
    for item in range_results:
        md.extend([f"## `{item['range']}`", '', '### Diff Stat', '', '```text', item['stat']['stdout'].strip() or item['stat']['stderr'].strip() or '<empty>', '```', '', '### Changed Files', '', '```text', item['name_status']['stdout'].strip() or item['name_status']['stderr'].strip() or '<empty>', '```', '', '### Security Pattern Matches', ''])
        for pattern_result in item['patterns']:
            if not pattern_result['matches'] and (not pattern_result['stderr']):
                continue
            md.extend([f"#### `{pattern_result['pattern']}`", ''])
            if pattern_result['matches']:
                for match in pattern_result['matches']:
                    md.append(f'- `{match}`')
            if pattern_result['stderr']:
                md.append(f"- Stderr: `{pattern_result['stderr']}`")
            md.append('')
    write_text(out_dir / f'patch_mining_{stamp}.md', '\n'.join(md))
    print(rel(out_dir / f'patch_mining_{stamp}.md'))

def cmd_proof_plan(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    out_dir = run_dir / 'proof_plans'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = out_dir / f'{args.candidate_id}_{stamp}.md'
    md = [f'# Proof Plan: {args.candidate_id}', '', f"- Title: {cand.get('title', '')}", f"- Current status: `{cand.get('status', '')}`", f"- Exploitability target: `{args.level or cand.get('exploitability', 'L3 deterministic local security impact')}`", '', '## Thesis', '', f"- Attacker control: {cand.get('attacker_control', '')}", f"- Entrypoint: {cand.get('entrypoint', '')}", f"- Trust boundary: {cand.get('trust_boundary', '')}", f"- Sink: {cand.get('sink', '')}", f"- Impact: {cand.get('impact', '')}", '', '## Preconditions', '', '- Current/latest affected version is installed locally.', '- Test instance is self-hosted or otherwise explicitly authorized.', '- Required feature flags/configuration are recorded.', '- Test users/roles needed for positive and negative controls exist.', '', '## Positive Proof', '', args.positive or '- Execute the vulnerable workflow and capture the security-relevant output.', '', '## Negative Controls', '', cand.get('negative_controls') or '- Add at least one denied/benign/patched control before claiming impact.', '', '## Evidence To Capture', '', '- Exact version, commit, package versions, and configuration.', '- Command, stdout, stderr, exit status, and timestamps.', '- Positive proof artifact.', '- Negative-control artifact.', '- Cleanup result.', '', '## Cleanup', '', args.cleanup or '- Remove test users, temporary files, services, database state, and tokens created for the proof.', '', '## Submission Blockers', '', '- No latest-version proof.', '- No negative control.', '- No clear root cause.', '- Duplicate/advisory status not checked.', '- Impact relies on speculation rather than captured behavior.', '']
    write_text(out, '\n'.join(md))

    def mark_proof_plan(updated: dict[str, Any]) -> None:
        updated['proof_plan'] = rel(out)
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'proof-plan', 'artifact': rel(out)})
    update_candidate_locked(run_dir, args.candidate_id, mark_proof_plan)
    print(rel(out))

def _terms_from_candidate(cand: dict[str, Any], supplied: list[str] | None) -> list[str]:
    terms = list(supplied or [])
    for key in ('entrypoint', 'sink', 'root_cause', 'trust_boundary', 'title', 'impact'):
        value = str(cand.get(key, '') or '')
        terms.extend(re.findall('[A-Za-z_][A-Za-z0-9_]{4,}', value))
    seen: set[str] = set()
    output = []
    for term in terms:
        lowered = term.lower()
        if lowered in COMMON_VARIANT_TERMS or lowered in seen:
            continue
        seen.add(lowered)
        output.append(term)
    return output[:30]

def cmd_flow_trace(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    graph = _h._load_semantic_graph(run_dir)
    functions = graph.get('functions', [])
    terms = list(args.term or []) if args.only_terms else _terms_from_candidate(cand, args.term)
    out_dir = run_dir / 'flow_traces'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    term_hits = []
    function_hits: dict[str, dict[str, Any]] = {}
    for term in terms:
        cmd = ['rg', '-n', '-S', '-F', term]
        for path in args.path or []:
            cmd.append(path)
        if not args.include_tests:
            for glob in _h.DEFAULT_SOURCE_GRAPH_EXCLUDES:
                cmd.extend(['--glob', glob])
        result = _h.run_cmd(cmd, src, timeout=args.timeout)
        hits = result['stdout'].splitlines()[:args.max_hits] if result['returncode'] in (0, 1) else []
        mapped = []
        for hit in hits:
            parts = hit.split(':', 2)
            if len(parts) < 3:
                continue
            file_name, raw_line, text = parts
            try:
                line_no = int(raw_line)
            except ValueError:
                continue
            fn = _h._function_for_hit(functions, file_name, line_no)
            mapped_item = {'hit': hit, 'file': file_name, 'line': line_no, 'function': fn.get('name') if fn else '<module>', 'function_line': fn.get('line') if fn else '', 'categories': fn.get('categories', []) if fn else []}
            mapped.append(mapped_item)
            key = f"{file_name}:{mapped_item['function']}:{mapped_item['function_line']}"
            bucket = function_hits.setdefault(key, {'file': file_name, 'function': mapped_item['function'], 'function_line': mapped_item['function_line'], 'terms': set(), 'categories': set(mapped_item['categories']), 'hits': []})
            bucket['terms'].add(term)
            bucket['hits'].append(hit)
        term_hits.append({'term': term, 'mapped_hits': mapped, 'returncode': result['returncode']})
    ranked = []
    for item in function_hits.values():
        categories = set(item['categories'])
        score = len(item['terms']) * 5 + len(categories) * 3
        if 'authz_checks' in categories:
            score += 8
        if 'events_broadcasts' in categories:
            score += 8
        if 'routes_handlers' in categories:
            score += 6
        if 'network_clients' in categories or 'process_execution' in categories:
            score += 6
        ranked.append({'score': score, 'file': item['file'], 'function': item['function'], 'function_line': item['function_line'], 'terms': sorted(item['terms']), 'categories': sorted(categories), 'hits': item['hits'][:args.max_hits_per_function]})
    ranked.sort(key=lambda item: (-item['score'], item['file'], str(item['function_line'])))
    artifact = {'candidate_id': args.candidate_id, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'terms': terms, 'ranked_functions': ranked[:args.max_functions], 'term_hits': term_hits}
    base = out_dir / f'{args.candidate_id}_{stamp}'
    dump_yaml(artifact, base.with_suffix('.yaml'))
    md = [f'# Flow Trace: {args.candidate_id}', '', f"- Candidate: `{cand.get('title', '')}`", f"- Terms: `{', '.join(terms)}`", '', '## Ranked Functions', '']
    for item in ranked[:args.max_functions]:
        md.extend([f"### `{item['file']}:{item['function_line']} {item['function']}`", '', f"- Score: `{item['score']}`", f"- Terms: `{', '.join(item['terms'])}`", f"- Categories: `{', '.join(item['categories'])}`", ''])
        for hit in item['hits']:
            md.append(f'- `{hit}`')
        md.append('')
    write_text(base.with_suffix('.md'), '\n'.join(md))

    def mark_flow(updated: dict[str, Any]) -> None:
        updated['flow_trace'] = rel(base.with_suffix('.md'))
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'flow-trace', 'artifact': rel(base.with_suffix('.md'))})
    update_candidate_locked(run_dir, args.candidate_id, mark_flow)
    print(rel(base.with_suffix('.md')))

def _candidate_from_blackbox(item: dict[str, Any], next_id: str) -> dict[str, Any]:
    severity = str(item.get('severity') or 'unknown').lower()
    cve_match = re.search('CVE-\\d{4}-\\d{4,}', json.dumps(item), flags=re.IGNORECASE)
    title = item.get('title') or item.get('name') or item.get('template_id') or 'Blackbox scanner finding'
    cwe = item.get('cwe') or ('CWE-200' if 'exposure' in title.lower() or 'leak' in title.lower() else 'CWE-693')
    impact = item.get('impact') or f'Blackbox evidence reported severity `{severity}` for `{title}`.'
    return _normalize_candidate({'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'id': next_id, 'title': str(title)[:180], 'status': 'candidate', 'surface': item.get('surface') or 'outside-in blackbox', 'weakness': cwe, 'impact': impact, 'attacker_control': item.get('attacker_control') or 'remote HTTP/TLS request within authorized blackbox scope', 'entrypoint': item.get('matched_at') or item.get('url') or item.get('host') or '', 'trust_boundary': 'external client to exposed service', 'latest_affected': 'unchecked', 'sink': item.get('sink') or item.get('evidence') or str(title), 'novelty': 'unchecked', 'proof': 'not_started', 'cve': cve_match.group(0).upper() if cve_match else 'N/A', 'cwe': cwe, 'cvss': '', 'notes': item.get('notes') or '', 'created_at': dt.datetime.now().isoformat(timespec='seconds'), 'history': [{'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'created:ingest-blackbox-run'}]})

def cmd_ingest_blackbox_run(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    evidence_dir = run_path(args.evidence_dir)
    if not evidence_dir.exists():
        raise SystemExit(f'blackbox evidence directory not found: {evidence_dir}')
    findings = []
    for path in sorted(evidence_dir.rglob('*')):
        if not path.is_file() or path.stat().st_size > args.max_file_mb * 1024 * 1024:
            continue
        if path.suffix.lower() in {'.json', '.jsonl'}:
            findings.extend(_h._parse_blackbox_json(path, args.include_info))
        elif path.suffix.lower() in {'.txt', '.md', '.log', '.csv'}:
            findings.extend(_h._parse_blackbox_text(path, args.include_info))
    findings = findings[:args.max_findings]
    out_dir = run_dir / 'blackbox_ingest'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    artifact = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'evidence_dir': rel(evidence_dir), 'finding_count': len(findings), 'findings': findings}
    dump_yaml(artifact, out_dir / f'blackbox_ingest_{stamp}.yaml')
    created = []
    if args.create_candidates and findings:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in findings:
                cand = _candidate_from_blackbox(item, next_candidate_id(data))
                data.setdefault('candidates', []).append(cand)
                created.append(cand['id'])
            save_candidates(run_dir, data)
    md = ['# Blackbox Evidence Ingest', '', f'- Evidence dir: `{rel(evidence_dir)}`', f'- Findings parsed: `{len(findings)}`', f"- Candidates created: `{', '.join(created) or 'none'}`", '']
    for item in findings:
        md.extend([f"## {item.get('title')}", '', f"- Severity: `{item.get('severity')}`", f"- Matched at: `{item.get('matched_at', '')}`", f"- Source file: `{item.get('source_file', '')}`", f"- Evidence: `{str(item.get('evidence', ''))[:300]}`", ''])
    write_text(out_dir / f'blackbox_ingest_{stamp}.md', '\n'.join(md))
    print(rel(out_dir / f'blackbox_ingest_{stamp}.md'))

def cmd_guard_drift(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    categories = args.sink_category or ['file_storage', 'path_traversal', 'deserialization', 'network_clients', 'process_execution']
    sink_patterns = {category: _h.GUARD_DRIFT_SINK_OVERRIDES.get(category, _h.GRAPH_QUERIES[category]) for category in categories if category in _h.GRAPH_QUERIES or category in _h.GUARD_DRIFT_SINK_OVERRIDES}
    if not sink_patterns:
        raise SystemExit('no valid sink categories selected')
    guard_regex = args.guard_regex or _h.DEFAULT_GUARD_DRIFT_REGEX
    functions = _h._guard_drift_functions(src, args.include_tests, args.path, args.max_files, args.max_functions)
    guarded: list[dict[str, Any]] = []
    unguarded: list[dict[str, Any]] = []
    for fn in functions:
        body_lines = fn.get('body_lines', [])
        if not body_lines:
            continue
        active_lines = _h._active_code_lines(body_lines)
        body = '\n'.join(active_lines)
        guard_hits = _h._line_hits(active_lines, guard_regex, int(fn.get('line', 1)))
        for category, sink_regex in sink_patterns.items():
            if not re.search(sink_regex, body, flags=re.IGNORECASE):
                continue
            item = {'category': category, 'file': fn.get('file', ''), 'function': fn.get('name', ''), 'line': fn.get('line', ''), 'end_line': fn.get('end_line', ''), 'signature': fn.get('signature', ''), 'sink_hits': _h._line_hits(active_lines, sink_regex, int(fn.get('line', 1))), 'guard_hits': guard_hits}
            if guard_hits:
                guarded.append(item)
            else:
                unguarded.append(item)
    candidates = []
    for item in unguarded:
        examples = _h._sibling_guarded_examples(item, guarded, args.examples)
        if args.require_guarded_sibling and (not examples):
            continue
        ranked = dict(item)
        ranked['guarded_examples'] = examples
        ranked['confidence'] = 'higher' if examples else 'low-no-guarded-sibling'
        candidates.append(ranked)
    candidates.sort(key=lambda item: (0 if item.get('guarded_examples') else 1, str(item.get('category')), str(item.get('file')), int(item.get('line') or 0)))
    candidates = candidates[:args.max_candidates]
    out_dir = run_dir / 'guard_drift'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'guard_drift_{stamp}'
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'target_id': target.get('id', ''), 'run_id': state.get('run_id', ''), 'source_path': rel(src), 'guard_regex': guard_regex, 'sink_categories': list(sink_patterns), 'functions_scanned': len(functions), 'guarded_sink_functions': len(guarded), 'unguarded_sink_functions': len(unguarded), 'candidate_count': len(candidates), 'candidates': candidates}
    dump_yaml(payload, base.with_suffix('.yaml'))
    md = ['# Guard Drift Analysis', '', f"- Target: `{target.get('id', '')}`", f'- Source: `{rel(src)}`', f'- Guard regex: `{guard_regex}`', f"- Sink categories: `{', '.join(sink_patterns)}`", f'- Functions scanned: `{len(functions)}`', f'- Guarded sink functions: `{len(guarded)}`', f'- Unguarded sink functions: `{len(unguarded)}`', f'- Candidate signals: `{len(candidates)}`', '']
    for item in candidates:
        md.extend([f"## `{item['file']}:{item['line']} {item['function']}`", '', f"- Category: `{item['category']}`", f"- Confidence: `{item['confidence']}`", f"- Signature: `{item.get('signature', '')}`", '', '### Sink Hits', ''])
        for hit in item.get('sink_hits', []):
            md.append(f"- `{hit['line']}`: `{hit['text']}`")
        md.extend(['', '### Guarded Sibling Examples', ''])
        if item.get('guarded_examples'):
            for example in item['guarded_examples']:
                md.append(f"- `{example['file']}:{example['line']} {example['function']}`")
                for hit in example.get('guard_hits', []):
                    md.append(f"  - guard `{hit['line']}`: `{hit['text']}`")
                for hit in example.get('sink_hits', []):
                    md.append(f"  - sink `{hit['line']}`: `{hit['text']}`")
        else:
            md.append('- No guarded sibling captured; treat as low-confidence broad sink inventory.')
        md.append('')
    write_text(base.with_suffix('.md'), '\n'.join(md))
    created = []
    if args.create_candidates and candidates:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in candidates[:args.create_limit]:
                cand = _h._guard_drift_candidate(item, next_candidate_id(data), base.with_suffix('.md'))
                data.setdefault('candidates', []).append(cand)
                created.append(cand['id'])
            save_candidates(run_dir, data)
    if created:
        print(f"{rel(base.with_suffix('.md'))} created={','.join(created)}")
    else:
        print(rel(base.with_suffix('.md')))

def recommend_next_action(run_dir: Path) -> dict[str, Any]:
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    candidates = data.get('candidates', [])
    stages = state.get('stages', {})
    if 'prepare' not in stages:
        return {'command': f'{sys.argv[0]} prepare {rel(run_dir)}', 'reason': 'Source fingerprint has not been captured.', 'priority': 'setup'}
    if 'map' not in stages:
        return {'command': f'{sys.argv[0]} map {rel(run_dir)}', 'reason': 'Attack-surface map is missing.', 'priority': 'setup'}
    if 'source_graph' not in stages:
        return {'command': f'{sys.argv[0]} source-graph {rel(run_dir)}', 'reason': 'Source graph is missing; hypotheses need surface ranking.', 'priority': 'setup'}
    if 'semantic_graph' not in stages:
        return {'command': f'{sys.argv[0]} semantic-graph {rel(run_dir)}', 'reason': 'Semantic graph is missing; flow and taint commands depend on it.', 'priority': 'setup'}
    if not candidates:
        return {'command': f'{sys.argv[0]} hypothesize {rel(run_dir)}', 'reason': 'No candidates exist; generate hypotheses from current source graph.', 'priority': 'triage'}
    for cand in candidates:
        verdict = str(cand.get('triage_verdict') or '').strip()
        if not verdict:
            return {'command': f"{sys.argv[0]} candidate-set {rel(run_dir)} {cand['id']} --triage-verdict <needs_proof|defended|false_positive>", 'candidate_id': cand['id'], 'reason': 'Flow has no triage verdict; classify it before any proof work.', 'priority': 'triage'}
        if verdict in {'defended', 'false_positive'}:
            continue
        if not dedup_checked(cand):
            return {'command': f"{sys.argv[0]} dedup {rel(run_dir)} {cand['id']} --check-osv", 'candidate_id': cand['id'], 'reason': 'Candidate has not passed the novelty gate.', 'priority': 'novelty'}
        ok, blockers = promotion_findings(cand)
        if not ok:
            return {'command': f"{sys.argv[0]} gate {rel(run_dir)} {cand['id']}", 'candidate_id': cand['id'], 'reason': 'Promotion gate has blockers: ' + ','.join(blockers), 'priority': 'gate'}
        if cand.get('proof') != 'passed':
            return {'command': f"{sys.argv[0]} proof-plan {rel(run_dir)} {cand['id']}", 'candidate_id': cand['id'], 'reason': 'Candidate is gate-clean but lacks passing proof.', 'priority': 'proof'}
        if not substantive(cand.get('root_cause')):
            return {'command': f"{sys.argv[0]} candidate-set {rel(run_dir)} {cand['id']} --status root_cause_recorded --root-cause '<broken invariant>'", 'candidate_id': cand['id'], 'reason': 'Proof passed but root cause is missing.', 'priority': 'root-cause'}
        if not substantive(cand.get('variant_analysis')):
            return {'command': f"{sys.argv[0]} variant {rel(run_dir)} {cand['id']}", 'candidate_id': cand['id'], 'reason': 'Proof passed but sibling-surface variant analysis is missing.', 'priority': 'variant'}
        if not substantive(cand.get('patch_diff')):
            return {'command': f"{sys.argv[0]} patch-diff {rel(run_dir)} {cand['id']} --base <old-ref> --head <new-ref>", 'candidate_id': cand['id'], 'reason': 'Patch/advisory review is missing or not scoped out.', 'priority': 'patch-review'}
        report_blockers = workflow_blockers(cand, 'report_ready')
        if report_blockers:
            return {'command': f"{sys.argv[0]} gate {rel(run_dir)} {cand['id']} --report-ready", 'candidate_id': cand['id'], 'reason': 'Report-ready blockers remain: ' + ','.join(report_blockers), 'priority': 'report'}
    return {'command': f'{sys.argv[0]} report {rel(run_dir)}', 'reason': 'No immediate candidate blockers found; regenerate report/dashboard and prepare review.', 'priority': 'reporting'}

def cmd_next_action(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    result = recommend_next_action(run_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result['command'])
        print('reason=' + result['reason'])

def cmd_orient(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, _ = _h.load_run(run_dir)
    cursor = _h._load_cursor(state)
    rec = recommend_next_action(run_dir)
    signature = _h._recommendation_signature(rec)
    pending = cursor.get('pending_step')
    if pending and pending.get('signature') == signature:
        step = pending
        reissued = True
    else:
        cursor['step_counter'] = int(cursor.get('step_counter', 0)) + 1
        step = _h._build_step(rec, cursor['step_counter'])
        cursor['pending_step'] = step
        _h._persist_cursor(run_dir, cursor)
        reissued = False
    out = {'step': step, 'reissued': reissued}
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"step {step['step_id']} [{step['state']}] {step['task']}")
        print('run: ' + step['command'])
        if step.get('gate'):
            print('gate: ' + step['gate'])
        print('expect: ' + step['required_result'])

def cmd_submit(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, _ = _h.load_run(run_dir)
    cursor = _h._load_cursor(state)
    pending = cursor.get('pending_step')
    if not pending:
        raise SystemExit('no pending step; run `orient` first')
    if pending.get('gate') and args.triage_verdict:
        if args.triage_verdict not in TRIAGE_VERDICTS:
            raise SystemExit(f'invalid triage verdict: {args.triage_verdict}')
        cand_id = pending.get('candidate_id')
        if not cand_id:
            raise SystemExit('triage step has no candidate to classify')

        def _set(cand: dict[str, Any]) -> None:
            cand['triage_verdict'] = args.triage_verdict
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': f'triage_verdict:{args.triage_verdict}'})
        update_candidate_locked(run_dir, cand_id, _set)
    weakness_key = ''
    cand_id = pending.get('candidate_id') or ''
    if cand_id:
        cand = next((c for c in load_candidates(run_dir).get('candidates', []) if c.get('id') == cand_id), None)
        if cand:
            weakness_key = str(cand.get('cwe') or cand.get('weakness') or '')
    outcome_id = _append_step_outcome({'run': rel(run_dir), 'target_id': state.get('target_id') or '', 'step_id': pending.get('step_id'), 'state': pending.get('state'), 'priority': pending.get('priority'), 'candidate_id': cand_id, 'weakness': weakness_key, 'signature': pending.get('signature'), 'triage_verdict': args.triage_verdict or '', 'note': args.note or ''})
    new_rec = recommend_next_action(run_dir)
    new_sig = _h._recommendation_signature(new_rec)
    advanced = new_sig != pending.get('signature') or pending.get('priority') == 'reporting'
    result: dict[str, Any] = {'advanced': advanced, 'outcome_id': outcome_id}
    if advanced:
        cursor.setdefault('history', []).append({'step_id': pending.get('step_id'), 'state': pending.get('state'), 'signature': pending.get('signature'), 'outcome_id': outcome_id})
        seen = cursor.setdefault('states_seen', [])
        st = pending.get('state')
        if st and st not in seen:
            seen.append(st)
        cursor['pending_step'] = None
        result['next'] = {'command': new_rec.get('command'), 'reason': new_rec.get('reason'), 'priority': new_rec.get('priority')}
    else:
        result['blocker'] = 'step did not advance the loop; same recommendation still pending'
        result['still_pending'] = pending.get('signature')
    _h._persist_cursor(run_dir, cursor)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif advanced:
        print(f'advanced; outcome={outcome_id}')
        print('next: ' + str(new_rec.get('command')))
    else:
        print('not advanced: ' + str(result['blocker']))

def _candidate_summary(cand: dict[str, Any]) -> dict[str, Any]:
    ok, blockers = promotion_findings(cand)
    return {'id': cand.get('id'), 'title': cand.get('title'), 'status': cand.get('status'), 'novelty': cand.get('novelty'), 'dedup_checked': dedup_checked(cand), 'proof': cand.get('proof'), 'gate_passed': ok, 'gate_blockers': blockers, 'quality_score': cand.get('quality_score', {}).get('score') if isinstance(cand.get('quality_score'), dict) else None, 'last_history': (cand.get('history') or [])[-5:] if isinstance(cand.get('history'), list) else []}

def _candidate_signal(cand: dict[str, Any]) -> str:
    fields = [cand.get('title', ''), cand.get('surface', ''), cand.get('weakness', ''), cand.get('sink', ''), cand.get('root_cause', ''), cand.get('impact', '')]
    return ' '.join((str(item) for item in fields))

def _term_set(text: str) -> set[str]:
    return {term.lower() for term in re.findall('[A-Za-z_][A-Za-z0-9_]{4,}', text) if term.lower() not in COMMON_VARIANT_TERMS}

def cmd_score_tune(args: argparse.Namespace) -> None:
    rows = read_jsonl(submissions_path())
    if args.since:
        since = _parse_time(args.since)
        if since:
            rows = [row for row in rows if (_parse_time(row.get('submitted_at')) or dt.datetime.min) >= since]
    candidates_by_key = {}
    for row in read_jsonl(candidate_corpus_path()):
        key = (row.get('run_dir'), row.get('candidate', {}).get('id'))
        candidates_by_key[key] = row.get('candidate', {})
    fields = ['attacker_control', 'entrypoint', 'trust_boundary', 'sink', 'impact', 'negative_controls', 'root_cause', 'variant_analysis', 'patch_diff', 'cvss', 'cwe']
    stats: dict[str, dict[str, int]] = {field: {'positive_present': 0, 'positive_absent': 0, 'negative_present': 0, 'negative_absent': 0} for field in fields}
    terminal = [row for row in rows if row.get('final_status')]
    for row in terminal:
        cand = candidates_by_key.get((row.get('candidate_run'), row.get('candidate_id')), {})
        positive = submission_positive(str(row.get('final_status')))
        for field in fields:
            present = substantive(cand.get(field))
            key = ('positive_' if positive else 'negative_') + ('present' if present else 'absent')
            stats[field][key] += 1
    recommendations = []
    for field, item in stats.items():
        pos_total = item['positive_present'] + item['positive_absent']
        neg_total = item['negative_present'] + item['negative_absent']
        if not pos_total or not neg_total:
            continue
        pos_rate = item['positive_present'] / pos_total
        neg_rate = item['negative_present'] / neg_total
        delta = round(pos_rate - neg_rate, 3)
        recommendations.append({'field': field, 'positive_presence_rate': round(pos_rate, 3), 'negative_presence_rate': round(neg_rate, 3), 'delta': delta})
    recommendations.sort(key=lambda item: -abs(item['delta']))
    out_dir = ROOT / 'vapt' / 'harness' / 'corpus'
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"score_tune_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    md = ['# Score Tuning Report', '', f'- Terminal submissions: `{len(terminal)}`', f'- Minimum recommended threshold: `{args.min_terminal}`', f"- Status: `{('sufficient' if len(terminal) >= args.min_terminal else 'insufficient-data')}`", '', '## Field Correlations', '']
    for item in recommendations:
        md.append(f"- `{item['field']}` positive_rate=`{item['positive_presence_rate']}` negative_rate=`{item['negative_presence_rate']}` delta=`{item['delta']}`")
    if not recommendations:
        md.append('- Not enough terminal positive/negative data yet.')
    write_text(out, '\n'.join(md) + '\n')
    print(rel(out))

def cmd_refine(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    probe_name = args.probe or _h.select_probe(cand)
    out_dir = run_dir / 'refine'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    if not probe_name:
        missing_class = cand.get('weakness') or cand.get('surface') or 'unknown'
        _h.log_tool_gap(run_dir, args.candidate_id, str(missing_class), 'No matching probe for candidate terms')
        artifact = {'candidate_id': args.candidate_id, 'status': 'tool-gap', 'missing_class': missing_class, 'iterations': []}
        dump_yaml(artifact, out_dir / f'{args.candidate_id}_{stamp}.yaml')
        print(rel(out_dir / f'{args.candidate_id}_{stamp}.yaml'))
        raise SystemExit(2)
    probe = _h.load_probe(probe_name)
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from probes.base import ProbeContext
    iterations = []
    for index in range(args.max_iterations):
        ctx = _h.ProbeContext(run_dir=run_dir, target=target, candidate=cand, knobs={'iteration': index + 1})
        probe.prepare(ctx)
        result = probe.run(ctx)
        evidence = probe.evidence(ctx, result)
        probe.cleanup(ctx)
        iterations.append({'iteration': index + 1, 'probe': probe_name, 'result': dict(result), 'evidence': rel(evidence)})
        if result.get('passed'):
            break
    artifact = {'candidate_id': args.candidate_id, 'probe': probe_name, 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'iterations': iterations}
    dump_yaml(artifact, out_dir / f'{args.candidate_id}_{stamp}.yaml')
    md = [f'# Refine: {args.candidate_id}', '', f'- Probe: `{probe_name}`', f'- Iterations: `{len(iterations)}`', '']
    for item in iterations:
        result = item['result']
        md.extend([f"## Iteration {item['iteration']}", '', f"- Passed: `{result.get('passed')}`", f"- Missing: `{', '.join(result.get('missing', []))}`", f"- Evidence: `{item['evidence']}`", f"- Next: {result.get('recommended_next', '')}", ''])
    write_text(out_dir / f'{args.candidate_id}_{stamp}.md', '\n'.join(md))
    update_candidate_locked(run_dir, args.candidate_id, lambda updated: updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'refine', 'probe': probe_name, 'artifact': rel(out_dir / f'{args.candidate_id}_{stamp}.md')}))
    print(rel(out_dir / f'{args.candidate_id}_{stamp}.md'))

def cmd_ingest_tool_scan(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    artifact = run_path(args.artifact)
    if not artifact.exists():
        raise SystemExit(f'tool scan artifact not found: {artifact}')
    records = _h.read_tool_records(artifact)
    findings = _h.normalize_scanner_findings(args.tool, records, artifact, args.include_low)[:args.max_findings]
    out_dir = run_dir / 'tool_scans' / 'ingest'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'tool_ingest_{args.tool}_{stamp}.json'
    created = []
    if args.create_candidates and findings:
        with candidate_ledger_lock(run_dir):
            data = load_candidates(run_dir)
            for item in findings:
                cand = _h.candidate_from_tool_finding(item, next_candidate_id(data))
                data.setdefault('candidates', []).append(cand)
                created.append(cand['id'])
            save_candidates(run_dir, data)
    output = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'tool': args.tool, 'artifact': rel(artifact), 'finding_count': len(findings), 'created_candidates': created, 'findings': findings}
    write_json(out_json, output)
    md = ['# Tool Scan Ingest', '', f'- Tool: `{args.tool}`', f'- Artifact: `{rel(artifact)}`', f'- Findings parsed: `{len(findings)}`', f"- Candidates created: `{', '.join(created) or 'none'}`", '']
    for item in findings:
        md.extend([f"## {item.get('title')}", '', f"- Severity: `{item.get('severity')}`", f"- CWE: `{item.get('cwe') or 'unset'}`", f"- CVE: `{item.get('cve') or 'N/A'}`", f"- Location: `{item.get('matched_at') or item.get('file') or item.get('package') or ''}`", f"- Evidence: {str(item.get('evidence', ''))[:300]}", ''])
    out_md = out_dir / f'tool_ingest_{args.tool}_{stamp}.md'
    write_text(out_md, '\n'.join(md))
    print(rel(out_md))
