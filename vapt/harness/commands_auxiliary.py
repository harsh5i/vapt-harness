"""Auxiliary CLI handlers: discovery sweep/list/claim, OSV cache stats/prefetch/clear, queue list/claim, mutation-plan, patch-first-plan, ledger-sqlite.

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
from core import CURRENT_CANDIDATE_SCHEMA_VERSION, HARNESS_VERSION, ROOT, candidate_corpus_path, rel, run_path, source_path, submissions_path
from gates.osv import OSV_CACHE_FRESH_HOURS, _osv_cache_connect, _osv_package_query, _osv_vuln_query, osv_cache_path
from ledger.candidates import _normalize_candidate, load_candidates
from ledger.submissions import submission_stats
from source.targets import _load_target_profile, _target_profile_paths
from watch.state import queue_dir, queue_entries, queue_entry_path


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def cmd_ledger_sqlite(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    db_path = run_path(args.db) if args.db else run_dir / 'candidates.sqlite'
    if args.from_sqlite:
        with candidate_ledger_lock(run_dir):
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute('select candidate_json from candidates order by rowid').fetchall()
            candidates = [_normalize_candidate(json.loads(row[0])) for row in rows]
            dump_yaml({'schema_version': CURRENT_CANDIDATE_SCHEMA_VERSION, 'candidates': candidates}, run_dir / 'candidates.yaml')
        print(rel(run_dir / 'candidates.yaml'))
        return
    data = load_candidates(run_dir)
    with sqlite3.connect(db_path) as conn:
        conn.execute('create table if not exists candidates (id text primary key, status text, title text, candidate_json text not null)')
        conn.execute('create table if not exists history (candidate_id text, at text, event text, history_json text not null)')
        conn.execute('delete from candidates')
        conn.execute('delete from history')
        for cand in data.get('candidates', []):
            conn.execute('insert or replace into candidates (id, status, title, candidate_json) values (?, ?, ?, ?)', (cand.get('id', ''), cand.get('status', ''), cand.get('title', ''), json.dumps(cand, sort_keys=False)))
            for item in cand.get('history', []) if isinstance(cand.get('history'), list) else []:
                conn.execute('insert into history (candidate_id, at, event, history_json) values (?, ?, ?, ?)', (cand.get('id', ''), item.get('at', ''), item.get('event', ''), json.dumps(item, sort_keys=False)))
        conn.commit()
    print(rel(db_path))

def cmd_osv_cache_stats(args: argparse.Namespace) -> None:
    path = osv_cache_path()
    if not path.exists():
        payload = {'path': rel(path), 'exists': False, 'package_rows': 0, 'vuln_rows': 0}
    else:
        with contextlib.closing(_osv_cache_connect()) as conn:
            package_rows = conn.execute('SELECT COUNT(*) FROM osv_package').fetchone()[0]
            vuln_rows = conn.execute('SELECT COUNT(*) FROM osv_vuln').fetchone()[0]
            oldest_pkg = conn.execute('SELECT MIN(fetched_at) FROM osv_package').fetchone()[0]
            newest_pkg = conn.execute('SELECT MAX(fetched_at) FROM osv_package').fetchone()[0]
            oldest_vuln = conn.execute('SELECT MIN(fetched_at) FROM osv_vuln').fetchone()[0]
            newest_vuln = conn.execute('SELECT MAX(fetched_at) FROM osv_vuln').fetchone()[0]
        payload = {'path': rel(path), 'exists': True, 'package_rows': package_rows, 'vuln_rows': vuln_rows, 'package_oldest': oldest_pkg, 'package_newest': newest_pkg, 'vuln_oldest': oldest_vuln, 'vuln_newest': newest_vuln, 'fresh_window_hours': OSV_CACHE_FRESH_HOURS}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for key, val in payload.items():
            print(f'{key}: {val}')

def cmd_osv_cache_prefetch(args: argparse.Namespace) -> None:
    targets = []
    for target_id in args.target:
        profile_path, target = _load_target_profile(target_id)
        if not profile_path:
            legacy = ROOT / 'vapt' / 'engagements' / target_id / 'target.yaml'
            if legacy.exists():
                target = load_yaml(legacy) or {}
                profile_path = legacy
        if not profile_path:
            print(f'skip {target_id}: no target profile found under vapt/engagements/', file=sys.stderr)
            continue
        targets.append((target_id, target))
    fetched_packages = 0
    fetched_vulns = 0
    errors: list[str] = []
    fake_args = argparse.Namespace(osv_ecosystem=None, osv_package=None, osv_version=None, osv_timeout=args.timeout, osv_cache_only=False, osv_fresh_only=args.refresh)
    for target_id, target in targets:
        try:
            pkg = _osv_package_query(target, fake_args)
            if pkg is not None:
                fetched_packages += 1
                for vuln in pkg.get('vulns', []) or []:
                    vuln_id = vuln.get('id')
                    if not vuln_id:
                        continue
                    try:
                        v = _osv_vuln_query(vuln_id, args.timeout, fresh_only=args.refresh)
                        if v is not None:
                            fetched_vulns += 1
                    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                        errors.append(f'{target_id}:{vuln_id}: {exc}')
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            errors.append(f'{target_id}:package: {exc}')
    payload = {'targets': [t for t, _ in targets], 'fetched_packages': fetched_packages, 'fetched_vulns': fetched_vulns, 'errors': errors}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f'prefetched packages={fetched_packages} vulns={fetched_vulns} errors={len(errors)}')
        for e in errors:
            print(f'  ! {e}', file=sys.stderr)

def cmd_osv_cache_clear(args: argparse.Namespace) -> None:
    path = osv_cache_path()
    if path.exists():
        path.unlink()
    payload = {'path': rel(path), 'cleared': True}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f'cleared {rel(path)}')

def cmd_discovery_sweep(args: argparse.Namespace) -> None:
    disc = _h._load_watch_module('discovery')
    advisories, fetch_errors = disc.fetch_recent_advisories(severity_floor=args.severity_floor, since_days=args.since_days, per_page=args.per_page, max_pages=args.max_pages, token=os.environ.get('GITHUB_TOKEN') or None, timeout=args.timeout)
    target_profile_paths = sorted((ROOT / 'vapt' / 'engagements').glob('*/targets/*.yaml'))
    watched = disc.watched_packages(target_profile_paths)
    proposals = disc.propose_targets(advisories, watched)
    written, skipped = disc.write_proposals(proposals, _h._discovery_queue_dir())
    payload = {'fetched_advisories': len(advisories), 'watched_packages': len(watched), 'proposals_total': len(proposals), 'proposals_written': written, 'proposals_skipped_existing': skipped, 'fetch_errors': fetch_errors, 'queue_dir': rel(_h._discovery_queue_dir() / disc.DISCOVERY_QUEUE_DIRNAME)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"advisories={payload['fetched_advisories']} proposals={payload['proposals_total']} written={payload['proposals_written']} skipped={payload['proposals_skipped_existing']}")
        for e in fetch_errors:
            print(f'  ! {e}', file=sys.stderr)

def cmd_discovery_list(args: argparse.Namespace) -> None:
    disc = _h._load_watch_module('discovery')
    rows = disc.list_proposals(_h._discovery_queue_dir(), include_claimed=args.all)
    if args.severity:
        wanted = {s.lower() for s in args.severity}
        rows = [r for r in rows if (r.get('severity') or '').lower() in wanted]
    if args.ecosystem:
        rows = [r for r in rows if (r.get('ecosystem') or '').lower() == args.ecosystem.lower()]
    if args.json:
        print(json.dumps({'proposals': rows}, indent=2, sort_keys=False))
    else:
        for r in rows:
            print(f"{r.get('proposal_slug')} [{r.get('severity')}] {r.get('ecosystem')}/{r.get('package')} -> {r.get('ghsa_id')} ({', '.join(r.get('cves') or []) or 'no-cve'})")

def cmd_discovery_claim(args: argparse.Namespace) -> None:
    disc = _h._load_watch_module('discovery')
    try:
        updated = disc.claim_proposal(_h._discovery_queue_dir(), args.slug, claimed_by=args.claimed_by, decision=args.decision, note=args.note or '')
    except FileNotFoundError as exc:
        raise SystemExit(f'proposal not found: {exc}')
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    eco = updated.get('ecosystem') or ''
    pkg = updated.get('package') or ''
    target_hint = re.sub('[^a-z0-9]+', '-', pkg.lower()).strip('-')
    watch_add_cmd = ''
    if updated.get('status') == 'claimed' and eco and pkg:
        watch_add_cmd = f'python3 vapt/harness/harness.py watch-add {target_hint} --source ghsa_advisories --ecosystem {eco} --package {pkg} --allow-network'
    payload = {'proposal_slug': args.slug, 'status': updated.get('status'), 'claimed_by': updated.get('claimed_by'), 'suggested_watch_add': watch_add_cmd}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"{args.slug}: status={updated.get('status')} by={updated.get('claimed_by')}")
        if watch_add_cmd:
            print(f'  next: {watch_add_cmd}')

def cmd_corpus_suggest(args: argparse.Namespace) -> None:
    profile_path, target = _load_target_profile(args.target_id)
    if not target:
        raise SystemExit(f'target profile not found: {args.target_id}')
    if not candidate_corpus_path().exists():
        _h.cmd_corpus_rebuild(argparse.Namespace())
    target_terms = _h._term_set(' '.join((str(x) for x in target.get('category', []) + target.get('in_scope', []))))
    rows = read_jsonl(candidate_corpus_path())
    suggestions = []
    for row in rows:
        cand = row.get('candidate', {})
        if row.get('target_id') == args.target_id:
            continue
        text = _h._candidate_signal(cand)
        terms = _h._term_set(text)
        overlap = sorted(target_terms & terms)
        if not overlap:
            continue
        status = str(cand.get('status') or '')
        proof_bonus = 5 if cand.get('proof') == 'passed' else 0
        positive_bonus = 8 if status in {'report-ready', 'validated-local-poc', 'triaged', 'resolved', 'paid'} else 0
        score = len(overlap) + proof_bonus + positive_bonus
        suggestions.append({'score': score, 'source_target': row.get('target_id'), 'source_run': row.get('run_dir'), 'candidate_id': cand.get('id'), 'title': cand.get('title'), 'surface': cand.get('surface'), 'weakness': cand.get('weakness'), 'sink': cand.get('sink'), 'overlap_terms': overlap[:20], 'rationale': 'Shared target/program terms plus prior proof/status signal.'})
    suggestions.sort(key=lambda item: (-item['score'], str(item['source_target']), str(item['candidate_id'])))
    payload = {'target_id': args.target_id, 'target_profile': rel(profile_path) if profile_path else '', 'suggestions': suggestions[:args.limit]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in payload['suggestions']:
            print(f"{item['score']} {item['source_target']} {item['candidate_id']} {item['title']}")
            print('  terms=' + ','.join(item['overlap_terms']))

def cmd_pick_target(args: argparse.Namespace) -> None:
    submissions = read_jsonl(submissions_path())
    stats = submission_stats(submissions)['programs']
    rows = read_jsonl(candidate_corpus_path()) if candidate_corpus_path().exists() else []
    target_results = []
    for path in _target_profile_paths():
        target = load_yaml(path) or {}
        if args.platform and args.platform.lower() not in str(target.get('program', '')).lower():
            continue
        target_id = target.get('id') or path.stem
        program = target.get('program') or target_id
        program_stats = stats.get(program, {})
        fresh_queue = 0
        candidate_count = sum((1 for row in rows if row.get('target_id') == target_id))
        accepted_like = sum((1 for row in rows if row.get('target_id') == target_id and (row.get('candidate', {}).get('proof') == 'passed' or row.get('candidate', {}).get('status') in {'report-ready', 'validated-local-poc'})))
        duplicate_pressure = len(target.get('known_duplicates') or [])
        category_bonus = len(target.get('in_scope') or []) / 2
        score = 10 + category_bonus + accepted_like * 4 + fresh_queue * 3
        score += float(program_stats.get('acceptance_rate', 0)) * 10
        score += min(float(program_stats.get('average_value', 0)) / 500, 10)
        score -= duplicate_pressure * 0.8
        if args.budget_minutes:
            score += min(int(args.budget_minutes), int((target.get('budgets') or _h.DEFAULT_BUDGETS).get('total_minutes', 480))) / 240
        target_results.append({'target_id': target_id, 'profile': rel(path), 'program': program, 'score': round(score, 2), 'candidate_count': candidate_count, 'accepted_like_candidates': accepted_like, 'known_duplicate_count': duplicate_pressure, 'rationale': 'Score uses in-scope breadth, prior local signal, known duplicate pressure, and submission outcomes when present.'})
    target_results.sort(key=lambda item: (-item['score'], item['target_id']))
    payload = {'ranked_targets': target_results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in target_results:
            print(f"{item['score']} {item['target_id']} {item['program']}")
            print(f"  {item['rationale']}")

def cmd_mutation_plan(args: argparse.Namespace) -> None:
    adapter_path, adapter = _h._load_target_adapter(args.target)
    catalog = _h.load_mutation_catalog()
    requested_modules = {args.module} if args.module else None
    modules = []
    for adapter_module in adapter.get('modules', []) or []:
        module_id = str(adapter_module.get('id') or '')
        local_name = str(adapter_module.get('local_name') or '')
        if requested_modules and module_id not in requested_modules and (local_name not in requested_modules):
            continue
        configured_families = adapter_module.get('mutation_families') or []
        if not configured_families:
            configured_families = [family_id for family_id, family in catalog.items() if module_id in set((str(item) for item in family.get('applies_to', [])))]
        families = []
        variant_count = 0
        for family_id in configured_families:
            family = catalog.get(str(family_id))
            if not family:
                families.append({'id': str(family_id), 'title': '', 'variants': [], 'stop_condition': '', 'status': 'missing_catalog_entry'})
                continue
            variants = [str(item) for item in family.get('variants', [])]
            variant_count += len(variants)
            families.append({'id': str(family.get('id')), 'title': family.get('title', ''), 'variants': variants, 'stop_condition': family.get('stop_condition', ''), 'status': 'planned'})
        modules.append({'id': module_id, 'local_name': local_name, 'families': families, 'variant_count': variant_count, 'adapter_command': adapter_module.get('command', []), 'result_files': adapter_module.get('result_files', [])})
    if requested_modules and (not modules):
        raise SystemExit(f'module not found in adapter: {args.module}')
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'target_id': adapter.get('target_id', args.target), 'adapter_manifest': rel(adapter_path), 'mutation_catalog': rel(_h.mutation_catalog_path()), 'modules': modules}
    if args.run_dir:
        run_dir = run_path(args.run_dir)
        out = run_dir / 'evidence' / 'mutation_coverage' / f"{args.module or 'all_modules'}.json"
        write_json(out, payload)
        print(rel(out))
        return
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _h._mutation_plan_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_h._mutation_plan_markdown(payload).rstrip())

def cmd_patch_first_plan(args: argparse.Namespace) -> None:
    profile_path, target = _h._target_profile_by_arg(args.target)
    src = source_path(target)
    target_id = str(target.get('id') or profile_path.stem)
    latest = target.get('latest_release') or {}
    latest_tag = str(latest.get('tag') or '')
    git_available = src.exists() and (src / '.git').exists()
    previous = _h._previous_tag(src, latest_tag, args.timeout) if git_available else ''
    priority = []
    suggested_commands = []
    if latest_tag and previous:
        ref_range = f'{previous}..{latest_tag}'
        priority.append({'type': 'release_diff', 'ref': ref_range, 'score': 95, 'rationale': 'Latest release range is locally available; mine security-adjacent changes before broad scans.', 'next_action': f'patch-mine <run-dir> --range {ref_range}'})
        suggested_commands.append(f'.venv-vapt/bin/python vapt/harness/harness.py patch-mine <run-dir> --range {ref_range}')
    elif latest_tag:
        priority.append({'type': 'release_diff', 'ref': latest_tag, 'score': 70, 'rationale': 'Latest release tag exists in profile, but previous local tag could not be verified.', 'next_action': 'fetch tags or provide an explicit patch-mine --range'})
    for cve in target.get('known_duplicates') or []:
        priority.append({'type': 'known_advisory', 'ref': str(cve), 'score': 80, 'rationale': 'Known duplicate/advisory should be used as a novelty boundary and sibling-variant seed.', 'next_action': f'dedup --reference {cve}; patch-diff around the fixing change if available'})
    for entry in queue_entries(target_id, include_claimed=False):
        priority.append({'type': str(entry.get('type') or 'watch_queue'), 'ref': str(entry.get('ref') or entry.get('queue_id')), 'score': 88, 'rationale': 'Fresh watch-generated queue entry should be triaged before broad scanning.', 'next_action': f"queue claim {entry.get('queue_id')}"})
    if any((item.get('type') == 'known_advisory' for item in priority)):
        suggested_commands.append(f'.venv-vapt/bin/python vapt/harness/harness.py campaign-plan {target_id} --limit 3')
    if target.get('osv_ecosystem') and target.get('osv_package'):
        suggested_commands.append(f".venv-vapt/bin/python vapt/harness/harness.py dedup <run-dir> <candidate-id> --check-osv --osv-ecosystem {target.get('osv_ecosystem')} --osv-package {target.get('osv_package')}")
    priority.sort(key=lambda item: (-int(item['score']), item['type'], item['ref']))
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'target_id': target_id, 'target_profile': rel(profile_path), 'source_path': rel(src), 'git_available': git_available, 'latest_release': latest, 'previous_tag': previous, 'priority_seeds': priority[:args.limit], 'suggested_commands': suggested_commands}
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _h._patch_first_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_h._patch_first_markdown(payload).rstrip())

def cmd_queue(args: argparse.Namespace) -> None:
    rows = queue_entries(args.target, include_claimed=args.all)
    summary = [{'queue_id': row.get('queue_id'), 'target_id': row.get('target_id'), 'status': row.get('status'), 'type': row.get('type'), 'ref': row.get('ref'), 'created_at': row.get('created_at'), 'candidate_seed_count': len(row.get('candidate_seeds', [])), 'path': rel(Path(row['_path']))} for row in rows]
    if args.json:
        print(json.dumps({'queue': summary}, indent=2, sort_keys=False))
        return
    for row in summary:
        print(f"{row['queue_id']} [{row['status']}] {row['type']} {row['ref']} seeds={row['candidate_seed_count']}")

def cmd_queue_claim(args: argparse.Namespace) -> None:
    if '/' not in args.queue_id:
        raise SystemExit("queue_id must be in '<target_id>/<id>' form")
    target_id, raw = args.queue_id.split('/', 1)
    path = queue_entry_path(target_id, raw.removesuffix('.yaml'))
    if not path.exists():
        raise SystemExit(f'queue entry not found: {args.queue_id}')
    with file_lock(path):
        entry = load_yaml(path) or {}
        if entry.get('status') != 'pending' and (not args.force):
            raise SystemExit(f"queue entry is not pending: {entry.get('status')}")
        entry['status'] = 'claimed'
        entry['claimed_by'] = args.claimed_by
        entry['claimed_at'] = dt.datetime.now().isoformat(timespec='seconds')
        entry.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'claimed', 'by': args.claimed_by, 'run_dir': args.run_dir or ''})
        if args.run_dir:
            entry['run_dir'] = args.run_dir
        dump_yaml(entry, path)
    print(rel(path))
