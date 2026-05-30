"""Watch polling + advisory matching: per-source poll handlers and the OSV/GHSA advisory match + patch-enrichment helpers.

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

from atomic_io import dump_yaml, load_yaml, read_jsonl, write_json, write_jsonl
from core import rel, run_path, source_path
from gates.osv import _http_json
from source.targets import _load_target_profile
from watch.state import load_watch_profiles, load_watch_state, queue_entries, queue_write_entry, save_watch_state, watch_profile_path, watch_source_key, watches_dir


_h = sys.modules.get("harness") or sys.modules.get("__main__")
if _h is None or not hasattr(_h, "load_run"):
    import harness as _h  # noqa: E402


def diff_pattern_hits(diff_text: str, trigger_patterns: list[str]) -> list[dict[str, Any]]:
    hits = []
    terms = _h.load_surface_terms(trigger_patterns)
    lowered = diff_text.lower()
    for term in terms:
        if term.lower() in lowered:
            matching_lines = [line for line in diff_text.splitlines() if term.lower() in line.lower()][:10]
            hits.append({'pattern': term, 'lines': matching_lines})
    return hits

def resolve_watch_repo_path(profile: dict[str, Any], source: dict[str, Any]) -> Path | None:
    raw = source.get('repo_path') or profile.get('repo_path')
    if not raw:
        target_file, target = _load_target_profile(str(profile.get('target_id') or ''))
        if target_file and target_file.exists():
            raw = target.get('source_path') or target.get('repo_path')
    if not raw:
        return None
    return run_path(str(raw))

def poll_local_git_source(profile: dict[str, Any], source: dict[str, Any], state: dict[str, Any], seed: bool) -> list[dict[str, Any]]:
    target_id = str(profile['target_id'])
    src = resolve_watch_repo_path(profile, source)
    if not src:
        return [{'kind': source.get('kind'), 'status': 'skipped', 'reason': 'no repo_path or target source_path'}]
    branch = source.get('branch') or 'HEAD'
    head = _h.run_cmd(['git', 'rev-parse', branch], src, timeout=20)
    if head['returncode'] != 0:
        return [{'kind': source.get('kind'), 'status': 'error', 'stderr': head['stderr'].strip()}]
    current = head['stdout'].strip()
    source_key = watch_source_key(source)
    source_state = state.setdefault('sources', {}).setdefault(source_key, {})
    previous = source_state.get('last_seen')
    source_state['last_seen'] = current
    source_state['last_polled_at'] = dt.datetime.now().isoformat(timespec='seconds')
    if not previous and (not seed):
        return [{'kind': source.get('kind'), 'status': 'initialized', 'head': current}]
    if previous == current and (not seed):
        return [{'kind': source.get('kind'), 'status': 'unchanged', 'head': current}]
    ref_range = f'{previous}..{current}' if previous else current
    paths = [str(item) for item in source.get('paths', [])]
    diff_args = ['git', 'diff', '--unified=20', ref_range, '--', *paths]
    diff = _h.run_cmd(diff_args, src, timeout=60)
    names = _h.run_cmd(['git', 'diff', '--name-status', ref_range, '--', *paths], src, timeout=30)
    diff_text = diff['stdout'] or ''
    hits = diff_pattern_hits(diff_text, [str(item) for item in profile.get('trigger_patterns', [])])
    status = 'changed'
    path = None
    if hits or seed:
        entry = {'type': 'commit_diff', 'source_kind': source.get('kind'), 'source_key': source_key, 'ref': current[:12], 'previous_ref': previous or '', 'repo_path': rel(src), 'branch': branch, 'paths': paths, 'matched_patterns': hits, 'changed_files': names['stdout'].splitlines(), 'diff_hunks': diff_text[:60000], 'candidate_seeds': [{'title': f'Review security-relevant change {current[:12]} in {target_id}', 'surface': ', '.join(paths) if paths else 'changed source', 'weakness': 'TBD', 'novelty': 'fresh-change', 'dedup': 'unchecked', 'next_action': 'Create a run, inspect diff_hunks, and promote only with reachability/proof.'}]}
        path = queue_write_entry(target_id, entry)
        status = 'queued'
    return [{'kind': source.get('kind'), 'status': status, 'previous': previous or '', 'head': current, 'hits': len(hits), 'queue_entry': rel(path) if path else ''}]

def poll_local_release_source(profile: dict[str, Any], source: dict[str, Any], state: dict[str, Any], seed: bool) -> list[dict[str, Any]]:
    target_id = str(profile['target_id'])
    src = resolve_watch_repo_path(profile, source)
    if not src:
        return [{'kind': source.get('kind'), 'status': 'skipped', 'reason': 'no repo_path or target source_path'}]
    latest = _h.run_cmd(['git', 'tag', '--sort=-creatordate'], src, timeout=20)
    if latest['returncode'] != 0:
        return [{'kind': source.get('kind'), 'status': 'error', 'stderr': latest['stderr'].strip()}]
    tags = [line.strip() for line in latest['stdout'].splitlines() if line.strip()]
    if not tags:
        return [{'kind': source.get('kind'), 'status': 'skipped', 'reason': 'no git tags found'}]
    current = tags[0]
    source_key = watch_source_key(source)
    source_state = state.setdefault('sources', {}).setdefault(source_key, {})
    previous = source_state.get('last_seen')
    source_state['last_seen'] = current
    source_state['last_polled_at'] = dt.datetime.now().isoformat(timespec='seconds')
    if not previous and (not seed):
        return [{'kind': source.get('kind'), 'status': 'initialized', 'release': current}]
    if previous == current and (not seed):
        return [{'kind': source.get('kind'), 'status': 'unchanged', 'release': current}]
    path = queue_write_entry(target_id, {'type': 'release', 'source_kind': source.get('kind'), 'source_key': source_key, 'ref': current, 'previous_ref': previous or '', 'repo_path': rel(src), 'candidate_seeds': [{'title': f'Review new release {current} for silent security fixes', 'surface': 'release diff', 'weakness': 'possible-regression', 'novelty': 'fresh-release', 'next_action': 'Run patch-mine across previous release to current release.'}]})
    return [{'kind': source.get('kind'), 'status': 'queued', 'release': current, 'queue_entry': rel(path)}]

def read_advisory_fixture(source: dict[str, Any]) -> list[dict[str, Any]]:
    fixture = source.get('fixture')
    if not fixture:
        return []
    path = run_path(str(fixture))
    if not path.exists():
        return []
    if path.suffix.lower() in {'.yaml', '.yml'}:
        data = load_yaml(path) or {}
    else:
        data = json.loads(path.read_text(encoding='utf-8'))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        rows = data.get('advisories') or data.get('vulns') or data.get('results') or []
        return [item for item in rows if isinstance(item, dict)]
    return []

def advisory_packages(row: dict[str, Any]) -> set[str]:
    values = _h.as_list(row.get('package')) + _h.as_list(row.get('name')) + _h.as_list(row.get('module'))
    for affected in _h.as_list(row.get('affected')):
        if not isinstance(affected, dict):
            continue
        package = affected.get('package')
        if isinstance(package, dict):
            values.extend(_h.as_list(package.get('name')))
            values.extend(_h.as_list(package.get('purl')))
        else:
            values.extend(_h.as_list(package))
    return _h.lower_values(values)

def advisory_ecosystems(row: dict[str, Any]) -> set[str]:
    values = _h.as_list(row.get('ecosystem'))
    for affected in _h.as_list(row.get('affected')):
        if not isinstance(affected, dict):
            continue
        package = affected.get('package')
        if isinstance(package, dict):
            values.extend(_h.as_list(package.get('ecosystem')))
    return _h.lower_values(values)

def advisory_cwes(row: dict[str, Any]) -> set[str]:
    values = _h.as_list(row.get('cwe')) + _h.as_list(row.get('cwes')) + _h.as_list(row.get('cwe_ids'))
    db = row.get('database_specific')
    if isinstance(db, dict):
        values.extend(_h.as_list(db.get('cwe_ids')))
        values.extend(_h.as_list(db.get('cwe')))
    return {str(value).strip().upper() for value in values if str(value).strip()}

def advisory_versions(row: dict[str, Any]) -> dict[str, Any]:
    versions: dict[str, Any] = {'affected_versions': [], 'ranges': []}
    versions['affected_versions'].extend(_h.as_list(row.get('versions')))
    versions['affected_versions'].extend(_h.as_list(row.get('affected_versions')))
    for affected in _h.as_list(row.get('affected')):
        if not isinstance(affected, dict):
            continue
        versions['affected_versions'].extend(_h.as_list(affected.get('versions')))
        for range_item in _h.as_list(affected.get('ranges')):
            if isinstance(range_item, dict):
                versions['ranges'].append(range_item)
    return versions

def advisory_match(profile: dict[str, Any], source: dict[str, Any], row: dict[str, Any]) -> tuple[bool, list[str]]:
    source_packages = _h.lower_values(_h.as_list(source.get('package')) + _h.as_list(source.get('package_aliases')) + _h.as_list(profile.get('package_aliases')))
    source_ecosystems = _h.lower_values(_h.as_list(source.get('ecosystem')) + _h.as_list(profile.get('ecosystem')))
    source_cwes = {str(item).upper() for item in _h.as_list(source.get('cwe')) + _h.as_list(source.get('cwes')) + _h.as_list(profile.get('cwe')) + _h.as_list(profile.get('cwes'))}
    row_packages = advisory_packages(row)
    row_ecosystems = advisory_ecosystems(row)
    row_cwes = advisory_cwes(row)
    reasons = []
    if source_packages and row_packages and source_packages & row_packages:
        reasons.append(f"package:{', '.join(sorted(source_packages & row_packages))}")
    if source_ecosystems and row_ecosystems and source_ecosystems & row_ecosystems:
        reasons.append(f"ecosystem:{', '.join(sorted(source_ecosystems & row_ecosystems))}")
    if source_cwes and row_cwes and source_cwes & row_cwes:
        reasons.append(f"cwe:{', '.join(sorted(source_cwes & row_cwes))}")
    trigger_terms = _h.lower_values(_h.as_list(profile.get('trigger_patterns')))
    row_text = json.dumps(row, sort_keys=True).lower()
    trigger_overlap = sorted((term for term in trigger_terms if term and term in row_text))
    if trigger_overlap:
        reasons.append(f"trigger:{', '.join(trigger_overlap[:5])}")
    package_required = bool(source_packages)
    ecosystem_required = bool(source_ecosystems and row_ecosystems)
    package_ok = not package_required or bool(source_packages & row_packages)
    ecosystem_ok = not ecosystem_required or bool(source_ecosystems & row_ecosystems)
    cwe_or_trigger_ok = bool(source_cwes & row_cwes or trigger_overlap or (not source_cwes))
    return (package_ok and ecosystem_ok and cwe_or_trigger_ok, reasons)

def advisory_patch_range(row: dict[str, Any]) -> str:
    for key in ('patch_range', 'fixed_range', 'git_range', 'commit_range'):
        value = row.get(key)
        if value:
            return str(value)
    db = row.get('database_specific')
    if isinstance(db, dict):
        for key in ('patch_range', 'fixed_range', 'git_range', 'commit_range'):
            value = db.get(key)
            if value:
                return str(value)
    return ''

def advisory_fixed_commit(row: dict[str, Any]) -> str:
    for key in ('fixed_commit', 'fixed_commit_sha', 'fix_commit', 'commit'):
        value = row.get(key)
        if value:
            return str(value)
    db = row.get('database_specific')
    if isinstance(db, dict):
        for key in ('fixed_commit', 'fixed_commit_sha', 'fix_commit', 'commit'):
            value = db.get(key)
            if value:
                return str(value)
    return ''

def advisory_patch_enrichment(profile: dict[str, Any], source: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    src = resolve_watch_repo_path(profile, source)
    if not src:
        return {'available': False, 'reason': 'no local repo_path for patch enrichment'}
    patch_range = advisory_patch_range(row)
    fixed_commit = advisory_fixed_commit(row)
    if not patch_range and fixed_commit:
        parent = _h.run_cmd(['git', 'rev-parse', f'{fixed_commit}^'], src, timeout=20)
        if parent['returncode'] == 0:
            patch_range = f"{parent['stdout'].strip()}..{fixed_commit}"
        else:
            patch_range = f'{fixed_commit}^..{fixed_commit}'
    if not patch_range:
        return {'available': False, 'reason': 'advisory did not include patch_range or fixed_commit'}
    paths = [str(item) for item in source.get('paths', [])]
    diff = _h.run_cmd(['git', 'diff', '--unified=20', patch_range, '--', *paths], src, timeout=60)
    names = _h.run_cmd(['git', 'diff', '--name-status', patch_range, '--', *paths], src, timeout=30)
    diff_text = diff['stdout'] or ''
    return {'available': diff['returncode'] == 0, 'repo_path': rel(src), 'range': patch_range, 'paths': paths, 'changed_files': names['stdout'].splitlines(), 'matched_patterns': diff_pattern_hits(diff_text, [str(item) for item in profile.get('trigger_patterns', [])]), 'diff_hunks': diff_text[:60000], 'stderr': diff['stderr'].strip()}

def poll_fixture_advisories(profile: dict[str, Any], source: dict[str, Any], state: dict[str, Any], seed: bool) -> list[dict[str, Any]]:
    target_id = str(profile['target_id'])
    source_key = watch_source_key(source)
    source_state = state.setdefault('sources', {}).setdefault(source_key, {})
    seen = set(source_state.get('seen_ids', []))
    rows = read_advisory_fixture(source)
    results = []
    new_seen = set(seen)
    for row in rows:
        adv_id = str(row.get('id') or row.get('ghsa_id') or row.get('cve') or row.get('modified') or uuid.uuid4().hex)
        if adv_id in seen and (not seed):
            continue
        matched, match_reasons = advisory_match(profile, source, row)
        if not matched:
            continue
        patch_enrichment = advisory_patch_enrichment(profile, source, row)
        new_seen.add(adv_id)
        path = queue_write_entry(target_id, {'type': 'advisory', 'source_kind': source.get('kind'), 'source_key': source_key, 'ref': adv_id, 'advisory': row, 'affected': {'packages': sorted(advisory_packages(row)), 'ecosystems': sorted(advisory_ecosystems(row)), 'cwes': sorted(advisory_cwes(row)), **advisory_versions(row)}, 'match_reasons': match_reasons, 'patch_enrichment': patch_enrichment, 'matched_patterns': [{'pattern': item, 'lines': []} for item in profile.get('trigger_patterns', [])], 'candidate_seeds': [{'title': f'Review {adv_id} for regression or affected-version correction', 'surface': str(row.get('summary') or row.get('details') or 'advisory'), 'weakness': str(row.get('cwe') or 'possible-regression'), 'novelty': 'possible-regression', 'dedup': 'advisory-known', 'next_action': 'Cross-reference affected package/version and patch diff before candidate promotion.'}]})
        results.append({'kind': source.get('kind'), 'status': 'queued', 'advisory': adv_id, 'match_reasons': match_reasons, 'patch_enriched': bool(patch_enrichment.get('available')), 'queue_entry': rel(path)})
    source_state['seen_ids'] = sorted(new_seen)
    source_state['last_polled_at'] = dt.datetime.now().isoformat(timespec='seconds')
    if not results:
        results.append({'kind': source.get('kind'), 'status': 'unchanged', 'advisories_seen': len(new_seen)})
    return results

def poll_remote_source(profile: dict[str, Any], source: dict[str, Any], state: dict[str, Any], seed: bool, timeout: int) -> list[dict[str, Any]]:
    if not source.get('allow_network'):
        return [{'kind': source.get('kind'), 'status': 'skipped', 'reason': 'network polling requires source.allow_network=true'}]
    target_id = str(profile['target_id'])
    kind = source.get('kind')
    source_key = watch_source_key(source)
    source_state = state.setdefault('sources', {}).setdefault(source_key, {})
    token = os.environ.get('GITHUB_TOKEN')
    advisory_rows: list[dict[str, Any]] = []
    try:
        if kind == 'github_commits':
            repo = source['repo']
            branch = source.get('branch') or 'main'
            path_arg = f"&path={source.get('paths', [''])[0]}" if source.get('paths') else ''
            url = f'https://api.github.com/repos/{repo}/commits?sha={branch}{path_arg}&per_page=1'
            rows = _h.fetch_json_url(url, token, timeout)
            current = rows[0]['sha'] if rows else ''
        elif kind == 'github_releases':
            repo = source['repo']
            row = _h.fetch_json_url(f'https://api.github.com/repos/{repo}/releases/latest', token, timeout)
            current = row.get('tag_name') or row.get('id')
        elif kind == 'ghsa_advisories':
            package = source.get('package', '')
            ecosystem = source.get('ecosystem', '')
            url = f'https://api.github.com/advisories?type=reviewed&ecosystem={ecosystem}&affects={package}&per_page=10'
            rows = _h.fetch_json_url(url, token, timeout)
            advisory_rows = [row for row in rows if isinstance(row, dict)]
            current = rows[0].get('ghsa_id') if rows else ''
        elif kind == 'osv_advisories':
            payload = {'package': {'name': source.get('package'), 'ecosystem': source.get('ecosystem')}}
            row = _http_json('POST', 'https://api.osv.dev/v1/query', payload, timeout)
            rows = row.get('vulns', [])
            advisory_rows = [item for item in rows if isinstance(item, dict)]
            current = rows[0].get('id') if rows else ''
        else:
            return [{'kind': kind, 'status': 'skipped', 'reason': 'unsupported remote source'}]
    except Exception as exc:
        return [{'kind': kind, 'status': 'error', 'error': str(exc)}]
    if kind in {'ghsa_advisories', 'osv_advisories'}:
        seen = set(source_state.get('seen_ids', []))
        results = []
        new_seen = set(seen)
        for row in advisory_rows:
            adv_id = str(row.get('id') or row.get('ghsa_id') or row.get('cve') or row.get('modified') or uuid.uuid4().hex)
            if adv_id in seen and (not seed):
                continue
            matched, match_reasons = advisory_match(profile, source, row)
            if not matched:
                continue
            new_seen.add(adv_id)
            patch_enrichment = advisory_patch_enrichment(profile, source, row)
            path = queue_write_entry(target_id, {'type': 'advisory', 'source_kind': kind, 'source_key': source_key, 'ref': adv_id, 'remote': True, 'advisory': row, 'affected': {'packages': sorted(advisory_packages(row)), 'ecosystems': sorted(advisory_ecosystems(row)), 'cwes': sorted(advisory_cwes(row)), **advisory_versions(row)}, 'match_reasons': match_reasons, 'patch_enrichment': patch_enrichment, 'candidate_seeds': [{'title': f'Review {adv_id} for regression or affected-version correction', 'surface': str(row.get('summary') or row.get('details') or 'remote advisory'), 'weakness': ', '.join(sorted(advisory_cwes(row))) or 'possible-regression', 'novelty': 'possible-regression', 'dedup': 'advisory-known', 'next_action': 'Cross-reference affected package/version and patch diff before candidate promotion.'}]})
            results.append({'kind': kind, 'status': 'queued', 'advisory': adv_id, 'match_reasons': match_reasons, 'patch_enriched': bool(patch_enrichment.get('available')), 'queue_entry': rel(path)})
        source_state['seen_ids'] = sorted(new_seen)
        source_state['last_polled_at'] = dt.datetime.now().isoformat(timespec='seconds')
        if results:
            return results
        return [{'kind': kind, 'status': 'unchanged', 'advisories_seen': len(new_seen)}]
    previous = source_state.get('last_seen')
    source_state['last_seen'] = current
    source_state['last_polled_at'] = dt.datetime.now().isoformat(timespec='seconds')
    if not current:
        return [{'kind': kind, 'status': 'unchanged', 'reason': 'no remote item returned'}]
    if previous == current and (not seed):
        return [{'kind': kind, 'status': 'unchanged', 'ref': current}]
    if not previous and (not seed):
        return [{'kind': kind, 'status': 'initialized', 'ref': current}]
    path = queue_write_entry(target_id, {'type': str(kind).replace('github_', '').replace('_advisories', '_advisory'), 'source_kind': kind, 'source_key': source_key, 'ref': current, 'previous_ref': previous or '', 'remote': True, 'candidate_seeds': [{'title': f'Review fresh {kind} event {current}', 'surface': source.get('repo') or source.get('package') or 'remote watch', 'weakness': 'TBD', 'novelty': 'fresh-watch-event', 'next_action': 'Fetch local source, patch-diff, dedup, and prove before promotion.'}]})
    return [{'kind': kind, 'status': 'queued', 'ref': current, 'queue_entry': rel(path)}]

def poll_watch_source(profile: dict[str, Any], source: dict[str, Any], state: dict[str, Any], seed: bool, timeout: int) -> list[dict[str, Any]]:
    kind = source.get('kind')
    if source.get('fixture') and kind in {'ghsa_advisories', 'osv_advisories'}:
        return poll_fixture_advisories(profile, source, state, seed)
    if kind == 'github_commits' and resolve_watch_repo_path(profile, source):
        return poll_local_git_source(profile, source, state, seed)
    if kind == 'github_releases' and resolve_watch_repo_path(profile, source):
        return poll_local_release_source(profile, source, state, seed)
    if kind in {'github_commits', 'github_releases', 'ghsa_advisories', 'osv_advisories'}:
        return poll_remote_source(profile, source, state, seed, timeout)
    return [{'kind': kind, 'status': 'skipped', 'reason': 'unsupported source kind'}]

def cmd_watch_add(args: argparse.Namespace) -> None:
    path = watch_profile_path(args.target_id)
    profile = load_yaml(path) if path.exists() else {'target_id': args.target_id, 'sources': []}
    profile.setdefault('target_id', args.target_id)
    profile.setdefault('sources', [])
    profile['poll_interval_minutes'] = args.poll_interval_minutes
    if args.trigger_pattern:
        profile['trigger_patterns'] = args.trigger_pattern
    else:
        profile.setdefault('trigger_patterns', [])
    source: dict[str, Any] = {'kind': args.source}
    for key in ('repo', 'repo_path', 'branch', 'ecosystem', 'package', 'fixture'):
        value = getattr(args, key)
        if value:
            source[key] = value
    if args.package_alias:
        source['package_aliases'] = args.package_alias
    if args.cwe:
        source['cwes'] = args.cwe
    if args.path:
        source['paths'] = args.path
    if args.allow_network:
        source['allow_network'] = True
    profile['sources'].append(source)
    dump_yaml(profile, path)
    print(rel(path))

def cmd_watch_list(args: argparse.Namespace) -> None:
    profiles = load_watch_profiles(args.target)
    rows = []
    for profile in profiles:
        target_id = str(profile['target_id'])
        state = load_watch_state(target_id)
        rows.append({'target_id': target_id, 'path': rel(Path(profile['_path'])), 'sources': profile.get('sources', []), 'poll_interval_minutes': profile.get('poll_interval_minutes'), 'trigger_patterns': profile.get('trigger_patterns', []), 'queue_pending': len(queue_entries(target_id)), 'last_state_update': state.get('updated_at', '')})
    if args.json:
        print(json.dumps({'watches': rows}, indent=2, sort_keys=False))
        return
    for row in rows:
        print(f"{row['target_id']}: sources={len(row['sources'])} pending={row['queue_pending']} updated={row['last_state_update'] or 'never'}")

def cmd_watch_tick(args: argparse.Namespace) -> None:
    profiles = load_watch_profiles(args.target)
    if not profiles:
        raise SystemExit('no watch profiles found')
    tick = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'profiles': []}
    for profile in profiles:
        target_id = str(profile['target_id'])
        state = load_watch_state(target_id)
        profile_result = {'target_id': target_id, 'sources': []}
        for source in profile.get('sources', []):
            results = poll_watch_source(profile, source, state, args.seed, args.timeout)
            profile_result['sources'].extend(results)
        save_watch_state(target_id, state)
        tick['profiles'].append(profile_result)
    out_dir = watches_dir() / 'ticks'
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"watch_tick_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    write_json(out, tick)
    if args.json:
        print(json.dumps(tick, indent=2, sort_keys=False))
    else:
        print(rel(out))

def cmd_watch_daemon(args: argparse.Namespace) -> None:
    heartbeat = watches_dir() / 'watch_daemon_heartbeat.jsonl'
    stop = {'value': False}

    def _stop(signum, frame):
        stop['value'] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    started = time.monotonic()
    iterations = 0
    while not stop['value']:
        iterations += 1
        try:
            ns = argparse.Namespace(target=args.target, seed=False, timeout=args.timeout, json=True)
            profiles = load_watch_profiles(args.target)
            for profile in profiles:
                state = load_watch_state(str(profile['target_id']))
                for source in profile.get('sources', []):
                    poll_watch_source(profile, source, state, False, args.timeout)
                save_watch_state(str(profile['target_id']), state)
            status = 'ok'
            error_msg = ''
        except Exception as exc:
            status = 'error'
            error_msg = str(exc)
        rows = read_jsonl(heartbeat)
        rows.append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'status': status, 'error': error_msg, 'iteration': iterations})
        write_jsonl(heartbeat, rows[-1000:])
        if args.max_iterations and iterations >= args.max_iterations:
            break
        if args.max_seconds and time.monotonic() - started >= args.max_seconds:
            break
        time.sleep(max(1, args.interval_seconds))
    print(rel(heartbeat))
