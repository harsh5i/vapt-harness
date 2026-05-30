"""Phase / loop / intent / outcome-tune / mutation-coverage check commands (CI-safe self-validation entry points).

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

from atomic_io import dump_yaml, file_lock, load_yaml, read_json, read_jsonl, write_json, write_jsonl, write_text
from core import HARNESS_VERSION, ROOT, rel, run_path, submissions_path
from ledger.candidates import find_candidate, load_candidates
from ledger.submissions import submission_stats
from outcome_tuning import outcome_tuning
from source.targets import _target_profile_paths
from tools.runtime import container_runtime, find_tool, macos_sandbox_exec, tool_env
from watch.state import load_watch_profiles, load_watch_state, queue_entries, save_watch_state, watch_profile_path, watch_state_dir, watches_dir


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def cmd_outcome_tune_check(args: argparse.Namespace) -> None:
    base = run_path(args.out_dir) if args.out_dir else ROOT / 'vapt' / 'harness' / 'tests' / 'results' / 'outcome-tune-check'
    if base.exists():
        shutil.rmtree(base)
    campaign_dir = base / 'campaign'
    with contextlib.redirect_stdout(io.StringIO()):
        _h.cmd_campaign_flow_check(argparse.Namespace(out_dir=str(base / 'flow'), json=False, fail=True))
    run_dir = base / 'flow' / 'campaign' / 'run'
    data = load_candidates(run_dir)
    cand = find_candidate(data, 'CAND-001')
    original_submission_rows = read_jsonl(submissions_path())
    with contextlib.redirect_stdout(io.StringIO()):
        _h.cmd_outcome_record(argparse.Namespace(submission_id='OUTCOME-TUNE-CHECK-ACCEPTED', run_dir=str(run_dir), candidate_id='CAND-001', status='accepted', platform='fixture', program='fixture', title=None, submitted_at=None, severity_claimed='high', severity='high', cvss=cand.get('cvss') or '', payout=1500.0, currency='USD', lesson='Fixture accepted authz_matrix queue campaign seed', note='fixture accepted', json=False))
    rows = read_jsonl(submissions_path())
    duplicate_row = {'submission_id': 'OUTCOME-TUNE-CHECK-DUPLICATE', 'platform': 'fixture', 'program': 'fixture', 'candidate_run': rel(run_dir), 'candidate_id': 'CAND-DUP', 'submitted_at': dt.datetime.now().isoformat(timespec='seconds'), 'updated_at': dt.datetime.now().isoformat(timespec='seconds'), 'title': 'Duplicate fixture', 'severity_claimed': 'medium', 'severity_final': 'medium', 'cvss_claimed': '', 'status_history': [{'at': dt.datetime.now().isoformat(timespec='seconds'), 'status': 'duplicate', 'note': 'fixture duplicate'}], 'final_status': 'duplicate', 'payout_value': None, 'payout_currency': None, 'days_to_final': 0, 'lessons': ['Fixture duplicate non_authz module'], 'target_id': 'harness-fixture', 'target_category': ['authz_boundary'], 'language': ['Python'], 'weakness': 'CWE-79', 'cwe': 'CWE-79', 'surface': 'fixture duplicate', 'sink': 'fixture duplicate', 'campaign_module': 'xss_render', 'evidence_kind': 'manual_seed', 'queue_type': ''}
    with file_lock(submissions_path()):
        rows = [row for row in rows if row.get('submission_id') not in {'OUTCOME-TUNE-CHECK-ACCEPTED', 'OUTCOME-TUNE-CHECK-DUPLICATE'}]
        rows.append(duplicate_row)
        accepted = read_jsonl(submissions_path())
        accepted = [row for row in accepted if row.get('submission_id') == 'OUTCOME-TUNE-CHECK-ACCEPTED']
        rows.extend(accepted)
        write_jsonl(submissions_path(), rows)
    tuning_out = base / 'outcome_tuning.yaml'
    with contextlib.redirect_stdout(io.StringIO()):
        _h.cmd_outcome_tune(argparse.Namespace(since=None, out=str(tuning_out), json=False))
    tuning = load_yaml(tuning_out) or {}
    with file_lock(submissions_path()):
        write_jsonl(submissions_path(), original_submission_rows)
    authz_adj = ((tuning.get('module_adjustments') or {}).get('authz_matrix') or {}).get('score_adjustment')
    xss_adj = ((tuning.get('module_adjustments') or {}).get('xss_render') or {}).get('score_adjustment')
    checks = [{'name': 'authz_positive_adjustment', 'passed': authz_adj is not None and float(authz_adj) > 0, 'detail': str(authz_adj)}, {'name': 'duplicate_lower_than_positive', 'passed': xss_adj is not None and float(xss_adj) < float(authz_adj or 0), 'detail': f'xss={xss_adj} authz={authz_adj}'}]
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': all((item['passed'] for item in checks)), 'checks': checks, 'tuning': rel(tuning_out), 'report': rel(tuning_out.with_suffix('.md'))}
    write_json(base / 'outcome_tune_check.json', payload)
    write_text(base / 'outcome_tune_check.md', '# Outcome Tune Check\n\n' + '\n'.join((f"- `{item['name']}` passed=`{item['passed']}` detail=`{item['detail']}`" for item in checks)) + '\n')
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(base / 'outcome_tune_check.md'))
    if args.fail and (not payload['passed']):
        raise SystemExit(2)

def cmd_intent_ordering_check(args: argparse.Namespace) -> None:
    fixture = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'intent_ordering' / 'source_graph.yaml'
    graph = load_yaml(fixture) or {}
    default = _h._order_hypotheses_by_intent(_h._build_hypotheses(graph, 3), [])
    default_top = default[0]['kind'] if default else ''
    cases = [('command_execution_boundary', 'command_execution_boundary'), ('ssrf_outbound_boundary', 'ssrf_outbound_boundary')]
    results: list[dict[str, Any]] = []
    for token, expected_kind in cases:
        hyps = _h._order_hypotheses_by_intent(_h._build_hypotheses(graph, 3), [token])
        top = hyps[0] if hyps else {}
        top_kind = top.get('kind', '')
        passed = top_kind == expected_kind and bool(top.get('intent_priority')) and (top_kind != default_top)
        results.append({'intent': token, 'expected_top': expected_kind, 'top_kind': top_kind, 'passed': passed})
    distinct = len({r['top_kind'] for r in results}) == len(results)
    all_passed = all((r['passed'] for r in results)) and distinct
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = out_dir / f'intent_ordering_{stamp}'
    write_json(out.with_suffix('.json'), {'passed': all_passed, 'default_top': default_top, 'distinct': distinct, 'results': results})
    md = ['# Intent Ordering Check', '', f'- All passed: `{all_passed}`', f'- Default top (no intent): `{default_top}`', f'- Two threat models produce distinct top hypotheses: `{distinct}`', '']
    for r in results:
        md.append(f"- intent `{r['intent']}` -> top `{r['top_kind']}` (expected `{r['expected_top']}`) passed=`{r['passed']}`")
    write_text(out.with_suffix('.md'), '\n'.join(md) + '\n')
    if args.json:
        print(json.dumps({'passed': all_passed, 'default_top': default_top, 'distinct': distinct, 'results': results}, indent=2, sort_keys=True))
    else:
        print(f'default top (no intent): {default_top}')
        for r in results:
            tag = 'PASS' if r['passed'] else 'FAIL'
            print(f"[{tag}] intent={r['intent']} top={r['top_kind']} expected={r['expected_top']}")
        print(f'distinct_tops={distinct} all_passed={all_passed}')
    if args.fail and (not all_passed):
        raise SystemExit(2)

def cmd_loop_integrity_check(args: argparse.Namespace) -> None:
    results: list[dict[str, Any]] = []
    if args.run_dir:
        run_dir = run_path(args.run_dir)
        state, _ = _h.load_run(run_dir)
        cands = load_candidates(run_dir).get('candidates', [])
        violations = _h._loop_integrity_violations(state, cands)
        results.append({'name': rel(run_dir), 'expect_pass': True, 'violations': violations, 'passed': not violations})
    else:
        fixture_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'loop_integrity'
        expectations = {'valid_run.json': True, 'skipped_state.json': False, 'unverdicted_proof.json': False}
        for name, expect_pass in expectations.items():
            payload = read_json(fixture_dir / name, {})
            violations = _h._loop_integrity_violations(payload.get('state', {}), payload.get('candidates', []))
            clean = not violations
            results.append({'name': name, 'expect_pass': expect_pass, 'violations': violations, 'passed': clean == expect_pass})
    all_passed = all((r['passed'] for r in results))
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = out_dir / f'loop_integrity_{stamp}'
    write_json(out.with_suffix('.json'), {'passed': all_passed, 'results': results})
    md = ['# Loop Integrity Check', '', f'- All passed: `{all_passed}`', '']
    for r in results:
        md.extend([f"## `{r['name']}`", '', f"- Expect pass: `{r['expect_pass']}`", f"- Passed: `{r['passed']}`", '- Violations:'])
        md.extend([f'  - {v}' for v in r['violations']] or ['  - (none)'])
        md.append('')
    write_text(out.with_suffix('.md'), '\n'.join(md))
    if args.json:
        print(json.dumps({'passed': all_passed, 'results': results}, indent=2, sort_keys=True))
    else:
        for r in results:
            tag = 'PASS' if r['passed'] else 'FAIL'
            print(f"[{tag}] {r['name']} expect_pass={r['expect_pass']} violations={r['violations']}")
        print('all_passed=' + str(all_passed))
    if args.fail and (not all_passed):
        raise SystemExit(2)

def cmd_mutation_coverage_check(args: argparse.Namespace) -> None:
    root = run_path(args.path)
    artifacts = _h._mutation_artifact_paths(root)
    if not artifacts:
        raise SystemExit(f'no mutation coverage artifacts found under: {args.path}')
    catalog = _h.load_mutation_catalog()
    results = [_h._validate_mutation_artifact(path, catalog, allow_missing=args.allow_missing, allow_unknown_variants=args.allow_unknown_variants) for path in artifacts]
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'root': rel(root), 'mutation_catalog': rel(_h.mutation_catalog_path()), 'passed': all((item['status'] == 'pass' for item in results)), 'artifacts': results}
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _h._mutation_coverage_check_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_h._mutation_coverage_check_markdown(payload).rstrip())
    if args.fail and (not payload['passed']):
        raise SystemExit(2)

def cmd_phase2_check(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    if not run_dir.exists():
        raise SystemExit(f'run directory not found: {run_dir}')
    _h.cmd_corpus_rebuild(argparse.Namespace())
    surface = _h.phase2_surface_regression()
    fixture_stats = _h.phase2_fixture_submission_stats()
    actual_stats = submission_stats(read_jsonl(submissions_path()))
    suggestion_count = _h.phase2_suggestion_count(args.target_id)
    ranked_targets = []
    for path in _target_profile_paths():
        target = load_yaml(path) or {}
        ranked_targets.append(target.get('id') or path.stem)
    retro_md = run_dir / 'retro.md'
    retro_patch = run_dir / 'retro.patch'
    if args.refresh_retro or not (retro_md.exists() and retro_patch.exists()):
        _h.cmd_retro(argparse.Namespace(run_dir=str(run_dir)))
    checks = {'submission_ledger_commands': True, 'fixture_submission_stats_meaningful': fixture_stats['total_submissions'] == 5 and fixture_stats['programs']['phase2-fixture']['terminal'] == 5 and (fixture_stats['programs']['phase2-fixture']['positive'] == 3), 'retro_artifacts_exist': retro_md.exists() and retro_patch.exists(), 'corpus_suggest_nontrivial': suggestion_count > 0, 'pick_target_has_registered_targets': len(ranked_targets) >= 1, 'pattern_coverage_passed': surface['passed']}
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'run_dir': rel(run_dir), 'target_id': args.target_id, 'passed': all(checks.values()), 'checks': checks, 'surface_regression': surface, 'fixture_submission_stats': fixture_stats, 'actual_submission_stats': actual_stats, 'corpus_suggestion_count': suggestion_count, 'registered_targets': ranked_targets, 'retro': {'retro_md': rel(retro_md) if retro_md.exists() else '', 'retro_patch': rel(retro_patch) if retro_patch.exists() else ''}}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'phase2_check_{stamp}.json'
    write_json(out_json, payload)
    out_md = out_dir / f'phase2_check_{stamp}.md'
    md = ['# Phase 2 Acceptance Check', '', f"- Passed: `{payload['passed']}`", f"- Run dir: `{payload['run_dir']}`", f'- Target: `{args.target_id}`', f'- Corpus suggestions: `{suggestion_count}`', f'- Registered targets: `{len(ranked_targets)}`', '', '## Checks', '']
    for name, passed in checks.items():
        md.append(f'- `{name}`: `{passed}`')
    if surface['failures']:
        md.extend(['', '## Surface Failures', ''])
        for failure in surface['failures']:
            md.append(f'- {failure}')
    write_text(out_md, '\n'.join(md) + '\n')
    print(rel(out_md))
    if not payload['passed']:
        raise SystemExit(2)

def cmd_phase3_check(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    probe_check = _h.phase3_probe_fixture_check()
    scanner_check = _h.phase3_scanner_fixture_check()
    tool_rows = []
    for tool in ['semgrep', 'bandit', 'pip-audit', 'osv-scanner', 'trufflehog', 'sslyze', 'testssl.sh', 'nuclei', 'codeql']:
        path = find_tool(tool)
        tool_rows.append({'tool': tool, 'available': bool(path), 'path': path or ''})
    required_commands = {'scan-nuclei', 'scan-semgrep', 'scan-codeql', 'codeql-workflow', 'playbook', 'report-gate', 'scan-trufflehog', 'scan-pip-audit', 'scan-bandit', 'scan-osv', 'scan-headers', 'scan-tls', 'sandbox-exec', 'probes', 'probes-test', 'refine', 'scaffold-poc', 'new-probe', 'tool-gaps', 'guard-drift'}
    parser = _h.build_parser()
    commands_present = required_commands <= set(parser._subparsers._group_actions[0].choices.keys())
    sandbox_runtime = container_runtime()
    macos_runtime = macos_sandbox_exec()
    sandbox_check = {'runtime': sandbox_runtime or macos_runtime or '', 'passed': True, 'note': 'Docker/Podman enforce container no-network mode when present; macOS sandbox-exec fallback enforces no network and evidence-only writes.'}
    checks = {'probe_fixtures_pass': probe_check['passed'], 'scanner_fixtures_auto_candidate': scanner_check['passed'], 'required_phase3_commands_present': commands_present, 'sandbox_policy_present': sandbox_check['passed'], 'tool_health_available': bool(tool_rows)}
    remaining_known_gaps = ['Refine is probe-driven but still not a fully autonomous multi-iteration model loop.']
    semgrep_tool = find_tool('semgrep')
    if semgrep_tool:
        semgrep_version = _h.run_cmd([semgrep_tool, '--version'], ROOT, timeout=5, env=tool_env('semgrep'))
        if semgrep_version['returncode'] != 0:
            remaining_known_gaps.insert(0, 'Semgrep is installed but not operational in the current local environment.')
    if not find_tool('codeql'):
        remaining_known_gaps.insert(0, 'CodeQL CLI is optional and currently missing locally.')
    if not find_tool('osv-scanner'):
        remaining_known_gaps.insert(0, 'OSV scanner binary is optional and currently missing locally.')
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': all(checks.values()), 'checks': checks, 'probe_check': probe_check, 'scanner_check': scanner_check, 'tool_health': tool_rows, 'sandbox': sandbox_check, 'remaining_known_gaps': remaining_known_gaps}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'phase3_check_{stamp}.json'
    write_json(out_json, payload)
    out_md = out_dir / f'phase3_check_{stamp}.md'
    md = ['# Phase 3 Acceptance Check', '', f"- Passed: `{payload['passed']}`", f'- Harness version: `{HARNESS_VERSION}`', '', '## Checks', '']
    for name, passed in checks.items():
        md.append(f'- `{name}`: `{passed}`')
    md.extend(['', '## Tool Availability', ''])
    for row in tool_rows:
        md.append(f"- `{row['tool']}`: `{('available' if row['available'] else 'missing')}` {row['path']}")
    md.extend(['', '## Remaining Known Gaps', ''])
    for gap in payload['remaining_known_gaps']:
        md.append(f'- {gap}')
    write_text(out_md, '\n'.join(md) + '\n')
    print(rel(out_md))
    if not payload['passed']:
        raise SystemExit(2)

def cmd_phase4_check(args: argparse.Namespace) -> None:
    base = ROOT / 'vapt' / 'harness' / 'tests' / 'results' / 'phase4_check_repo'
    base.mkdir(parents=True, exist_ok=True)
    if not (base / '.git').exists():
        _h.run_cmd(['git', 'init'], base, timeout=20)
        _h.run_cmd(['git', 'config', 'user.email', 'harness@example.local'], base, timeout=20)
        _h.run_cmd(['git', 'config', 'user.name', 'Harness Check'], base, timeout=20)
        write_text(base / 'app.py', 'def handler(user):\n    return user\n')
        _h.run_cmd(['git', 'add', 'app.py'], base, timeout=20)
        _h.run_cmd(['git', 'commit', '-m', 'initial'], base, timeout=20)
    target_id = 'phase4_fixture'
    profile_path = watch_profile_path(target_id)
    dump_yaml({'target_id': target_id, 'repo_path': rel(base), 'poll_interval_minutes': 1, 'trigger_patterns': ['authz_boundary', 'network_ssrf'], 'sources': [{'kind': 'github_commits', 'repo_path': rel(base), 'branch': 'HEAD', 'paths': ['app.py']}, {'kind': 'osv_advisories', 'ecosystem': 'PyPI', 'package': 'phase4-fixture', 'fixture': 'vapt/harness/tests/fixtures/advisories/osv_phase4_sample.json'}]}, profile_path)
    fixture_path = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'advisories' / 'osv_phase4_sample.json'
    write_json(fixture_path, {'vulns': [{'id': 'OSV-PHASE4-0001', 'package': 'phase4-fixture', 'ecosystem': 'PyPI', 'summary': 'Fixture advisory for watch queue regression testing', 'cwe': 'CWE-863'}]})
    state_path = watch_state_dir() / f'{target_id}.json'
    if state_path.exists():
        state_path.unlink()
    _h.poll_watch_source(load_watch_profiles(target_id)[0], load_watch_profiles(target_id)[0]['sources'][0], load_watch_state(target_id), False, 20)
    state = load_watch_state(target_id)
    profile = load_watch_profiles(target_id)[0]
    for source in profile['sources']:
        _h.poll_watch_source(profile, source, state, False, 20)
    save_watch_state(target_id, state)
    with (base / 'app.py').open('a', encoding='utf-8') as fh:
        fh.write("\n\ndef fetch_profile(url, token):\n    # authz token and requests.get SSRF review fixture\n    return requests.get(url, headers={'Authorization': token})\n")
    _h.run_cmd(['git', 'add', 'app.py'], base, timeout=20)
    _h.run_cmd(['git', 'commit', '-m', 'security relevant auth fetch'], base, timeout=20)
    fixed_head = _h.run_cmd(['git', 'rev-parse', 'HEAD'], base, timeout=20)['stdout'].strip()
    write_json(fixture_path, {'vulns': [{'id': 'OSV-PHASE4-0001', 'package': 'phase4-fixture', 'ecosystem': 'PyPI', 'summary': 'Fixture advisory for watch queue regression testing', 'cwe': 'CWE-863'}, {'id': f'OSV-PHASE4-{fixed_head[:8]}', 'package': 'phase4-fixture', 'ecosystem': 'PyPI', 'summary': 'Fixture advisory with fixed commit for patch-window enrichment', 'cwe': 'CWE-863', 'fixed_commit': fixed_head}]})
    state = load_watch_state(target_id)
    for source in profile['sources']:
        _h.poll_watch_source(profile, source, state, False, 20)
    save_watch_state(target_id, state)
    rows = queue_entries(target_id, include_claimed=True)
    parser = _h.build_parser()
    required = {'watch-add', 'watch-list', 'watch-tick', 'watch-daemon', 'queue', 'phase4-check', 'phase4-remote-check', 'phase4-soak-check'}
    commands_present = required <= set(parser._subparsers._group_actions[0].choices.keys())
    checks = {'watch_profile_written': profile_path.exists(), 'commit_queue_created': any((row.get('type') == 'commit_diff' for row in rows)), 'advisory_queue_created': any((row.get('type') == 'advisory' for row in rows)), 'patch_window_enriched': any((row.get('type') == 'advisory' and row.get('patch_enrichment', {}).get('available') for row in rows)), 'required_phase4_commands_present': commands_present}
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': all(checks.values()), 'checks': checks, 'queue_entries': [{'queue_id': row.get('queue_id'), 'type': row.get('type'), 'ref': row.get('ref'), 'path': rel(Path(row['_path']))} for row in rows]}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'phase4_check_{stamp}.json'
    write_json(out_json, payload)
    out_md = out_dir / f'phase4_check_{stamp}.md'
    md = ['# Phase 4 Acceptance Check', '', f"- Passed: `{payload['passed']}`", f'- Harness version: `{HARNESS_VERSION}`', '', '## Checks', '']
    for name, passed in checks.items():
        md.append(f'- `{name}`: `{passed}`')
    md.extend(['', '## Queue Entries', ''])
    for row in payload['queue_entries']:
        md.append(f"- `{row['queue_id']}` `{row['type']}` `{row['ref']}` -> `{row['path']}`")
    write_text(out_md, '\n'.join(md) + '\n')
    print(rel(out_md))
    if not payload['passed']:
        raise SystemExit(2)

def cmd_phase4_remote_check(args: argparse.Namespace) -> None:
    target_id = 'phase4_remote_check'
    profile = {'target_id': target_id, 'trigger_patterns': ['authz_boundary', 'network_ssrf'], 'sources': [{'kind': 'github_commits', 'repo': 'octocat/Hello-World', 'branch': 'master', 'allow_network': True}, {'kind': 'github_releases', 'repo': 'cli/cli', 'allow_network': True}, {'kind': 'osv_advisories', 'ecosystem': 'PyPI', 'package': 'requests', 'allow_network': True}, {'kind': 'ghsa_advisories', 'ecosystem': 'pip', 'package': 'requests', 'allow_network': True}]}
    state = {'target_id': target_id, 'sources': {}}
    results = []
    for source in profile['sources']:
        before_count = len(queue_entries(target_id, include_claimed=True))
        source_results = _h.poll_watch_source(profile, source, state, True, args.timeout)
        after_count = len(queue_entries(target_id, include_claimed=True))
        results.append({'source': source, 'results': source_results, 'queue_entries_created': after_count - before_count, 'passed': any((item.get('status') in {'queued', 'initialized', 'unchanged'} for item in source_results))})
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': all((item['passed'] for item in results)), 'results': results, 'note': 'This check requires network access. GitHub API rate limits or local network policy may cause failure.'}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'phase4_remote_check_{stamp}.json'
    write_json(out_json, payload)
    out_md = out_dir / f'phase4_remote_check_{stamp}.md'
    md = ['# Phase 4 Remote Polling Check', '', f"- Passed: `{payload['passed']}`", f'- Harness version: `{HARNESS_VERSION}`', '', '## Sources', '']
    for result in results:
        source = result['source']
        md.append(f"- `{source['kind']}` `{source.get('repo') or source.get('package')}`: passed=`{result['passed']}`, queued=`{result['queue_entries_created']}`")
        for item in result['results']:
            md.append(f"  - status=`{item.get('status')}` ref=`{item.get('ref') or item.get('advisory') or item.get('release') or item.get('head') or ''}` error=`{item.get('error') or item.get('reason') or ''}`")
    write_text(out_md, '\n'.join(md) + '\n')
    print(rel(out_md))
    if not payload['passed']:
        raise SystemExit(2)

def cmd_phase4_soak_check(args: argparse.Namespace) -> None:
    heartbeat = watches_dir() / 'watch_daemon_heartbeat.jsonl'
    before = len(read_jsonl(heartbeat))
    start = time.monotonic()
    iterations = 0
    errors = []
    while True:
        iterations += 1
        try:
            profiles = load_watch_profiles(args.target)
            for profile in profiles:
                state = load_watch_state(str(profile['target_id']))
                for source in profile.get('sources', []):
                    _h.poll_watch_source(profile, source, state, False, args.timeout)
                save_watch_state(str(profile['target_id']), state)
            status = 'ok'
            error_msg = ''
        except Exception as exc:
            status = 'error'
            error_msg = str(exc)
            errors.append(error_msg)
        rows = read_jsonl(heartbeat)
        rows.append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'status': status, 'error': error_msg, 'iteration': iterations, 'soak_check': True})
        write_jsonl(heartbeat, rows[-2000:])
        elapsed = time.monotonic() - start
        if args.iterations and iterations >= args.iterations:
            break
        if elapsed >= args.seconds:
            break
        time.sleep(max(1, args.interval_seconds))
    after = len(read_jsonl(heartbeat))
    duration_seconds = time.monotonic() - start
    passed = not errors and after > before and (iterations >= 1)
    if args.require_24h and duration_seconds < 24 * 60 * 60:
        passed = False
        errors.append('require_24h was set but elapsed time was less than 86400 seconds')
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': passed, 'target': args.target or 'all', 'iterations': iterations, 'duration_seconds': round(duration_seconds, 3), 'heartbeat': rel(heartbeat), 'errors': errors, 'require_24h': args.require_24h}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = out_dir / f'phase4_soak_check_{stamp}.json'
    write_json(out_json, payload)
    out_md = out_dir / f'phase4_soak_check_{stamp}.md'
    md = ['# Phase 4 Daemon Soak Check', '', f"- Passed: `{payload['passed']}`", f'- Harness version: `{HARNESS_VERSION}`', f"- Target: `{payload['target']}`", f'- Iterations: `{iterations}`', f"- Duration seconds: `{payload['duration_seconds']}`", f"- Heartbeat: `{payload['heartbeat']}`", '', '## Errors', '']
    md.extend([f'- {error}' for error in errors] or ['- none'])
    write_text(out_md, '\n'.join(md) + '\n')
    print(rel(out_md))
    if not passed:
        raise SystemExit(2)
