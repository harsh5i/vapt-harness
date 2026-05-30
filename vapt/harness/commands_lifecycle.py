"""Lifecycle + operator-facing CLI handlers: init, prepare, map, score, report, dashboard, status, intent, budget, session-start, knowledge, explain, commands, retro, reference-add, test-skeleton, plus probes/playbook/codeql/scaffold-poc/new-probe scaffolding.

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

from atomic_io import candidate_ledger_lock, dump_yaml, load_yaml, read_json, write_json, write_text
from core import HARNESS_VERSION, ROOT, now_id, rel, run_path, source_path
from gates.promotion import promotion_findings
from ledger.candidates import find_candidate, load_candidates, save_candidates, update_candidate_locked
from source.targets import _load_target_profile
from validators import cvss3_base_score


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def cmd_init(args: argparse.Namespace) -> None:
    target_file = run_path(args.target)
    target = load_yaml(target_file)
    target_id = target['id']
    run_id = args.run_id or now_id()
    out = ROOT / 'vapt' / 'engagements' / target_id / 'runs' / target_id / run_id
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f'run directory already exists: {out}')
    out.mkdir(parents=True, exist_ok=True)
    dump_yaml(target, out / 'target.yaml')
    write_json(out / 'state.json', {'target_id': target_id, 'run_id': run_id, 'created_at': dt.datetime.now().isoformat(timespec='seconds'), 'status': 'initialized', 'stages': {}})
    dump_yaml({'candidates': []}, out / 'candidates.yaml')
    write_text(out / 'notes.md', f'# Notes: {target_id} / {run_id}\n\n')
    for sub in ('evidence', 'reports', 'logs'):
        (out / sub).mkdir(exist_ok=True)
    print(rel(out))

def cmd_prepare(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    checks = {'git_head': _h.run_cmd(['git', 'rev-parse', 'HEAD'], src), 'git_last_commit': _h.run_cmd(['git', 'log', '-1', '--oneline', '--decorate'], src), 'git_tags': _h.run_cmd(['git', 'tag', '--points-at', 'HEAD'], src), 'git_status': _h.run_cmd(['git', 'status', '--short'], src), 'files': _h.run_cmd(['rg', '--files'], src, timeout=60)}
    if checks['git_head']['returncode'] != 0 and (not args.allow_non_git):
        write_json(run_dir / 'prepare.json', {'target': target, 'source_path': rel(src), 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'checks': checks, 'error': 'source_path is not a git checkout; rerun with --allow-non-git for tarball/wheel sources'})
        raise SystemExit('source_path is not a git checkout; rerun prepare with --allow-non-git if intentional')
    files = checks['files']['stdout'].splitlines() if checks['files']['returncode'] == 0 else []
    suffix_counts: dict[str, int] = {}
    for name in files:
        suffix = Path(name).suffix.lower() or '<none>'
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
    prepared = {'target': target, 'source_path': rel(src), 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'checks': checks, 'file_count': len(files), 'suffix_counts': dict(sorted(suffix_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:30])}
    write_json(run_dir / 'prepare.json', prepared)
    md = [f"# Prepare: {target['id']}", '', f'- Source: `{rel(src)}`', f'- File count: `{len(files)}`', f"- HEAD: `{checks['git_head']['stdout'].strip()}`", f"- Last commit: `{checks['git_last_commit']['stdout'].strip()}`", f"- Tags at HEAD: `{checks['git_tags']['stdout'].strip() or 'none'}`", '', '## Top File Suffixes', '']
    for suffix, count in prepared['suffix_counts'].items():
        md.append(f'- `{suffix}`: {count}')
    write_text(run_dir / 'prepare.md', '\n'.join(md) + '\n')
    _h.save_stage(run_dir, state, 'prepare')
    print(rel(run_dir / 'prepare.md'))

def cmd_map(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    surfaces: dict[str, list[dict[str, str]]] = {}
    for category, patterns in _h.PATTERNS.items():
        surfaces[category] = []
        for pattern in patterns:
            result = _h.run_cmd(['rg', '-n', '-S', '-F', pattern], src, timeout=45)
            if result['returncode'] not in (0, 1):
                surfaces[category].append({'pattern': pattern, 'error': result['stderr'].strip()})
                continue
            for line in result['stdout'].splitlines()[:args.max_hits]:
                surfaces[category].append({'pattern': pattern, 'hit': line})
    dump_yaml({'surfaces': surfaces}, run_dir / 'attack_surface.yaml')
    md = [f"# Attack Surface Map: {target['id']}", '']
    for category, hits in surfaces.items():
        md.extend([f'## {category}', ''])
        if not hits:
            md.append('- No hits')
        else:
            for item in hits[:args.max_hits]:
                if 'hit' in item:
                    md.append(f"- `{item['pattern']}`: `{item['hit']}`")
                else:
                    md.append(f"- `{item['pattern']}` error: `{item['error']}`")
        md.append('')
    write_text(run_dir / 'attack_surface.md', '\n'.join(md))
    _h.save_stage(run_dir, state, 'map')
    print(rel(run_dir / 'attack_surface.md'))

def cmd_score(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    out_dir = run_dir / 'quality'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    state = read_json(run_dir / 'state.json', {})
    intent_tokens = _h._intent_tokens(state)
    results = []
    fail_seen = False
    with candidate_ledger_lock(run_dir):
        data = load_candidates(run_dir)
        candidates = data.get('candidates', [])
        if args.candidate_id:
            candidates = [find_candidate(data, args.candidate_id)]
        for cand in candidates:
            score, strengths, gaps = _h._score_candidate(cand, intent_tokens)
            band = _h._quality_band(score)
            cvss_base, cvss_error = cvss3_base_score(str(cand.get('cvss', '')))
            result = {'candidate_id': cand['id'], 'title': cand.get('title', ''), 'score': score, 'band': band, 'strengths': strengths, 'gaps': gaps, 'cvss_base_score': cvss_base, 'cvss_error': cvss_error}
            cand['quality_score'] = result
            cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'quality-score', 'score': score, 'band': band})
            results.append(result)
            fail_seen = fail_seen or score < args.fail_under
            print(f"{cand['id']} score={score} band={band}")
        save_candidates(run_dir, data)
    artifact = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'results': results}
    dump_yaml(artifact, out_dir / f'quality_{stamp}.yaml')
    md = ['# Candidate Quality Scores', '']
    for result in results:
        md.extend([f"## {result['candidate_id']}: {result['title']}", '', f"- Score: `{result['score']}`", f"- Band: `{result['band']}`", f"- CVSS base score: `{(result['cvss_base_score'] if result['cvss_base_score'] is not None else result['cvss_error'])}`", f"- Strengths: `{', '.join(result['strengths'])}`", f"- Gaps: `{', '.join(result['gaps'])}`", ''])
    write_text(out_dir / f'quality_{stamp}.md', '\n'.join(md))
    if fail_seen:
        raise SystemExit(2)

def cmd_test_skeleton(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    data = load_candidates(run_dir)
    cand = find_candidate(data, args.candidate_id)
    out_dir = run_dir / 'test_skeletons'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'{args.candidate_id}_{stamp}'
    test_name = args.test_name or re.sub('[^A-Za-z0-9]+', '_', cand.get('title', 'candidate')).strip('_')
    if not test_name.startswith('Test'):
        test_name = 'Test' + test_name[:120]
    go_skeleton = f"""func {test_name}(t *testing.T) {{\n    // Preconditions:\n    // - Latest affected version is running locally.\n    // - Required feature/config flags are enabled.\n    // - Positive actor, denied actor, and target object/user are created.\n\n    t.Run("negative control denies access", func(t *testing.T) {{\n        // Prove the receiver cannot access the target through the intended guarded path.\n        // Expected: 403/permission error or equivalent redaction.\n    }})\n\n    t.Run("positive proof demonstrates impact", func(t *testing.T) {{\n        // Execute entrypoint:\n        // {cand.get('entrypoint', '')}\n        //\n        // Observe sink/effect:\n        // {cand.get('sink', '')}\n        //\n        // Expected impact:\n        // {cand.get('impact', '')}\n    }})\n\n    t.Run("cleanup", func(t *testing.T) {{\n        // Remove test users, objects, files, services, tokens, and temporary state.\n    }})\n}}\n"""
    md = [f'# Test Skeleton: {args.candidate_id}', '', f"- Candidate: {cand.get('title', '')}", f'- Framework: `{args.framework}`', '', '## Required Assertions', '', f"- Attacker control: {cand.get('attacker_control', '')}", f"- Entrypoint: {cand.get('entrypoint', '')}", f"- Trust boundary: {cand.get('trust_boundary', '')}", f"- Sink: {cand.get('sink', '')}", f"- Negative control: {cand.get('negative_controls', '')}", '', '## Go Test Skeleton', '', '```go', go_skeleton.rstrip(), '```', '']
    write_text(base.with_suffix('.md'), '\n'.join(md))
    write_text(base.with_suffix('.go.txt'), go_skeleton)

    def mark_skeleton(updated: dict[str, Any]) -> None:
        updated['test_skeleton'] = rel(base.with_suffix('.md'))
        updated.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'test-skeleton', 'artifact': rel(base.with_suffix('.md'))})
    update_candidate_locked(run_dir, args.candidate_id, mark_skeleton)
    print(rel(base.with_suffix('.md')))

def cmd_report(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    references = load_yaml(run_dir / 'references.yaml') if (run_dir / 'references.yaml').exists() else {'references': []}
    out = run_dir / 'reports' / 'triage_draft.md'
    md = [f"# Triage Draft: {target['id']}", '', f"- Run: `{state.get('run_id')}`", f"- Target: `{target.get('name', target['id'])}`", f"- Source: `{target.get('source_path')}`", '', '## Candidates', '']
    for cand in data.get('candidates', []):
        md.extend([f"### {cand['id']}: {cand['title']}", '', f"- Status: `{cand.get('status')}`", f"- Surface: `{cand.get('surface')}`", f"- Weakness: `{cand.get('weakness')}`", f"- CVE: `{cand.get('cve')}`", f"- CWE: `{cand.get('cwe', cand.get('weakness', ''))}`", f"- CVSS: `{cand.get('cvss', '')}`", f"- Impact: {cand.get('impact')}", f"- Attacker control: {cand.get('attacker_control')}", f"- Entrypoint: {cand.get('entrypoint', '')}", f"- Trust boundary: {cand.get('trust_boundary', '')}", f"- Latest affected: `{cand.get('latest_affected', '')}`", f"- Sink: `{cand.get('sink')}`", f"- Duplicate status: `{cand.get('novelty')}`", f"- Proof: `{cand.get('proof')}`", f"- Negative controls: {cand.get('negative_controls', '')}", f"- Root cause: {cand.get('root_cause', '')}", f"- Variant analysis: {cand.get('variant_analysis', '')}", f"- Patch/advisory diff: {cand.get('patch_diff', '')}", f"- Exploitability: {cand.get('exploitability', '')}", f"- Safety notes: {cand.get('safety_notes', '')}", f"- Framework mappings: `{json.dumps(cand.get('framework_mappings', {}), sort_keys=True)}`", f"- Decision reason: {cand.get('decision_reason', '')}", ''])
    if references.get('references'):
        md.extend(['## References Ledger', ''])
        for ref in references.get('references', []):
            md.append(f"- `{ref.get('kind', '')}` {ref.get('title', '')}: {ref.get('url', ref.get('path', ''))}")
        md.append('')
    write_text(out, '\n'.join(md))
    print(rel(out))

def cmd_reference_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    path = run_dir / 'references.yaml'
    data = load_yaml(path) if path.exists() else {'references': []}
    ref = {'added_at': dt.datetime.now().isoformat(timespec='seconds'), 'kind': args.kind, 'title': args.title, 'url': args.url or '', 'path': args.path or '', 'candidate_id': args.candidate_id or '', 'notes': args.notes or '', 'trusted': bool(args.trusted)}
    data.setdefault('references', []).append(ref)
    dump_yaml(data, path)
    print(rel(path))

def cmd_dashboard(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    candidates = data.get('candidates', [])
    counts: dict[str, int] = {}
    for cand in candidates:
        status = cand.get('status', 'unknown')
        counts[status] = counts.get(status, 0) + 1
    rows = []
    for cand in candidates:
        ok, blocking = promotion_findings(cand)
        rows.append(f"<tr><td>{html.escape(cand.get('id', ''))}</td><td>{html.escape(cand.get('status', ''))}</td><td>{html.escape(cand.get('title', ''))}</td><td>{html.escape(cand.get('weakness', ''))}</td><td>{html.escape(cand.get('novelty', ''))}</td><td>{html.escape(cand.get('proof', ''))}</td><td>{('pass' if ok else html.escape(', '.join(blocking)))}</td></tr>")
    html_doc = f"""<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <title>Harness Dashboard - {html.escape(target['id'])}</title>\n  <style>\n    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; color: #17202a; }}\n    table {{ border-collapse: collapse; width: 100%; }}\n    th, td {{ border: 1px solid #ccd1d1; padding: 8px; text-align: left; vertical-align: top; }}\n    th {{ background: #eef2f3; }}\n    code {{ background: #f4f6f7; padding: 1px 4px; }}\n    .summary {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}\n    .pill {{ border: 1px solid #ccd1d1; padding: 8px 10px; border-radius: 6px; background: #fafafa; }}\n  </style>\n</head>\n<body>\n  <h1>Harness Dashboard: {html.escape(target['id'])}</h1>\n  <p>Run <code>{html.escape(str(state.get('run_id')))}</code> in <code>{html.escape(rel(run_dir))}</code></p>\n  <div class="summary">\n    <div class="pill">Stages: {html.escape(', '.join(sorted(state.get('stages', {}).keys())) or 'none')}</div>\n    <div class="pill">Candidates: {len(candidates)}</div>\n    <div class="pill">Status counts: {html.escape(json.dumps(counts, sort_keys=True))}</div>\n  </div>\n  <table>\n    <thead>\n      <tr><th>ID</th><th>Status</th><th>Title</th><th>CWE</th><th>Duplicate Status</th><th>Proof</th><th>Gate</th></tr>\n    </thead>\n    <tbody>\n      {''.join(rows)}\n    </tbody>\n  </table>\n</body>\n</html>\n"""
    out = run_dir / 'dashboard.html'
    write_text(out, html_doc)
    print(rel(out))

def cmd_status(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    counts: dict[str, int] = {}
    for cand in data.get('candidates', []):
        counts[cand.get('status', 'unknown')] = counts.get(cand.get('status', 'unknown'), 0) + 1
    result = {'target': target['id'], 'run': state.get('run_id'), 'status': state.get('status'), 'stages': sorted(state.get('stages', {}).keys()), 'candidates': counts, 'budget': _h.budget_status(run_dir), 'next_action': _h.recommend_next_action(run_dir)}
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"target={result['target']} run={result['run']} status={result['status']}")
        print('stages=' + ','.join(result['stages']))
        print('candidates=' + json.dumps(counts, sort_keys=True))

def cmd_intent_set(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    bad = [t for t in args.threat if t not in _h.INTENT_VOCAB]
    if bad:
        raise SystemExit('unknown threat-model tokens: ' + ','.join(bad) + '; choose from ' + ','.join(sorted(_h.INTENT_VOCAB)))
    state = read_json(run_dir / 'state.json', {})
    threat_model = list(dict.fromkeys(args.threat))
    state['intent'] = {'threat_model': threat_model, 'rationale': args.rationale or '', 'set_at': dt.datetime.now().isoformat(timespec='seconds')}
    write_json(run_dir / 'state.json', state)
    print('intent set: ' + ', '.join(threat_model))

def cmd_intent_show(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state = read_json(run_dir / 'state.json', {})
    intent = state.get('intent') or {}
    if args.json:
        print(json.dumps(intent, indent=2, sort_keys=True))
        return
    tokens = intent.get('threat_model') or []
    if not tokens:
        print('no intent set; run `intent-set <run> --threat <token> ...`')
        print('vocabulary: ' + ', '.join(sorted(_h.INTENT_VOCAB)))
        return
    print('threat model: ' + ', '.join(tokens))
    if intent.get('rationale'):
        print('rationale: ' + intent['rationale'])
    if intent.get('set_at'):
        print('set at: ' + intent['set_at'])

def cmd_budget(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    result = _h.budget_status(run_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"elapsed_minutes={result['elapsed_minutes']}")
        print('budgets=' + json.dumps(result['budgets'], sort_keys=True))
        print('overruns=' + ','.join(result['overruns']) if result['overruns'] else 'overruns=none')
    if result['overruns']:
        raise SystemExit(2)

def cmd_session_start(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    payload = {'harness_version': HARNESS_VERSION, 'run_dir': rel(run_dir), 'state': state, 'target': {'id': target.get('id'), 'name': target.get('name'), 'program': target.get('program'), 'repo_url': target.get('repo_url'), 'source_path': target.get('source_path'), 'latest_release': target.get('latest_release'), 'in_scope': target.get('in_scope', []), 'out_of_scope': target.get('out_of_scope', [])}, 'candidate_count': len(data.get('candidates', [])), 'candidates': [_h._candidate_summary(cand) for cand in data.get('candidates', [])], 'budget': _h.budget_status(run_dir), 'recommended_next_action': _h.recommend_next_action(run_dir), 'knowledge': {'index': rel(ROOT / 'vapt' / 'harness' / 'knowledge' / 'INDEX.md'), 'principles': rel(ROOT / 'vapt' / 'harness' / 'knowledge' / 'principles.md'), 'workflow': rel(ROOT / 'vapt' / 'harness' / 'knowledge' / 'workflow.md'), 'patterns': rel(ROOT / 'vapt' / 'harness' / 'config' / 'surfaces.yaml'), 'scoring': rel(ROOT / 'vapt' / 'harness' / 'knowledge' / 'scoring.yaml')}, 'latest_artifacts': {'source_graph': rel(run_dir / 'source_graph' / 'source_graph.md') if (run_dir / 'source_graph' / 'source_graph.md').exists() else '', 'semantic_graph': rel(run_dir / 'semantic_graph' / 'semantic_graph.md') if (run_dir / 'semantic_graph' / 'semantic_graph.md').exists() else '', 'taint_trace': _h._latest_artifact(run_dir, 'taint_traces'), 'report': rel(run_dir / 'reports' / 'triage_draft.md') if (run_dir / 'reports' / 'triage_draft.md').exists() else '', 'dashboard': rel(run_dir / 'dashboard.html') if (run_dir / 'dashboard.html').exists() else ''}}
    print(json.dumps(payload, indent=2, sort_keys=False))

def cmd_knowledge(args: argparse.Namespace) -> None:
    terms = [term.lower() for term in re.findall('[A-Za-z0-9_:-]{3,}', args.query)]
    if not terms:
        raise SystemExit('knowledge query needs at least one searchable term')
    results = []
    for path in _h._knowledge_files():
        with contextlib.suppress(OSError):
            text = path.read_text(encoding='utf-8', errors='replace')
            score = _h._rank_text(terms, text)
            if score:
                lines = text.splitlines()
                snippets = []
                for idx, line in enumerate(lines, start=1):
                    if any((term in line.lower() for term in terms)):
                        snippets.append({'line': idx, 'text': line[:240]})
                    if len(snippets) >= args.snippets:
                        break
                results.append({'path': rel(path), 'score': score, 'snippets': snippets})
    results.sort(key=lambda item: (-item['score'], item['path']))
    payload = {'query': args.query, 'results': results[:args.limit]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for item in payload['results']:
            print(f"{item['score']} {item['path']}")
            for snippet in item['snippets']:
                print(f"  L{snippet['line']}: {snippet['text']}")

def cmd_explain(args: argparse.Namespace) -> None:
    print('# Command Help')
    print()
    print('```text')
    print(_h._command_help(args.command).rstrip())
    print('```')
    print()
    refs = _h.COMMAND_DOCTRINE.get(args.command, ['knowledge/INDEX.md', 'knowledge/principles.md'])
    print('# Relevant Knowledge')
    print()
    for ref in refs:
        path = ROOT / 'vapt' / 'harness' / ref
        if not path.exists():
            path = ROOT / 'vapt' / ref
        if path.exists():
            print(f'- `{rel(path)}`')
    examples = {'session-start': f'{sys.argv[0]} session-start vapt/engagements/<target>/runs/<target>/<run-id>', 'knowledge': f"{sys.argv[0]} knowledge 'websocket authz negative control'", 'next-action': f'{sys.argv[0]} next-action vapt/engagements/<target>/runs/<target>/<run-id>', 'budget': f'{sys.argv[0]} budget vapt/engagements/<target>/runs/<target>/<run-id>'}
    if args.command in examples:
        print()
        print('# Example')
        print()
        print(f'```sh\n{examples[args.command]}\n```')

def cmd_commands(args: argparse.Namespace) -> None:
    parser = _h.build_parser()
    actions = []
    for action in parser._subparsers._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in sorted(action.choices.items()):
                argspec = []
                for sub_action in subparser._actions:
                    if sub_action.dest == 'help':
                        continue
                    argspec.append({'dest': sub_action.dest, 'option_strings': sub_action.option_strings, 'required': getattr(sub_action, 'required', False), 'nargs': sub_action.nargs, 'default': None if sub_action.default is argparse.SUPPRESS else sub_action.default})
                actions.append({'name': name, 'help': subparser.description or subparser.prog, 'args': argspec})
    print(json.dumps({'version': HARNESS_VERSION, 'commands': actions}, indent=2, sort_keys=False))

def cmd_retro(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    data = load_candidates(run_dir)
    out = run_dir / 'retro.md'
    patch = run_dir / 'retro.patch'
    candidates = data.get('candidates', [])
    passed = []
    noisy = []
    lessons = []
    for cand in candidates:
        ok, blockers = promotion_findings(cand)
        if ok and cand.get('proof') == 'passed':
            passed.append(cand)
        if cand.get('status') in {'rejected', 'hardening-only', 'duplicate'} or blockers:
            noisy.append({'candidate': cand, 'blockers': blockers})
    if passed:
        lessons.append('Promoted candidates had formal proof and dedup records; preserve this gate discipline.')
    if any(('variant_analysis' in item.get('blockers', []) for item in noisy)):
        lessons.append('Variant analysis remained a recurring blocker; run it immediately after first proof.')
    if not lessons:
        lessons.append('No strong reusable lesson identified; continue collecting outcomes.')
    md = [f"# Retro: {target.get('id')} / {state.get('run_id')}", '', f'- Run dir: `{rel(run_dir)}`', f'- Candidate count: `{len(candidates)}`', f'- Gate/proof passed: `{len(passed)}`', f'- Noisy or blocked: `{len(noisy)}`', '', '## Candidates That Passed', '']
    for cand in passed:
        md.append(f"- `{cand.get('id')}` {cand.get('title')} proof=`{cand.get('proof')}` novelty=`{cand.get('novelty')}`")
    if not passed:
        md.append('- None')
    md.extend(['', '## Blocked / Low-Signal Candidates', ''])
    for item in noisy:
        cand = item['candidate']
        md.append(f"- `{cand.get('id')}` {cand.get('title')} status=`{cand.get('status')}` blockers=`{', '.join(item['blockers'])}`")
    if not noisy:
        md.append('- None')
    md.extend(['', '## Lessons To Propagate', ''])
    for lesson in lessons:
        md.append(f'- {lesson}')
    write_text(out, '\n'.join(md) + '\n')
    lesson_file = f"vapt/harness/knowledge/lessons/{dt.datetime.now().strftime('%Y-%m-%d')}_{target.get('id')}_retro.md"
    patch_lines = [f'diff --git a/{lesson_file} b/{lesson_file}', 'new file mode 100644', 'index 0000000..0000000', '--- /dev/null', f'+++ b/{lesson_file}', '@@', f"+# Retro Lesson: {target.get('id')} / {state.get('run_id')}", '+']
    for lesson in lessons:
        patch_lines.append(f'+- {lesson}')
    write_text(patch, '\n'.join(patch_lines) + '\n')
    print(rel(out))
    print(rel(patch))

def cmd_probes(args: argparse.Namespace) -> None:
    items = []
    for name, spec in sorted(_h.PROBE_REGISTRY.items()):
        items.append({'name': name, 'vuln_class': spec['vuln_class'], 'terms': spec['terms']})
    print(json.dumps({'probes': items}, indent=2, sort_keys=False))

def cmd_probes_test(args: argparse.Namespace) -> None:
    fixture = run_path(args.fixture)
    data = load_yaml(fixture) or {}
    candidates = data.get('candidates', {})
    if not isinstance(candidates, dict):
        raise SystemExit('probe fixture must contain candidates mapping')
    run_dir = run_path(args.run_dir) if args.run_dir else ROOT / 'vapt' / 'harness' / 'tests' / 'results' / 'probe_smoke'
    run_dir.mkdir(parents=True, exist_ok=True)
    target = data.get('target') or {'id': 'probe-fixture', 'source_path': '.'}
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from probes.base import ProbeContext
    selected = [args.probe] if args.probe else sorted(_h.PROBE_REGISTRY)
    results = []
    failures = []
    for probe_name in selected:
        if probe_name not in _h.PROBE_REGISTRY:
            raise SystemExit(f'unknown probe: {probe_name}')
        cand = candidates.get(probe_name)
        if not cand:
            failures.append({'probe': probe_name, 'reason': 'fixture candidate missing'})
            continue
        probe = _h.load_probe(probe_name)
        ctx = ProbeContext(run_dir=run_dir, target=target, candidate=dict(cand), knobs={'fixture': str(fixture)})
        probe.prepare(ctx)
        result = probe.run(ctx)
        evidence = probe.evidence(ctx, result)
        probe.cleanup(ctx)
        item = {'probe': probe_name, 'passed': bool(result.get('passed')), 'missing': result.get('missing', []), 'evidence': rel(evidence)}
        results.append(item)
        if not item['passed']:
            failures.append(item)
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    artifact = out_dir / f'probe_smoke_{stamp}.json'
    write_json(artifact, {'fixture': rel(fixture), 'run_dir': rel(run_dir), 'results': results, 'failures': failures})
    print(rel(artifact))
    if failures:
        raise SystemExit(1)

def cmd_playbook(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _state, target = _h.load_run(run_dir)
    playbook_id = args.kind if args.kind != 'auto' else _h._infer_playbook_class(target)
    playbook = _h.TARGET_PLAYBOOKS.get(playbook_id)
    if not playbook:
        raise SystemExit(f'unknown playbook: {playbook_id}')
    out_dir = run_dir / 'playbooks'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    commands = [f'{sys.argv[0]} prepare {rel(run_dir)} --allow-non-git', f'{sys.argv[0]} map {rel(run_dir)}', f'{sys.argv[0]} source-graph {rel(run_dir)}', f'{sys.argv[0]} semantic-graph {rel(run_dir)}', f'{sys.argv[0]} scan-semgrep {rel(run_dir)} --ruleset auto', f"{sys.argv[0]} scan-codeql {rel(run_dir)} --create-database --language {playbook['codeql']} --query security-extended", f"{sys.argv[0]} scan-codeql {rel(run_dir)} --database {rel(run_dir / 'tool_scans' / 'codeql_db' / playbook['codeql'])} --query security-and-quality", f'{sys.argv[0]} hypothesize {rel(run_dir)}']
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'target': target.get('id', ''), 'playbook_id': playbook_id, 'name': playbook['name'], 'checks': playbook['checks'], 'recommended_poc_classes': playbook['poc_classes'], 'commands': commands}
    dump_yaml(payload, out_dir / f'playbook_{playbook_id}_{stamp}.yaml')
    md = [f"# Target Playbook: {playbook['name']}", '', f"- Target: `{target.get('id', '')}`", f'- Playbook: `{playbook_id}`', f"- CodeQL language: `{playbook['codeql']}`", '', '## Review Checks', '']
    md.extend((f'- {item}' for item in playbook['checks']))
    md.extend(['', '## Commands', ''])
    md.extend((f'```sh\n{cmd}\n```' for cmd in commands))
    md.extend(['', '## PoC Templates', ''])
    md.extend((f"- `{item}`: `{sys.argv[0]} scaffold-poc {item} {target.get('id', '')}`" for item in playbook['poc_classes']))
    write_text(out_dir / f'playbook_{playbook_id}_{stamp}.md', '\n'.join(md) + '\n')
    print(rel(out_dir / f'playbook_{playbook_id}_{stamp}.md'))

def cmd_codeql_workflow(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _state, target = _h.load_run(run_dir)
    workflow_id = args.language or _h._infer_playbook_class(target)
    if workflow_id in _h.TARGET_PLAYBOOKS:
        workflow_id = _h.TARGET_PLAYBOOKS[workflow_id]['codeql']
    workflow = _h.CODEQL_WORKFLOWS.get(workflow_id)
    if not workflow:
        raise SystemExit(f'unknown CodeQL workflow: {workflow_id}')
    out_dir = run_dir / 'tool_scans' / 'codeql_workflows'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    database = run_dir / 'tool_scans' / 'codeql_db' / workflow['language']
    commands = [f"{sys.argv[0]} scan-codeql {rel(run_dir)} --create-database --language {workflow['language']} --query {workflow['queries'][0]}"]
    for query in workflow['queries'][1:]:
        commands.append(f'{sys.argv[0]} scan-codeql {rel(run_dir)} --database {rel(database)} --query {query}')
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'target': target.get('id', ''), 'workflow': workflow_id, 'language': workflow['language'], 'queries': workflow['queries'], 'focus': workflow['focus'], 'commands': commands}
    dump_yaml(payload, out_dir / f'codeql_workflow_{workflow_id}_{stamp}.yaml')
    md = [f'# CodeQL Workflow: {workflow_id}', '', f"- Language: `{workflow['language']}`", '']
    md.extend(['## Focus', ''])
    md.extend((f'- {item}' for item in workflow['focus']))
    md.extend(['', '## Commands', ''])
    md.extend((f'```sh\n{cmd}\n```' for cmd in commands))
    write_text(out_dir / f'codeql_workflow_{workflow_id}_{stamp}.md', '\n'.join(md) + '\n')
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(rel(out_dir / f'codeql_workflow_{workflow_id}_{stamp}.md'))

def cmd_scaffold_poc(args: argparse.Namespace) -> None:
    profile_path, target = _load_target_profile(args.target_id)
    if not target:
        raise SystemExit(f'target profile not found: {args.target_id}')
    out_dir = ROOT / 'vapt' / 'pocs' / args.target_id / dt.datetime.now().strftime('%Y-%m-%d')
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_class = re.sub('[^A-Za-z0-9_]+', '_', args.vuln_class).strip('_')
    out = out_dir / f'poc_{safe_class}.py'
    doctrine = ROOT / 'vapt' / 'harness' / 'knowledge' / 'vuln_classes' / args.vuln_class / 'doctrine.md'
    script = f'''#!/usr/bin/env python3\n"""PoC scaffold for {args.vuln_class} on {args.target_id}.\n\nDoctrine: {(rel(doctrine) if doctrine.exists() else 'not available')}\nTarget profile: {(rel(profile_path) if profile_path else args.target_id)}\n\nFill in only authorized, local/captive test logic. Keep positive proof and\nnegative controls separate.\n"""\n\nfrom __future__ import annotations\n\nimport json\nimport sys\nfrom pathlib import Path\n\n\n{_h._poc_template_body(args.vuln_class)}\n\n\ndef main() -> int:\n    result = {{\n        "target": "{args.target_id}",\n        "vuln_class": "{args.vuln_class}",\n        "scaffold_only": True,\n        "ready_for_submission": False,\n        "positive": positive_proof(),\n        "negative": negative_control(),\n    }}\n    print(json.dumps(result, indent=2))\n    return 0\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n'''
    write_text(out, script)
    out.chmod(493)
    print(rel(out))

def cmd_new_probe(args: argparse.Namespace) -> None:
    name = re.sub('[^A-Za-z0-9_]+', '_', args.name).strip('_')
    if not name:
        raise SystemExit('invalid probe name')
    class_name = ''.join((part.capitalize() for part in name.split('_'))) + 'Probe'
    probe_path = ROOT / 'vapt' / 'harness' / 'probes' / f'{name}.py'
    if probe_path.exists() and (not args.force):
        raise SystemExit(f'probe already exists: {rel(probe_path)}')
    doctrine_dir = ROOT / 'vapt' / 'harness' / 'knowledge' / 'vuln_classes' / args.vuln_class
    doctrine_dir.mkdir(parents=True, exist_ok=True)
    doctrine = doctrine_dir / 'doctrine.md'
    if not doctrine.exists():
        write_text(doctrine, f'# {args.vuln_class}\n\nDescribe thesis shape, required proof, sinks, and negative controls.\n')
    code = f'''from __future__ import annotations\n\nfrom .base import Probe, ProbeContext, ProbeResult\n\n\nclass {class_name}(Probe):\n    name = "{name}"\n    vuln_class = "{args.vuln_class}"\n    description = "{args.description or 'Probe scaffold'}"\n\n    def run(self, ctx: ProbeContext) -> ProbeResult:\n        return ProbeResult({{\n            "probe": self.name,\n            "candidate_id": ctx.candidate.get("id"),\n            "passed": False,\n            "missing": ["implement probe logic"],\n            "recommended_next": "Fill this probe with a bounded local differential test.",\n        }})\n'''
    write_text(probe_path, code)
    test_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'probes'
    test_dir.mkdir(parents=True, exist_ok=True)
    write_text(test_dir / f'test_{name}.py', f'import sys\nfrom pathlib import Path\n\nsys.path.insert(0, str(Path(__file__).resolve().parents[2]))\nfrom probes.{name} import {class_name}\n\n\ndef test_probe_metadata():\n    probe = {class_name}()\n    assert probe.name == {name!r}\n    assert probe.vuln_class == {args.vuln_class!r}\n')
    print(rel(probe_path))
