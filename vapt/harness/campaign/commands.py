"""CLI handlers + helper functions for the campaign lifecycle.

The campaign layer drives a per-target sweep through reusable
campaign-module adapters: campaign-start (advisory refresh + plan
files), campaign-plan (rank modules), campaign-adapter-check (validate
adapter manifests), campaign-dashboard (status summary),
campaign-run (execute selected modules), campaign-gate (verify
outcomes), campaign-flow-check (CI-safe end-to-end), and the
candidate->campaign linkage command.

The handlers are still registered through cli.py via the harness
module's namespace, so harness.py re-imports each one. The `_h` lookup
below is the same dual sys.modules pattern cli.py uses: it lets these
handlers reach the still-in-harness helpers (load_run, _target_*,
_adapter_*, run_cmd, etc.) without an import-time circular.
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
from pathlib import Path
from typing import Any

from atomic_io import load_yaml, read_json, write_json, write_text
from campaign.context import campaign_module_catalog_path, load_campaign_modules
from core import HARNESS_VERSION, ROOT, rel, run_path, source_path
from gates.promotion import campaign_evidence_findings, queue_evidence_findings
from ledger.candidates import find_candidate, load_candidates, update_candidate_locked
from ledger.submissions import load_outcome_tuning
from watch.state import load_watch_state, queue_entries, save_watch_state


_h = sys.modules.get("harness") or sys.modules.get("__main__")
if _h is None or not hasattr(_h, "load_run"):
    import harness as _h  # noqa: E402


def cmd_candidate_link_campaign(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    campaign_dir = run_path(args.campaign_dir)
    campaign_run_path = campaign_dir / 'campaign_run.json'
    campaign_gate_path = campaign_dir / 'campaign_gate.json'
    if args.campaign_run:
        campaign_run_path = run_path(args.campaign_run)
    if args.campaign_gate:
        campaign_gate_path = run_path(args.campaign_gate)
    if not campaign_run_path.exists():
        raise SystemExit(f'campaign_run artifact not found: {rel(campaign_run_path)}')
    if not campaign_gate_path.exists():
        raise SystemExit(f'campaign_gate artifact not found: {rel(campaign_gate_path)}')
    campaign_run = read_json(campaign_run_path, {})
    campaign_gate = read_json(campaign_gate_path, {})
    module_name = args.module
    modules = campaign_run.get('modules') or []
    matching = [module for module in modules if module_name in {str(module.get('module_id') or ''), str(module.get('local_name') or '')}]
    if not matching:
        raise SystemExit(f'module not found in campaign_run: {module_name}')
    if args.require_gate and campaign_gate.get('passed') is not True:
        raise SystemExit('campaign gate did not pass')
    if args.require_module_pass and (not any((module.get('status') == 'pass' for module in matching))):
        raise SystemExit('campaign module did not pass')

    def updater(cand: dict[str, Any]) -> None:
        cand['evidence_kind'] = 'runtime_campaign'
        cand['campaign_run'] = rel(campaign_run_path)
        cand['campaign_gate'] = rel(campaign_gate_path)
        cand['campaign_module'] = module_name
        cand['campaign_evidence'] = {'linked_at': dt.datetime.now().isoformat(timespec='seconds'), 'campaign_dir': rel(campaign_dir), 'campaign_run': rel(campaign_run_path), 'campaign_gate': rel(campaign_gate_path), 'campaign_module': module_name, 'gate_passed': campaign_gate.get('passed') is True, 'module_status': matching[0].get('status'), 'module_id': matching[0].get('module_id'), 'local_name': matching[0].get('local_name')}
        cand.setdefault('history', []).append({'at': dt.datetime.now().isoformat(timespec='seconds'), 'event': 'campaign-linked', 'campaign_gate': rel(campaign_gate_path), 'campaign_module': module_name})
    cand = update_candidate_locked(run_dir, args.candidate_id, updater)
    ok, blockers, warnings = campaign_evidence_findings(cand)
    payload = {'candidate_id': args.candidate_id, 'campaign_run': rel(campaign_run_path), 'campaign_gate': rel(campaign_gate_path), 'campaign_module': module_name, 'passed': ok, 'blockers': blockers, 'warnings': warnings}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(f"{args.candidate_id} campaign_link={('pass' if ok else 'fail')}")
        if blockers:
            print('blocking=' + ','.join(blockers))
        if warnings:
            print('warnings=' + ','.join(warnings))
    if args.fail and (not ok):
        raise SystemExit(2)

def _campaign_start_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Campaign Start: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Campaign dir: `{payload['campaign_dir']}`", f"- Target profile: `{payload['target_profile']}`", f"- Adapter present: `{payload['adapter_present']}`", '', '## Artifacts', '']
    for artifact in payload['artifacts']:
        lines.append(f"- `{artifact['name']}`: `{artifact['path']}`")
    lines.extend(['', '## Next Commands', ''])
    for command in payload['next_commands']:
        lines.append(f'```sh\n{command}\n```')
    return '\n'.join(lines).rstrip() + '\n'

def _campaign_next_commands_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Next Commands: {payload['target_id']}", '', 'Run these in order. Do not promote runtime candidates before `campaign-gate` passes.', '']
    for idx, command in enumerate(payload['next_commands'], 1):
        lines.append(f'## {idx}. Step')
        lines.append('')
        lines.append(f'```sh\n{command}\n```')
        lines.append('')
    if not payload['adapter_present']:
        lines.extend(['## Adapter Missing', '', 'No target adapter manifest was found. Create one under:', '', f"`{payload['target_root']}/adapters/`", '', 'Then run `campaign-start` again.', ''])
    return '\n'.join(lines).rstrip() + '\n'

def _write_campaign_start_plan_files(target_ref: str, campaign_dir: Path) -> dict[str, str]:
    artifacts = {}
    patch_path = campaign_dir / 'patch_first_plan.md'
    with contextlib.redirect_stdout(io.StringIO()):
        _h.cmd_patch_first_plan(argparse.Namespace(target=target_ref, limit=12, timeout=10, out=str(patch_path), json=False))
    artifacts['patch_first_plan'] = rel(patch_path)
    campaign_path = campaign_dir / 'campaign_plan.md'
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_campaign_plan(argparse.Namespace(target=target_ref, limit=8, out=str(campaign_path), json=False))
    artifacts['campaign_plan'] = rel(campaign_path)
    return artifacts

def _campaign_refresh_package_metadata(target: dict[str, Any], args: argparse.Namespace) -> tuple[str, str, str]:
    repo = _h._github_repo_from_url(str(target.get('repo_url') or ''))
    languages = {str(item).lower() for item in _h.as_list(target.get('language'))}
    ecosystem = args.refresh_ecosystem or target.get('osv_ecosystem') or target.get('ghsa_ecosystem') or target.get('package_ecosystem') or ''
    if not ecosystem:
        if 'go' in languages and repo:
            ecosystem = 'Go'
        elif 'python' in languages:
            ecosystem = 'PyPI'
        elif languages & {'javascript', 'typescript', 'node', 'nodejs'}:
            ecosystem = 'npm'
    package = args.refresh_package or target.get('osv_package') or target.get('ghsa_package') or target.get('package_name') or ''
    if not package:
        if str(ecosystem).lower() == 'go' and repo:
            package = f'github.com/{repo}'
        elif str(ecosystem).lower() in {'pypi', 'npm'}:
            package = str(target.get('name') or target.get('id') or '').strip()
    return (str(ecosystem or ''), str(package or ''), repo)

def _campaign_refresh_sources(target: dict[str, Any], args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    ecosystem, package, repo = _campaign_refresh_package_metadata(target, args)
    warnings: list[str] = []
    source_base: dict[str, Any] = {'ecosystem': ecosystem, 'package': package, 'allow_network': not bool(args.refresh_fixture), 'repo_path': target.get('source_path') or target.get('repo_path') or ''}
    aliases = _h.as_list(target.get('package_aliases'))
    if args.refresh_package_alias:
        aliases.extend(args.refresh_package_alias)
    if aliases:
        source_base['package_aliases'] = aliases
    if args.refresh_fixture:
        return ([{**source_base, 'kind': 'osv_advisories', 'fixture': args.refresh_fixture}], warnings)
    if not ecosystem or not package:
        warnings.append('missing ecosystem/package metadata; pass --refresh-ecosystem and --refresh-package or add target osv_* metadata')
        return ([], warnings)
    source_kind = args.refresh_source
    if source_kind not in {'osv', 'ghsa', 'both'}:
        warnings.append(f'unsupported refresh source: {source_kind}')
        return ([], warnings)
    sources = []
    if source_kind in {'osv', 'both'}:
        sources.append({**source_base, 'kind': 'osv_advisories'})
    if source_kind in {'ghsa', 'both'}:
        ghsa = {**source_base, 'ecosystem': _h._ghsa_ecosystem(ecosystem), 'kind': 'ghsa_advisories'}
        if repo:
            ghsa['repo'] = repo
        sources.append(ghsa)
    return (sources, warnings)

def _campaign_advisory_refresh_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Advisory Refresh: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Status: `{payload['status']}`", f"- Sources: `{len(payload['sources'])}`", f"- New queue entries: `{len(payload['new_queue_entries'])}`", f"- Pending queue depth: `{payload['pending_queue_depth']}`", '']
    if payload.get('warnings'):
        lines.append('## Warnings')
        lines.append('')
        for warning in payload['warnings']:
            lines.append(f'- {warning}')
        lines.append('')
    if payload['sources']:
        lines.append('## Sources')
        lines.append('')
        for source in payload['sources']:
            source_bits = [str(source.get('kind') or '')]
            if source.get('ecosystem') or source.get('package'):
                source_bits.append(f"{source.get('ecosystem')}/{source.get('package')}")
            if source.get('fixture'):
                source_bits.append(f"fixture={source.get('fixture')}")
            lines.append(f"- {' '.join((bit for bit in source_bits if bit))}")
        lines.append('')
    lines.append('## Results')
    lines.append('')
    for result in payload['results']:
        ref = result.get('advisory') or result.get('ref') or ''
        detail = f' {ref}' if ref else ''
        lines.append(f"- `{result.get('kind')}` `{result.get('status')}`{detail}")
    if not payload['results']:
        lines.append('- No polling result was produced.')
    lines.append('')
    lines.append('## New Queue Entries')
    lines.append('')
    for entry in payload['new_queue_entries']:
        lines.append(f"- `{entry['queue_id']}` `{entry['type']}` `{entry['ref']}`: {entry['summary']}")
    if not payload['new_queue_entries']:
        lines.append('- None.')
    return '\n'.join(lines).rstrip() + '\n'

def _run_campaign_advisory_refresh(target_id: str, target: dict[str, Any], campaign_root: Path, args: argparse.Namespace) -> dict[str, Any]:
    before_ids = {str(row.get('queue_id')) for row in queue_entries(target_id, include_claimed=True)}
    sources, warnings = _campaign_refresh_sources(target, args)
    trigger_patterns = _h.as_list(target.get('trigger_patterns')) or _h.as_list(target.get('category'))
    profile = {'target_id': target_id, 'repo_path': target.get('source_path') or target.get('repo_path') or '', 'ecosystem': sources[0].get('ecosystem') if sources else '', 'package_aliases': _h.as_list(target.get('package_aliases')), 'trigger_patterns': [str(item) for item in trigger_patterns], 'sources': sources}
    state: dict[str, Any] = {'target_id': target_id, 'sources': {}}
    if not args.refresh_ephemeral_state:
        state = load_watch_state(target_id)
    results: list[dict[str, Any]] = []
    for source in sources:
        results.extend(_h.poll_watch_source(profile, source, state, args.refresh_seed, args.refresh_timeout))
    if sources and (not args.refresh_ephemeral_state):
        save_watch_state(target_id, state)
    after_rows = queue_entries(target_id, include_claimed=True)
    new_rows = [row for row in after_rows if str(row.get('queue_id')) not in before_ids]
    pending_depth = len(queue_entries(target_id, include_claimed=False))
    new_entries = []
    for row in new_rows:
        seeds = row.get('candidate_seeds') or []
        first_seed = seeds[0] if seeds and isinstance(seeds[0], dict) else {}
        new_entries.append({'queue_id': row.get('queue_id'), 'type': row.get('type'), 'ref': row.get('ref'), 'path': rel(Path(row['_path'])), 'summary': first_seed.get('title') or row.get('ref') or row.get('type') or ''})
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'target_id': target_id, 'status': 'completed' if sources else 'skipped', 'sources': sources, 'warnings': warnings, 'results': results, 'new_queue_entries': new_entries, 'pending_queue_depth': pending_depth, 'state_persisted': bool(sources and (not args.refresh_ephemeral_state))}
    write_json(campaign_root / 'advisory_refresh.json', payload)
    write_text(campaign_root / 'advisory_refresh.md', _campaign_advisory_refresh_markdown(payload))
    return payload

def cmd_campaign_start(args: argparse.Namespace) -> None:
    profile_path, target = _h._target_profile_by_arg(args.target)
    target_id = str(target.get('id') or profile_path.stem)
    bb_root = _h._target_bb_root(profile_path)
    target_cli_ref = target_id if rel(profile_path).startswith('vapt/engagements/') else rel(profile_path)
    stamp = args.name or dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    campaign_root = run_path(args.out_dir) if args.out_dir else bb_root / 'campaigns' / stamp
    campaign_root.mkdir(parents=True, exist_ok=True)
    write_json(campaign_root / 'target_snapshot.json', target)
    write_text(campaign_root / 'candidates.yaml', 'schema_version: 2\ncandidates: []\n')
    advisory_refresh: dict[str, Any] | None = None
    if args.refresh_advisories:
        advisory_refresh = _run_campaign_advisory_refresh(target_id, target, campaign_root, args)
    artifact_paths = _write_campaign_start_plan_files(str(profile_path), campaign_root)
    adapter_present = False
    adapter_path = None
    adapter_artifacts: dict[str, str] = {}
    with contextlib.suppress(SystemExit):
        adapter_path, _adapter = _h._load_target_adapter(target_cli_ref)
        adapter_present = True
    if adapter_present and adapter_path:
        adapter_check_path = campaign_root / 'adapter_check.md'
        with contextlib.redirect_stdout(io.StringIO()):
            cmd_campaign_adapter_check(argparse.Namespace(target=target_cli_ref, out=str(adapter_check_path), json=False, fail=False))
        adapter_artifacts['adapter_check'] = rel(adapter_check_path)
        mutation_path = campaign_root / 'mutation_plan.md'
        with contextlib.redirect_stdout(io.StringIO()):
            _h.cmd_mutation_plan(argparse.Namespace(target=target_cli_ref, module=None, run_dir=None, out=str(mutation_path), json=False))
        adapter_artifacts['mutation_plan'] = rel(mutation_path)
    run_dir = campaign_root / 'run'
    next_commands = []
    if advisory_refresh:
        for entry in advisory_refresh.get('new_queue_entries', []):
            next_commands.append(f".venv-vapt/bin/python vapt/harness/harness.py candidate-from-queue {rel(run_dir)} {entry['queue_id']} --claim")
    if adapter_present:
        next_commands.extend([f'.venv-vapt/bin/python vapt/harness/harness.py campaign-run --target {target_cli_ref} --out-dir {rel(run_dir)} --validate-mutation --fail', f'.venv-vapt/bin/python vapt/harness/harness.py campaign-gate {rel(run_dir)} --revalidate-mutation --fail'])
    else:
        next_commands.append(f'.venv-vapt/bin/python vapt/harness/harness.py campaign-adapter-check --target {target_cli_ref} --fail')
    next_commands.extend([f".venv-vapt/bin/python vapt/harness/harness.py campaign-dashboard {target_cli_ref} --out {rel(campaign_root / 'campaign_dashboard.md')}", f".venv-vapt/bin/python vapt/harness/harness.py patch-first-plan {target_cli_ref} --out {rel(campaign_root / 'patch_first_plan.md')}"])
    artifacts = [{'name': 'target_snapshot', 'path': rel(campaign_root / 'target_snapshot.json')}, {'name': 'candidates', 'path': rel(campaign_root / 'candidates.yaml')}, *([{'name': 'advisory_refresh', 'path': rel(campaign_root / 'advisory_refresh.md')}, {'name': 'advisory_refresh_json', 'path': rel(campaign_root / 'advisory_refresh.json')}] if advisory_refresh else []), *[{'name': name, 'path': path} for name, path in artifact_paths.items()], *[{'name': name, 'path': path} for name, path in adapter_artifacts.items()]]
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'target_id': target_id, 'target_profile': rel(profile_path), 'target_root': rel(bb_root), 'campaign_dir': rel(campaign_root), 'adapter_present': adapter_present, 'adapter_manifest': rel(adapter_path) if adapter_path else '', 'advisory_refresh': advisory_refresh or {}, 'artifacts': artifacts, 'next_commands': next_commands}
    write_json(campaign_root / 'campaign_start.json', payload)
    write_text(campaign_root / 'campaign_start.md', _campaign_start_markdown(payload))
    write_text(campaign_root / 'NEXT_COMMANDS.md', _campaign_next_commands_markdown(payload))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(campaign_root / 'campaign_start.md'))
        print(rel(campaign_root / 'NEXT_COMMANDS.md'))

def _campaign_flow_check_markdown(payload: dict[str, Any]) -> str:
    lines = ['# Campaign Flow Check', '', f"- Generated at: `{payload['generated_at']}`", f"- Passed: `{payload['passed']}`", f"- Campaign dir: `{payload['campaign_dir']}`", f"- Candidate id: `{payload.get('candidate_id') or ''}`", '', '## Checks', '']
    for check in payload['checks']:
        lines.append(f"- `{check['name']}` passed=`{check['passed']}` {check.get('detail', '')}")
    lines.extend(['', '## Artifacts', ''])
    for artifact in payload['artifacts']:
        lines.append(f'- `{artifact}`')
    return '\n'.join(lines).rstrip() + '\n'

def cmd_campaign_flow_check(args: argparse.Namespace) -> None:
    base = run_path(args.out_dir) if args.out_dir else ROOT / 'vapt' / 'harness' / 'tests' / 'results' / 'campaign-flow-check'
    if base.exists():
        shutil.rmtree(base)
    campaign_dir = base / 'campaign'
    target_profile = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'targets' / 'campaign_flow_target.yaml'
    fixture = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'advisories' / 'osv_phase4_sample.json'
    adapter = ROOT / 'vapt' / 'harness' / 'tests' / 'fixtures' / 'adapters' / 'fixture_adapter.yaml'
    checks: list[dict[str, Any]] = []
    artifacts: list[str] = []
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_campaign_start(argparse.Namespace(target=str(target_profile), name=None, out_dir=str(campaign_dir), refresh_advisories=True, refresh_source='osv', refresh_ecosystem=None, refresh_package=None, refresh_package_alias=None, refresh_fixture=str(fixture), refresh_timeout=20, refresh_seed=True, refresh_ephemeral_state=True, json=False))
    start = read_json(campaign_dir / 'campaign_start.json', {})
    refresh = start.get('advisory_refresh') or {}
    queue_entries_new = refresh.get('new_queue_entries') or []
    checks.append({'name': 'campaign_start', 'passed': bool(start and queue_entries_new), 'detail': f'queue_entries={len(queue_entries_new)}'})
    if not queue_entries_new:
        raise SystemExit('campaign-flow-check failed: no queue entries generated')
    queue_id = queue_entries_new[0]['queue_id']
    run_dir = campaign_dir / 'run'
    with contextlib.redirect_stdout(io.StringIO()):
        _h.cmd_candidate_from_queue(_h._flow_args(run_dir=str(run_dir), queue_id=queue_id, claim=True, campaign_module='authz_matrix'))
    candidates = load_candidates(run_dir).get('candidates', [])
    cand = candidates[-1] if candidates else {}
    candidate_id = str(cand.get('id') or '')
    queue_ok, queue_blockers, _queue_warnings = queue_evidence_findings(cand)
    campaign_seed_ok = bool((cand.get('campaign_evidence') or {}).get('campaign_start'))
    checks.append({'name': 'candidate_from_queue', 'passed': bool(candidate_id and queue_ok and campaign_seed_ok), 'detail': ','.join(queue_blockers)})
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_campaign_run(argparse.Namespace(target=None, adapter=str(adapter), module=None, out_dir=str(run_dir), timeout=120, allowed_exit_code=None, dry_run=False, validate_mutation=True, allow_missing_mutation=False, allow_unknown_variants=False, skip_adapter_check=False, out=None, json=False, fail=True))
        cmd_campaign_gate(argparse.Namespace(campaign_dir=str(run_dir), revalidate_mutation=True, allow_missing_mutation=False, allow_unknown_variants=False, out=None, json=False, fail=True))
        cmd_candidate_link_campaign(argparse.Namespace(run_dir=str(run_dir), candidate_id=candidate_id, campaign_dir=str(run_dir), module='authz_matrix', campaign_run=None, campaign_gate=None, require_gate=True, require_module_pass=True, json=False, fail=True))
    data = load_candidates(run_dir)
    cand = find_candidate(data, candidate_id)
    campaign_ok, campaign_blockers, _campaign_warnings = campaign_evidence_findings(cand)
    queue_ok, queue_blockers, _queue_warnings = queue_evidence_findings(cand)
    checks.append({'name': 'campaign_run_gate_link', 'passed': campaign_ok, 'detail': ','.join(campaign_blockers)})
    checks.append({'name': 'queue_provenance_gate', 'passed': queue_ok, 'detail': ','.join(queue_blockers)})
    artifacts.extend((rel(path) for path in [campaign_dir / 'campaign_start.json', campaign_dir / 'advisory_refresh.json', run_dir / 'candidates.yaml', run_dir / 'campaign_run.json', run_dir / 'campaign_gate.json'] if path.exists()))
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'passed': all((check['passed'] for check in checks)), 'campaign_dir': rel(campaign_dir), 'candidate_id': candidate_id, 'checks': checks, 'artifacts': artifacts}
    write_json(base / 'campaign_flow_check.json', payload)
    write_text(base / 'campaign_flow_check.md', _campaign_flow_check_markdown(payload))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(base / 'campaign_flow_check.md'))
    if args.fail and (not payload['passed']):
        raise SystemExit(2)

def _campaign_history(bb_root: Path) -> dict[str, Any]:
    modules: dict[str, dict[str, Any]] = {}
    campaigns = []
    seen_artifacts: set[str] = set()

    def add_module(module_row: dict[str, Any], source_path: Path) -> None:
        raw_module = str(module_row.get('module') or source_path.parent.name)
        key = _h._module_key(raw_module)
        if not key:
            return
        if module_row.get('artifact_dir'):
            artifact_path = str(module_row.get('artifact_dir'))
        elif source_path.name == 'campaign.json':
            artifact_path = rel(source_path.parent / 'modules' / raw_module)
        else:
            artifact_path = rel(source_path.parent)
        artifact = _h._module_artifact_key(artifact_path)
        if artifact and artifact in seen_artifacts:
            return
        if artifact:
            seen_artifacts.add(artifact)
        item = modules.setdefault(key, {'runs': 0, 'checks': 0, 'candidate_signals': 0, 'failed_expectations': 0, 'verdicts': [], 'artifacts': []})
        item['runs'] += 1
        item['checks'] += int(module_row.get('check_count') or 0)
        item['candidate_signals'] += len(module_row.get('finding_candidates') or [])
        item['failed_expectations'] += sum((1 for check in module_row.get('checks', []) if isinstance(check, dict) and check.get('expectation_passed') is False))
        if module_row.get('verdict'):
            item['verdicts'].append(str(module_row.get('verdict')))
        if artifact:
            item['artifacts'].append(artifact)
    for path in sorted((bb_root / 'runs').glob('*/*/campaign.json')):
        if 'smoke' in path.parent.name.lower():
            continue
        with contextlib.suppress(Exception):
            data = read_json(path, {})
            campaigns.append({'path': rel(path), 'verdict': data.get('verdict'), 'finished_at': data.get('finished_at')})
            for module_row in data.get('modules', []):
                if isinstance(module_row, dict):
                    add_module(module_row, path)
    for path in sorted((bb_root / 'runs').glob('*/*/modules/*/results.json')):
        if any(('smoke' in part.lower() for part in path.parts)):
            continue
        with contextlib.suppress(Exception):
            data = read_json(path, {})
            if isinstance(data, dict):
                data.setdefault('module', path.parent.name)
                data.setdefault('artifact_dir', rel(path.parent))
                add_module(data, path)
    return {'campaigns': campaigns, 'modules': modules}

def _score_campaign_module(module: dict[str, Any], target: dict[str, Any], status: str) -> tuple[float, list[str]]:
    target_text = ' '.join((str(item) for item in [target.get('id', ''), target.get('name', ''), target.get('category', ''), target.get('purpose', ''), target.get('attack_surface', ''), target.get('in_scope', ''), target.get('out_of_scope', ''), target.get('notes', ''), target.get('program', '')])).lower()
    keywords = [str(item).lower() for item in module.get('keywords', [])]
    matches = [item for item in keywords if item and item in target_text]
    score = 20.0 + min(len(matches), 10) * 5.0
    reasons = []
    if matches:
        reasons.append('target matches: ' + ', '.join(matches[:8]))
    else:
        reasons.append('no strong keyword match in target profile')
    family = str(module.get('family') or '')
    if family == 'runtime' and any((term in target_text for term in ['api', 'web', 'server', 'dashboard', 'tenant', 'org'])):
        score += 10
        reasons.append('runtime surface present')
    if family == 'source_runtime' and any((term in target_text for term in ['parser', 'file', 'archive', 'plugin', 'model', 'upload'])):
        score += 10
        reasons.append('source/runtime boundary present')
    if family == 'source' and any((term in target_text for term in ['open source', 'github', 'cve', 'patch'])):
        score += 8
        reasons.append('source history can be mined')
    if len(target.get('known_duplicates') or []) >= 3 and module.get('id') == 'patch_diff_regression':
        score += 10
        reasons.append('duplicate pressure suggests patch-diff regression mining')
    status_adjustments = {'untested': (25, 'untested module'), 'partial': (35, 'partial prior coverage needs closure'), 'candidate_signal': (12, 'prior candidate signal needs deeper proof'), 'tested_unknown': (8, 'tested but not cleanly closed'), 'closed': (-20, 'recently closed by prior run')}
    adjustment, reason = status_adjustments.get(status, (0, status))
    score += adjustment
    reasons.append(reason)
    tuning = load_outcome_tuning()
    module_tuning = (tuning.get('module_adjustments') or {}).get(str(module.get('id') or ''), {})
    if module_tuning:
        outcome_adjustment = float(module_tuning.get('score_adjustment') or 0)
        score += outcome_adjustment
        reasons.append(f"outcome tuning module_adjustment={round(outcome_adjustment, 2)} acceptance={module_tuning.get('acceptance_rate')} duplicate={module_tuning.get('duplicate_rate')}")
    return (round(score, 2), reasons)

def _campaign_plan_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Campaign Plan: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Target profile: `{payload['target_profile']}`", f"- Module catalog: `{payload['module_catalog']}`", f"- Prior campaigns: `{payload['coverage']['prior_campaigns']}`", '', '## Coverage', '']
    for key in ['closed', 'partial', 'candidate_signal', 'tested_unknown', 'untested', 'total']:
        lines.append(f"- `{key}`: `{payload['coverage'].get(key, 0)}`")
    lines.extend(['', '## Next Modules', ''])
    for item in payload['next_modules']:
        lines.append(f"- `{item['id']}` score=`{item['score']}` status=`{item['status']}`")
        lines.append(f"  - {item['title']}")
        lines.append(f"  - impact: {item['impact']}")
        lines.append(f"  - why: {'; '.join(item['reasons'][:4])}")
    if not payload['next_modules']:
        lines.append('- None')
    lines.extend(['', '## Full Ranking', ''])
    for item in payload['modules']:
        lines.append(f"- `{item['id']}` score=`{item['score']}` status=`{item['status']}` runs=`{item['history'].get('runs', 0)}` checks=`{item['history'].get('checks', 0)}`")
    return '\n'.join(lines) + '\n'

def cmd_campaign_plan(args: argparse.Namespace) -> None:
    profile_path, target = _h._target_profile_by_arg(args.target)
    bb_root = _h._target_bb_root(profile_path)
    history = _campaign_history(bb_root)
    ranked = []
    coverage = {'closed': 0, 'partial': 0, 'candidate_signal': 0, 'tested_unknown': 0, 'untested': 0, 'total': 0, 'prior_campaigns': len(history['campaigns'])}
    for module in load_campaign_modules():
        module_id = str(module.get('id') or '')
        module_history = history['modules'].get(module_id, {})
        status = _h._module_status(module_history)
        score, reasons = _score_campaign_module(module, target, status)
        coverage[status] = int(coverage.get(status, 0)) + 1
        coverage['total'] += 1
        ranked.append({'id': module_id, 'title': module.get('title', ''), 'family': module.get('family', ''), 'impact': module.get('impact', ''), 'adapter_requirements': module.get('adapter_requirements', []), 'stop_condition': module.get('stop_condition', ''), 'status': status, 'score': score, 'reasons': reasons, 'history': module_history})
    ranked.sort(key=lambda item: (-float(item['score']), item['id']))
    next_modules = [item for item in ranked if item['status'] in {'untested', 'partial', 'candidate_signal', 'tested_unknown'}][:args.limit]
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'target_id': target.get('id') or profile_path.stem, 'target_profile': rel(profile_path), 'target_root': rel(bb_root), 'module_catalog': rel(campaign_module_catalog_path()), 'coverage': coverage, 'next_modules': next_modules, 'modules': ranked}
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _campaign_plan_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_campaign_plan_markdown(payload).rstrip())

def _campaign_adapter_check_markdown(payload: dict[str, Any]) -> str:
    lines = ['# Campaign Adapter Check', '', f"- Generated at: `{payload['generated_at']}`", f"- Harness version: `{payload['harness_version']}`", f"- Passed: `{payload['passed']}`", f"- Contract: `{payload['contract']}`", f"- Catalog: `{payload['module_catalog']}`", '', '## Adapters', '']
    for item in payload['adapters']:
        lines.append(f"- `{item['path']}` target=`{item['target_id']}` adapter=`{item['adapter_id']}` status=`{item['status']}`")
        for error_item in item['errors']:
            lines.append(f'  - error: {error_item}')
        for warning_item in item['warnings']:
            lines.append(f'  - warning: {warning_item}')
        for module in item['modules']:
            lines.append(f"  - module `{module['id']}` local=`{module['local_name']}` status=`{module['status']}`")
    return '\n'.join(lines) + '\n'

def cmd_campaign_adapter_check(args: argparse.Namespace) -> None:
    modules = {str(item.get('id')): item for item in load_campaign_modules()}
    contract = load_yaml(_h.module_contract_path()) or {}
    paths = _h._adapter_manifest_paths(args.target)
    if not paths:
        raise SystemExit('no adapter manifests found')
    adapters = [_h._adapter_check_one(path, modules, contract) for path in paths]
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'contract': rel(_h.module_contract_path()), 'module_catalog': rel(campaign_module_catalog_path()), 'passed': all((item['status'] == 'pass' for item in adapters)), 'adapters': adapters}
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _campaign_adapter_check_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_campaign_adapter_check_markdown(payload).rstrip())
    if args.fail and (not payload['passed']):
        raise SystemExit(2)

def _campaign_dashboard_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Campaign Dashboard: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Target profile: `{payload['target_profile']}`", f"- Target root: `{payload['target_root']}`", '', '## Coverage', '']
    for key in ['closed', 'partial', 'candidate_signal', 'tested_unknown', 'untested', 'total']:
        lines.append(f"- `{key}`: `{payload['coverage'].get(key, 0)}`")
    lines.extend(['', '## Required Next Actions', ''])
    for item in payload['required_next_actions']:
        lines.append(f"- `{item['module_id']}` status=`{item['status']}`: {item['next_action']}")
    if not payload['required_next_actions']:
        lines.append('- None')
    lines.extend(['', '## Module Status', ''])
    for item in payload['modules']:
        lines.append(f"- `{item['id']}` status=`{item['status']}` score=`{item['score']}` runs=`{item['runs']}` checks=`{item['checks']}`")
    lines.extend(['', '## Prior Campaigns', ''])
    for campaign in payload['campaigns']:
        lines.append(f"- `{campaign['path']}` verdict=`{campaign.get('verdict')}` next=`{campaign.get('next_action')}`")
    if not payload['campaigns']:
        lines.append('- None')
    return '\n'.join(lines).rstrip() + '\n'

def cmd_campaign_dashboard(args: argparse.Namespace) -> None:
    profile_path, target = _h._target_profile_by_arg(args.target)
    bb_root = _h._target_bb_root(profile_path)
    target_id = str(target.get('id') or profile_path.stem)
    history = _campaign_history(bb_root)
    modules = []
    coverage = {'closed': 0, 'partial': 0, 'candidate_signal': 0, 'tested_unknown': 0, 'untested': 0, 'total': 0}
    for module in load_campaign_modules():
        module_id = str(module.get('id') or '')
        module_history = history['modules'].get(module_id, {})
        status = _h._module_status(module_history)
        score, reasons = _score_campaign_module(module, target, status)
        coverage[status] = int(coverage.get(status, 0)) + 1
        coverage['total'] += 1
        modules.append({'id': module_id, 'title': module.get('title', ''), 'status': status, 'score': score, 'runs': int(module_history.get('runs') or 0), 'checks': int(module_history.get('checks') or 0), 'candidate_signals': int(module_history.get('candidate_signals') or 0), 'next_action': _h._next_action_for_module(module_id, status, target_id), 'reasons': reasons})
    modules.sort(key=lambda item: (-float(item['score']), item['id']))
    required_next_actions = [{'module_id': item['id'], 'status': item['status'], 'next_action': item['next_action']} for item in modules if item['status'] != 'closed'][:args.limit]
    campaigns = []
    for campaign in history['campaigns']:
        verdict = str(campaign.get('verdict') or '')
        next_action = 'none'
        if verdict == 'no_findings':
            next_action = f'run campaign-plan {target_id} and execute the top untested/partial module'
        elif verdict == 'partial':
            next_action = 'close setup gaps before treating coverage as negative'
        elif verdict == 'candidate_signals':
            next_action = 'prove, dedup, and report-gate candidate signals'
        campaigns.append(dict(campaign, next_action=next_action))
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'target_id': target_id, 'target_profile': rel(profile_path), 'target_root': rel(bb_root), 'coverage': coverage, 'required_next_actions': required_next_actions, 'modules': modules, 'campaigns': campaigns}
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _campaign_dashboard_markdown(payload))
        print(rel(out))
    elif args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_campaign_dashboard_markdown(payload).rstrip())

def _campaign_run_markdown(payload: dict[str, Any]) -> str:
    lines = ['# Campaign Run', '', f"- Generated at: `{payload['generated_at']}`", f"- Adapter: `{payload['adapter_manifest']}`", f"- Out dir: `{payload['out_dir']}`", f"- Dry run: `{payload['dry_run']}`", f"- Passed: `{payload['passed']}`", '', '## Modules', '']
    for module in payload['modules']:
        lines.append(f"- `{module['module_id']}` local=`{module['local_name']}` status=`{module['status']}` exit=`{module.get('returncode')}`")
        lines.append(f"  - command: `{' '.join(module['command'])}`")
        for artifact in module.get('expected_artifacts', []):
            lines.append(f"  - artifact `{artifact['path']}` exists=`{artifact['exists']}`")
        if module.get('error'):
            lines.append(f"  - error: {module['error']}")
    if payload.get('mutation_coverage_check'):
        check = payload['mutation_coverage_check']
        lines.extend(['', '## Mutation Coverage', ''])
        lines.append(f"- Passed: `{check.get('passed')}`")
        for artifact in check.get('artifacts', []):
            lines.append(f"- `{artifact['path']}` status=`{artifact['status']}`")
    return '\n'.join(lines).rstrip() + '\n'

def cmd_campaign_run(args: argparse.Namespace) -> None:
    adapter_path, adapter = _h._load_adapter_from_args(args)
    module_catalog = {str(item.get('id')): item for item in load_campaign_modules()}
    contract = load_yaml(_h.module_contract_path()) or {}
    adapter_check = _h._adapter_check_one(adapter_path, module_catalog, contract)
    if adapter_check['status'] != 'pass' and (not args.skip_adapter_check):
        payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'adapter_manifest': rel(adapter_path), 'passed': False, 'error': 'adapter validation failed', 'adapter_check': adapter_check, 'modules': []}
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=False))
        else:
            print(json.dumps(payload, indent=2, sort_keys=False))
        if args.fail:
            raise SystemExit(2)
        return
    selected = set(args.module or [])
    modules = []
    for module in adapter.get('modules', []) or []:
        module_id = str(module.get('id') or '')
        local_name = str(module.get('local_name') or '')
        if selected and module_id not in selected and (local_name not in selected):
            continue
        modules.append(module)
    if selected and (not modules):
        raise SystemExit('no selected modules found in adapter')
    out_dir = run_path(args.out_dir) if args.out_dir else run_path(str(adapter.get('default_run_root') or 'vapt/harness/tests/results/campaign-run'))
    if not args.out_dir:
        out_dir = out_dir / dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir.mkdir(parents=True, exist_ok=True)
    allowed_exit_codes = {int(item) for item in args.allowed_exit_code or [0]}
    module_results = []
    passed = True
    started = dt.datetime.now().isoformat(timespec='seconds')
    for module in modules:
        module_id = str(module.get('id') or '')
        local_name = str(module.get('local_name') or module_id)
        module_out_dir = out_dir / 'modules' / local_name
        module_out_dir.mkdir(parents=True, exist_ok=True)
        context = {'workspace_root': str(ROOT), 'target_id': str(adapter.get('target_id') or ''), 'adapter_id': str(adapter.get('adapter_id') or ''), 'module_id': module_id, 'local_name': local_name, 'out_dir': str(out_dir), 'module_out_dir': str(module_out_dir), 'runtime_root': str(run_path(str(adapter.get('runtime_root') or ''))) if adapter.get('runtime_root') else '', 'default_target': str((adapter.get('safety') or {}).get('default_target') or '')}
        try:
            command = [str(item) for item in _h._render_adapter_value(module.get('command') or [], context)]
        except KeyError as exc:
            command = []
            result = {'module_id': module_id, 'local_name': local_name, 'status': 'fail', 'error': str(exc), 'command': command, 'expected_artifacts': []}
            module_results.append(result)
            passed = False
            continue
        expected_artifacts = [{'path': rel(out_dir / str(path)), 'exists': (out_dir / str(path)).exists()} for path in module.get('result_files', [])]
        if args.dry_run:
            module_results.append({'module_id': module_id, 'local_name': local_name, 'status': 'planned', 'command': command, 'expected_artifacts': expected_artifacts})
            continue
        result = _h.run_cmd(command, ROOT, timeout=args.timeout)
        expected_artifacts = [{'path': rel(out_dir / str(path)), 'exists': (out_dir / str(path)).exists()} for path in module.get('result_files', [])]
        ok = int(result['returncode']) in allowed_exit_codes and (not result['timeout'])
        module_result = {'module_id': module_id, 'local_name': local_name, 'status': 'pass' if ok else 'fail', 'command': command, 'cwd': rel(ROOT), 'returncode': result['returncode'], 'timeout': result['timeout'], 'stdout_tail': str(result.get('stdout') or '')[-2000:], 'stderr_tail': str(result.get('stderr') or '')[-2000:], 'expected_artifacts': expected_artifacts}
        write_json(module_out_dir / 'campaign_run_execution.json', module_result)
        module_results.append(module_result)
        passed = passed and ok
    mutation_check = None
    if args.validate_mutation and (not args.dry_run):
        artifacts = _h._mutation_artifact_paths(out_dir)
        if artifacts:
            catalog = _h.load_mutation_catalog()
            check_results = [_h._validate_mutation_artifact(path, catalog, args.allow_missing_mutation, args.allow_unknown_variants) for path in artifacts]
            mutation_check = {'passed': all((item['status'] == 'pass' for item in check_results)), 'artifacts': check_results}
            passed = passed and bool(mutation_check['passed'])
        else:
            mutation_check = {'passed': False, 'artifacts': [], 'errors': ['no mutation artifacts found']}
            passed = False
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'started_at': started, 'harness_version': HARNESS_VERSION, 'adapter_manifest': rel(adapter_path), 'target_id': adapter.get('target_id', ''), 'adapter_id': adapter.get('adapter_id', ''), 'out_dir': rel(out_dir), 'dry_run': args.dry_run, 'passed': passed, 'allowed_exit_codes': sorted(allowed_exit_codes), 'adapter_check': adapter_check, 'modules': module_results, 'mutation_coverage_check': mutation_check}
    write_json(out_dir / 'campaign_run.json', payload)
    write_text(out_dir / 'campaign_run.md', _campaign_run_markdown(payload))
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _campaign_run_markdown(payload))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(out_dir / 'campaign_run.md'))
    if args.fail and (not passed):
        raise SystemExit(2)

def _campaign_gate_markdown(payload: dict[str, Any]) -> str:
    lines = ['# Campaign Gate', '', f"- Generated at: `{payload['generated_at']}`", f"- Campaign dir: `{payload['campaign_dir']}`", f"- Passed: `{payload['passed']}`", '', '## Checks', '']
    for check in payload['checks']:
        lines.append(f"- `{check['id']}`: `{check['status']}`")
        for detail in check.get('details', []):
            lines.append(f'  - {detail}')
    return '\n'.join(lines).rstrip() + '\n'

def cmd_campaign_gate(args: argparse.Namespace) -> None:
    campaign_dir = run_path(args.campaign_dir)
    campaign_path = campaign_dir / 'campaign_run.json'
    if not campaign_path.exists():
        raise SystemExit(f'campaign_run.json not found: {rel(campaign_path)}')
    campaign = read_json(campaign_path, {})
    checks = []
    checks.append(_h._gate_check('campaign_run_present', True, [rel(campaign_path)]))
    checks.append(_h._gate_check('campaign_run_not_dry_run', campaign.get('dry_run') is False))
    checks.append(_h._gate_check('campaign_run_passed', campaign.get('passed') is True))
    adapter_check = campaign.get('adapter_check') or {}
    checks.append(_h._gate_check('adapter_check_passed', isinstance(adapter_check, dict) and adapter_check.get('status') == 'pass', adapter_check.get('errors', []) if isinstance(adapter_check, dict) else ['missing adapter_check']))
    module_details = []
    modules_ok = True
    artifact_ok = True
    artifact_details = []
    for module in campaign.get('modules', []) or []:
        module_id = str(module.get('module_id') or '')
        status = str(module.get('status') or '')
        returncode = module.get('returncode')
        timeout = module.get('timeout')
        if status != 'pass' or timeout:
            modules_ok = False
            module_details.append(f'{module_id}: status={status} returncode={returncode} timeout={timeout}')
        for artifact in module.get('expected_artifacts', []) or []:
            artifact_path = _h._artifact_path_from_record(artifact)
            exists = bool(artifact.get('exists')) and artifact_path.exists()
            if not exists:
                artifact_ok = False
                artifact_details.append(f"missing artifact: {artifact.get('path')}")
            if not _h._path_is_under(artifact_path, campaign_dir):
                artifact_ok = False
                artifact_details.append(f"artifact escapes campaign dir: {artifact.get('path')}")
    checks.append(_h._gate_check('module_execution_passed', modules_ok, module_details))
    checks.append(_h._gate_check('declared_artifacts_present_and_contained', artifact_ok, artifact_details))
    mutation_check = campaign.get('mutation_coverage_check')
    mutation_ok = isinstance(mutation_check, dict) and mutation_check.get('passed') is True
    mutation_details = []
    if not mutation_ok:
        mutation_details.append('campaign_run mutation_coverage_check missing or failed')
    if args.revalidate_mutation:
        artifacts = _h._mutation_artifact_paths(campaign_dir)
        catalog = _h.load_mutation_catalog()
        mutation_results = [_h._validate_mutation_artifact(path, catalog, allow_missing=args.allow_missing_mutation, allow_unknown_variants=args.allow_unknown_variants) for path in artifacts]
        revalidated = all((item['status'] == 'pass' for item in mutation_results))
        mutation_ok = mutation_ok and revalidated
        for item in mutation_results:
            for error_item in item.get('errors', []):
                mutation_details.append(f"{item['path']}: {error_item}")
    checks.append(_h._gate_check('mutation_coverage_passed', mutation_ok, mutation_details))
    leak_details = []
    leak_ok = True
    adapter_manifest = str(campaign.get('adapter_manifest') or '')
    target_id = str(campaign.get('target_id') or '')
    is_harness_fixture = adapter_manifest.startswith('vapt/harness/tests/fixtures/')
    if not is_harness_fixture:
        bb_root = ROOT / 'vapt' / 'engagements'
        if not str(adapter_manifest).startswith('vapt/engagements/'):
            leak_ok = False
            leak_details.append(f'non-fixture adapter is outside engagements: {adapter_manifest}')
        if not _h._path_is_under(campaign_dir, bb_root):
            leak_ok = False
            leak_details.append(f'target campaign dir is outside engagements: {rel(campaign_dir)}')
    else:
        fixture_root = ROOT / 'vapt' / 'harness' / 'tests'
        if not _h._path_is_under(campaign_dir, fixture_root):
            leak_ok = False
            leak_details.append(f'harness fixture campaign dir is outside harness tests: {rel(campaign_dir)}')
    if target_id and target_id != 'harness-fixture' and _h._path_is_under(campaign_dir, ROOT / 'vapt' / 'harness'):
        leak_ok = False
        leak_details.append('non-fixture target evidence stored under core harness')
    checks.append(_h._gate_check('evidence_location_boundary', leak_ok, leak_details))
    passed = all((check['status'] == 'pass' for check in checks))
    payload = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'harness_version': HARNESS_VERSION, 'campaign_dir': rel(campaign_dir), 'campaign_run': rel(campaign_path), 'passed': passed, 'checks': checks}
    write_json(campaign_dir / 'campaign_gate.json', payload)
    write_text(campaign_dir / 'campaign_gate.md', _campaign_gate_markdown(payload))
    if args.out:
        out = run_path(args.out)
        if out.suffix.lower() == '.json':
            write_json(out, payload)
        else:
            write_text(out, _campaign_gate_markdown(payload))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(rel(campaign_dir / 'campaign_gate.md'))
    if args.fail and (not passed):
        raise SystemExit(2)
