"""CLI handlers for scanner wrappers, sandbox exec, tool capability/health, and scanner-finding normalization.

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

from atomic_io import file_lock, read_jsonl, write_json, write_jsonl, write_text
from core import ROOT, rel, run_path, source_path
from tools.runtime import _ensure_runtime_or_local, _load_tool_module, container_runtime, find_tool, macos_sandbox_exec, refuse_missing_tool, run_tool_scan, tool_env, tool_scan_base


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def tool_gaps_path() -> Path:
    return ROOT / 'vapt' / 'harness' / 'corpus' / 'tool_gaps.jsonl'

def log_tool_gap(run_dir: Path, candidate_id: str, missing_class: str, context: str) -> None:
    path = tool_gaps_path()
    entry = {'at': dt.datetime.now().isoformat(timespec='seconds'), 'run_dir': rel(run_dir), 'candidate_id': candidate_id, 'missing_class': missing_class, 'context': context}
    with file_lock(path):
        rows = read_jsonl(path)
        rows.append(entry)
        write_jsonl(path, rows)

def cmd_sandbox_exec(args: argparse.Namespace) -> None:
    runtime = container_runtime()
    macos_runtime = macos_sandbox_exec()
    run_dir = run_path(args.run_dir)
    out_dir = run_dir / 'evidence' / 'sandbox'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = out_dir / f'sandbox_{stamp}'
    if not runtime:
        if macos_runtime:
            policy = args.policy or 'macos-no-network'
            if policy not in {'none', 'macos-no-network'}:
                raise SystemExit('macOS sandbox fallback supports policy=macos-no-network or none')
            allowed_write_paths = [out_dir.resolve()]
            for mount in args.mount or []:
                host, mode = mount.rsplit(':', 1) if ':' in mount else (mount, 'ro')
                if mode not in {'ro', 'rw'}:
                    raise SystemExit(f'mount mode must be ro or rw: {mount}')
                if mode == 'rw':
                    allowed_write_paths.append(run_path(host).resolve())
            profile_lines = ['(version 1)', '(allow default)', '(deny network*)', '(deny file-write*)']
            for path in allowed_write_paths:
                profile_lines.append(f'(allow file-write* (subpath {json.dumps(str(path))}))')
            profile = '\n'.join(profile_lines) + '\n'
            profile_path = base.with_suffix('.sb')
            write_text(profile_path, profile)
            argv = [macos_runtime, '-f', str(profile_path), '/bin/sh', '-lc', args.cmd]
            result = run_tool_scan(argv, out_dir, base, args.timeout, env=tool_env('sandbox-exec'))
            write_json(base.with_suffix('.policy.json'), {'policy': policy, 'runtime': macos_runtime, 'cmd': args.cmd, 'argv': argv, 'network': 'denied', 'write_paths': [str(path) for path in allowed_write_paths], 'summary': rel(base.with_suffix('.summary.json'))})
            print(rel(base.with_suffix('.summary.json')))
            if result['returncode'] != 0:
                raise SystemExit(result['returncode'] if 0 < result['returncode'] < 126 else 1)
            return
        result = {'status': 'refused', 'reason': 'Docker/Podman runtime and macOS sandbox-exec fallback not found; no raw-shell fallback is allowed.', 'cmd': args.cmd, 'image': args.image}
        write_json(base.with_suffix('.policy.json'), result)
        print(rel(base.with_suffix('.policy.json')))
        raise SystemExit(2)
    policy = args.policy or 'none'
    if policy != 'none':
        raise SystemExit('only policy=none is implemented in this foundation pass')
    cmd = [runtime, 'run', '--rm', '--network', 'none', '--cpus', str(args.cpus), '--memory', args.memory, '--pids-limit', str(args.pids), '-v', f'{out_dir.resolve()}:/evidence:rw']
    for mount in args.mount or []:
        host, mode = mount.rsplit(':', 1) if ':' in mount else (mount, 'ro')
        if mode not in {'ro', 'rw'}:
            raise SystemExit(f'mount mode must be ro or rw: {mount}')
        cmd.extend(['-v', f'{run_path(host).resolve()}:{run_path(host).resolve()}:{mode}'])
    cmd.extend([args.image, 'sh', '-lc', args.cmd])
    result = _h.run_cmd(cmd, ROOT, timeout=args.timeout)
    write_json(base.with_suffix('.policy.json'), {'policy': policy, 'runtime': runtime, 'image': args.image, 'cmd': args.cmd, 'argv': cmd})
    write_text(base.with_suffix('.out'), result['stdout'])
    write_text(base.with_suffix('.err'), result['stderr'])
    write_text(base.with_suffix('.status'), str(result['returncode']) + '\n')
    print(rel(base.with_suffix('.status')))
    if result['returncode'] != 0:
        raise SystemExit(result['returncode'] if 0 < result['returncode'] < 126 else 1)

def cmd_tool_gap_add(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    log_tool_gap(run_dir, args.candidate_id or '', args.missing_class, args.context or '')
    print(rel(tool_gaps_path()))

def cmd_tool_gaps(args: argparse.Namespace) -> None:
    rows = read_jsonl(tool_gaps_path())
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get('missing_class') or 'unknown')
        counts[key] = counts.get(key, 0) + 1
    ranked = [{'missing_class': key, 'count': value} for key, value in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    if args.json:
        print(json.dumps({'tool_gaps': ranked, 'entries': rows if args.entries else []}, indent=2, sort_keys=False))
    else:
        for item in ranked:
            print(f"{item['count']} {item['missing_class']}")

def _authorize_scan(run_dir: Path, target_url: str | None, scanner: str) -> None:
    """Fail-closed scope + ROE gate. Refuses before any scanner subprocess runs.

    Loads the run's target profile and delegates to gates.authorization. On deny
    a structured JSON refusal record is written under the run's logs and the
    command exits non-zero without spawning the scanner.
    """
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from gates.authorization import authorize, AuthorizationError
    _state, target = _h.load_run(run_dir)
    try:
        _h.authorize(run_dir, target, target_url, scanner)
    except _h.AuthorizationError as exc:
        print(json.dumps({'authorization': 'denied', **exc.record}, indent=2))
        raise SystemExit(2)

def cmd_scope_check(args: argparse.Namespace) -> None:
    """Dry-run the scope/ROE gate without executing any scanner."""
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from gates.authorization import evaluate
    run_dir = run_path(args.run_dir)
    _state, target = _h.load_run(run_dir)
    record = _h.evaluate(target, args.target_url, args.scanner)
    print(json.dumps(record, indent=2))
    if record['decision'] != 'allow':
        raise SystemExit(2)

def cmd_scan_zap_baseline(args: argparse.Namespace) -> None:
    zap_mod = _load_tool_module('zap')
    run_dir = run_path(args.run_dir)
    _authorize_scan(run_dir, args.target_url, 'zap-baseline')
    base = tool_scan_base(run_dir, 'zap-baseline')
    out_dir = base.parent
    runtime, _ = _ensure_runtime_or_local('zap-baseline', None, base, f'install Docker/Podman to pull {zap_mod.ZAP_IMAGE} or run ZAP locally and expose zap-baseline.py on PATH')
    argv = zap_mod.baseline_argv(runtime, target_url=args.target_url, out_dir=out_dir, report_name=f'{base.name}.json', extra_zap_args=args.extra or [], network=args.network)
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('zap'))
    report_path = out_dir / f'{base.name}.json'
    summary = zap_mod.parse_baseline_report(report_path)
    write_json(base.with_suffix('.findings.json'), summary)
    print(rel(base.with_suffix('.findings.json')))
    if result['returncode'] not in (0, 1, 2):
        raise SystemExit(result['returncode'])

def cmd_scan_zap_full(args: argparse.Namespace) -> None:
    zap_mod = _load_tool_module('zap')
    run_dir = run_path(args.run_dir)
    _authorize_scan(run_dir, args.target_url, 'zap-full')
    base = tool_scan_base(run_dir, 'zap-full')
    out_dir = base.parent
    runtime, _ = _ensure_runtime_or_local('zap-full', None, base, f'install Docker/Podman to pull {zap_mod.ZAP_IMAGE}')
    argv = zap_mod.full_scan_argv(runtime, target_url=args.target_url, out_dir=out_dir, report_name=f'{base.name}.json', extra_zap_args=args.extra or [], network=args.network)
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('zap'))
    report_path = out_dir / f'{base.name}.json'
    summary = zap_mod.parse_baseline_report(report_path)
    write_json(base.with_suffix('.findings.json'), summary)
    print(rel(base.with_suffix('.findings.json')))
    if result['returncode'] not in (0, 1, 2):
        raise SystemExit(result['returncode'])

def cmd_scan_sqlmap(args: argparse.Namespace) -> None:
    sqlmap_mod = _load_tool_module('sqlmap')
    run_dir = run_path(args.run_dir)
    _authorize_scan(run_dir, args.target_url, 'sqlmap')
    base = tool_scan_base(run_dir, 'sqlmap')
    out_dir = base.parent
    runtime, local_bin = _ensure_runtime_or_local('sqlmap', 'sqlmap', base, f'install Docker/Podman to pull {sqlmap_mod.SQLMAP_IMAGE} or `pip install sqlmap` into .venv-vapt')
    if runtime:
        argv = sqlmap_mod.scan_argv(runtime, target_url=args.target_url, request_file=Path(args.request_file) if args.request_file else None, out_dir=out_dir, extra_args=args.extra or [], network=args.network)
    else:
        argv = [local_bin, '--batch', '--random-agent', '--output-dir', str(out_dir)]
        if args.target_url:
            argv += ['-u', args.target_url]
        if args.request_file:
            argv += ['-r', args.request_file]
        if args.extra:
            argv += list(args.extra)
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('sqlmap'))
    summary = sqlmap_mod.parse_log(base.with_suffix('.out'))
    write_json(base.with_suffix('.findings.json'), summary)
    print(rel(base.with_suffix('.findings.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def cmd_scan_jwt(args: argparse.Namespace) -> None:
    jwt_mod = _load_tool_module('jwt')
    run_dir = run_path(args.run_dir)
    base = tool_scan_base(run_dir, 'jwt')
    token = args.token
    if not token and args.token_file:
        token = Path(args.token_file).read_text().strip()
    if not token:
        raise SystemExit('--token or --token-file required')
    decoded = jwt_mod.decode_local(token)
    write_json(base.with_suffix('.decode.json'), decoded)
    if args.container:
        runtime, _ = _ensure_runtime_or_local('jwt', None, base, f'install Docker/Podman to pull {jwt_mod.JWT_IMAGE}')
        argv = jwt_mod.inspect_argv(runtime, token=token, out_dir=base.parent)
        result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('jwt'))
        if result['returncode'] not in (0, 1):
            raise SystemExit(result['returncode'])
    print(rel(base.with_suffix('.decode.json')))

def cmd_scan_screenshot(args: argparse.Namespace) -> None:
    shot_mod = _load_tool_module('screenshot')
    run_dir = run_path(args.run_dir)
    _authorize_scan(run_dir, args.target_url, 'screenshot')
    base = tool_scan_base(run_dir, 'screenshot')
    out_dir = base.parent
    runtime, local_bin = _ensure_runtime_or_local('screenshot', 'playwright', base, f'install Docker/Podman to pull {shot_mod.PLAYWRIGHT_IMAGE} or install playwright in .venv-vapt')
    script_path = shot_mod.write_capture_script(out_dir)
    image_name = f'{base.name}.png'
    if runtime:
        argv = shot_mod.capture_argv(runtime, target_url=args.target_url, out_dir=out_dir, script_path=script_path, image_name=image_name, wait_ms=args.wait_ms, network=args.network)
    else:
        argv = [local_bin, 'python', str(script_path), args.target_url, str(out_dir / image_name), str(args.wait_ms)]
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('playwright'))
    summary = {'image': rel(out_dir / image_name), 'url': args.target_url}
    write_json(base.with_suffix('.findings.json'), summary)
    print(rel(base.with_suffix('.findings.json')))
    if result['returncode'] != 0:
        raise SystemExit(result['returncode'])

def cmd_tools_capability(args: argparse.Namespace) -> None:
    """Report which Move 3 tools are reachable via container or local."""
    zap_mod = _load_tool_module('zap')
    sqlmap_mod = _load_tool_module('sqlmap')
    jwt_mod = _load_tool_module('jwt')
    shot_mod = _load_tool_module('screenshot')
    container_mod = _load_tool_module('container')
    capability_report = container_mod.capability_report
    runtime = container_runtime()
    rows = [capability_report('zap', runtime, find_tool('zap-baseline.py'), zap_mod.ZAP_IMAGE), capability_report('sqlmap', runtime, find_tool('sqlmap'), sqlmap_mod.SQLMAP_IMAGE), capability_report('jwt', runtime, find_tool('jwt_tool'), jwt_mod.JWT_IMAGE), capability_report('screenshot', runtime, find_tool('playwright'), shot_mod.PLAYWRIGHT_IMAGE)]
    payload = {'runtime': runtime or '', 'tools': rows, 'ready_count': sum((1 for r in rows if r['available'])), 'total': len(rows)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        for r in rows:
            print(f"{r['tool']}: {r['mode']} (image={r['container_image']})")
        print(f"ready={payload['ready_count']}/{payload['total']} runtime={payload['runtime'] or 'none'}")

def cmd_scan_semgrep(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'semgrep')
    tool = find_tool('semgrep')
    if not tool:
        refuse_missing_tool(base, 'semgrep', 'Install Semgrep in .venv-vapt or PATH.')
    config = args.ruleset or str(ROOT / 'vapt' / 'harness' / 'rules')
    result = run_tool_scan([tool, '--config', config, '--json', '--timeout', str(args.timeout), str(src)], ROOT, base, args.timeout + 30, env=tool_env('semgrep'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def cmd_scan_bandit(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'bandit')
    tool = find_tool('bandit')
    if not tool:
        refuse_missing_tool(base, 'bandit', 'Install bandit in .venv-vapt or PATH.')
    argv = [tool, '-r', str(src), '-f', 'json', '--severity-level', args.severity_level, '--confidence-level', args.confidence_level]
    if args.config:
        argv.extend(['-c', str(run_path(args.config))])
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('bandit'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def python_requirement_file(src: Path) -> Path | None:
    candidates = [src / 'requirements.txt', src / 'requirements-dev.txt', src / 'requirements_test.txt', src / 'dev-requirements.txt']
    for item in candidates:
        if item.exists():
            return item
    matches = sorted(src.glob('requirements*.txt'))
    return matches[0] if matches else None

def cmd_scan_pip_audit(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'pip_audit')
    tool = find_tool('pip-audit')
    if not tool:
        refuse_missing_tool(base, 'pip-audit', 'Install pip-audit in .venv-vapt or PATH.')
    req = run_path(args.requirement) if args.requirement else python_requirement_file(src)
    if req:
        argv = [tool, '-r', str(req), '--format', 'json', '--progress-spinner', 'off']
    else:
        argv = [tool, str(src), '--format', 'json', '--progress-spinner', 'off']
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('pip-audit'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def cmd_scan_osv(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'osv')
    tool = find_tool('osv-scanner')
    if not tool:
        refuse_missing_tool(base, 'osv-scanner', 'Install osv-scanner in PATH for lockfile/package vulnerability scans.')
    argv = [tool, 'scan', '--format', 'json', str(src)]
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('osv-scanner'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def cmd_scan_codeql(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'codeql')
    tool = find_tool('codeql')
    if not tool:
        refuse_missing_tool(base, 'codeql', 'Install the CodeQL CLI in PATH for CodeQL database analysis.')
    if args.database:
        database = run_path(args.database)
    else:
        if not args.create_database:
            write_json(base.with_suffix('.policy.json'), {'status': 'refused', 'reason': 'scan-codeql requires --database or explicit --create-database', 'source_path': rel(src)})
            print(rel(base.with_suffix('.policy.json')))
            raise SystemExit(2)
        if not args.language:
            raise SystemExit('--language is required with --create-database')
        database = run_dir / 'tool_scans' / 'codeql_db' / args.language
        create_base = tool_scan_base(run_dir, 'codeql_create')
        create_argv = [tool, 'database', 'create', str(database), '--source-root', str(src), '--language', args.language, '--threads', str(args.threads)]
        create_result = run_tool_scan(create_argv, ROOT, create_base, args.timeout, env=tool_env('codeql'))
        if create_result['returncode'] != 0:
            print(rel(create_base.with_suffix('.summary.json')))
            raise SystemExit(create_result['returncode'] if 0 < create_result['returncode'] < 126 else 1)
    out_sarif = base.with_suffix('.sarif')
    query = args.query or args.ql_pack or 'security-extended'
    argv = [tool, 'database', 'analyze', str(database), query, '--format', 'sarif-latest', '--output', str(out_sarif), '--threads', str(args.threads)]
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('codeql'))
    write_json(base.with_suffix('.codeql.json'), {'database': str(database), 'query': query, 'sarif': rel(out_sarif), 'summary': rel(base.with_suffix('.summary.json'))})
    print(rel(base.with_suffix('.codeql.json')))
    if result['returncode'] not in (0, 1, 2):
        raise SystemExit(result['returncode'] if 0 < result['returncode'] < 126 else 1)

def cmd_scan_trufflehog(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    base = tool_scan_base(run_dir, 'trufflehog')
    tool = find_tool('trufflehog')
    if not tool:
        refuse_missing_tool(base, 'trufflehog', 'Install trufflehog in PATH for secret scanning.')
    argv = [tool, 'filesystem', '--json', '--no-update', str(src)]
    if args.only_verified:
        argv.append('--only-verified')
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('trufflehog'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 183):
        raise SystemExit(result['returncode'] if 0 < result['returncode'] < 126 else 1)

def cmd_scan_tls(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir) if args.run_dir else ROOT / 'vapt' / 'evidence' / 'tls'
    base = tool_scan_base(run_dir, 'tls')
    sslyze = find_tool('sslyze')
    testssl = find_tool('testssl.sh')
    if sslyze:
        argv = [sslyze, '--certinfo', '--tlsv1_2', '--tlsv1_3', '--heartbleed', '--robot', args.host]
    elif testssl:
        argv = [testssl, '--fast', '--connect-timeout', '10', '--openssl-timeout', '20', args.host]
    else:
        refuse_missing_tool(base, 'sslyze/testssl.sh', 'Install sslyze or testssl.sh in PATH for TLS scans.')
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('sslyze' if sslyze else 'testssl.sh'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] != 0:
        raise SystemExit(result['returncode'] if 0 < result['returncode'] < 126 else 1)

def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    base = tool_scan_base(run_dir, 'nuclei')
    tool = find_tool('nuclei')
    if not tool:
        refuse_missing_tool(base, 'nuclei', 'Install nuclei in PATH for bounded template scans.')
    templates = args.template or []
    if not templates and (not args.allow_default_templates):
        write_json(base.with_suffix('.policy.json'), {'status': 'refused', 'reason': 'nuclei requires explicit --template unless --allow-default-templates is set', 'url': args.url})
        print(rel(base.with_suffix('.policy.json')))
        raise SystemExit(2)
    argv = [tool, '-u', args.url, '-jsonl', '-rl', str(args.rate_limit), '-c', str(args.concurrency), '-timeout', str(args.template_timeout), '-retries', '0', '-no-stdin']
    for template in templates:
        argv.extend(['-t', template])
    result = run_tool_scan(argv, ROOT, base, args.timeout, env=tool_env('nuclei'))
    print(rel(base.with_suffix('.summary.json')))
    if result['returncode'] not in (0, 1):
        raise SystemExit(result['returncode'])

def cmd_scan_headers(args: argparse.Namespace) -> None:
    out_dir = ROOT / 'vapt' / 'evidence' / 'headers'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = out_dir / f'headers_{stamp}.json'
    result = _h.run_cmd(['curl', '-I', '-L', '--max-time', str(args.timeout), args.url], ROOT, timeout=args.timeout + 5)
    write_json(out, {'url': args.url, 'result': result})
    print(rel(out))
    if result['returncode'] != 0:
        raise SystemExit(result['returncode'])

def cmd_tool_health(args: argparse.Namespace) -> None:
    tools = ['semgrep', 'bandit', 'pip-audit', 'osv-scanner', 'trufflehog', 'sslyze', 'testssl.sh', 'nuclei', 'codeql']
    rows = []
    for tool in tools:
        path = find_tool(tool)
        item: dict[str, Any] = {'tool': tool, 'available': bool(path), 'path': path or ''}
        if path and args.versions:
            version_cmd = [path, '--version']
            if tool == 'testssl.sh':
                version_cmd = [path, '--version']
            elif tool == 'nuclei':
                version_cmd = [path, '-version']
            elif tool == 'sslyze':
                version_cmd = [path, '-h']
            result = _h.run_cmd(version_cmd, ROOT, timeout=5, env=tool_env(tool))
            item['version_returncode'] = result['returncode']
            item['version'] = (result['stdout'] or result['stderr']).strip().splitlines()[:3]
        rows.append(item)
    out = {'tools': rows}
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=False))
    else:
        for row in rows:
            status = 'ok' if row['available'] else 'missing'
            print(f"{status:7} {row['tool']} {row['path']}")

def normalize_scanner_findings(tool: str, records: list[Any], source_file: Path, include_low: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def add(item: dict[str, Any]) -> None:
        severity = str(item.get('severity') or 'info').lower()
        if not include_low and _h.scanner_severity_rank(severity) < 2:
            return
        item.setdefault('tool', tool)
        item.setdefault('source_file', rel(source_file))
        item.setdefault('cwe', '')
        item.setdefault('cve', 'N/A')
        item.setdefault('evidence', '')
        item.setdefault('matched_at', item.get('file', '') or item.get('package', ''))
        findings.append(item)
    if tool == 'bandit':
        for record in records:
            for result in (record or {}).get('results', []) if isinstance(record, dict) else []:
                cwe = ''
                cwe_raw = result.get('issue_cwe') or result.get('cwe')
                if isinstance(cwe_raw, dict):
                    cwe = _h.first_cwe(cwe_raw.get('id') or cwe_raw.get('link'))
                else:
                    cwe = _h.first_cwe(cwe_raw)
                add({'title': f"Bandit {result.get('test_id', '')}: {result.get('test_name') or 'Python static finding'}", 'severity': str(result.get('issue_severity', 'info')).lower(), 'confidence': result.get('issue_confidence', ''), 'file': result.get('filename', ''), 'line': result.get('line_number', ''), 'cwe': cwe, 'cve': 'N/A', 'evidence': result.get('issue_text', '')})
    elif tool == 'semgrep':
        for record in records:
            for result in (record or {}).get('results', []) if isinstance(record, dict) else []:
                extra = result.get('extra') or {}
                metadata = extra.get('metadata') or {}
                add({'title': f"Semgrep {result.get('check_id', '')}", 'severity': str(extra.get('severity', 'info')).lower(), 'confidence': metadata.get('confidence', ''), 'file': result.get('path', ''), 'line': (result.get('start') or {}).get('line', ''), 'cwe': _h.first_cwe(metadata.get('cwe') or metadata.get('cwe_id')), 'cve': _h.first_cve(metadata.get('cve'), metadata.get('references')), 'evidence': extra.get('message', '')})
    elif tool in {'nuclei', 'nuclei-jsonl'}:
        for result in records:
            if not isinstance(result, dict):
                continue
            info = result.get('info') or {}
            classification = info.get('classification') or {}
            add({'title': f"Nuclei {result.get('template-id', '')}: {info.get('name') or 'template match'}", 'severity': str(info.get('severity', 'info')).lower(), 'confidence': result.get('matcher-status', ''), 'matched_at': result.get('matched-at', ''), 'file': result.get('template-path', ''), 'line': '', 'cwe': _h.first_cwe(classification.get('cwe-id')), 'cve': _h.first_cve(classification.get('cve-id')), 'evidence': result.get('extracted-results') or result.get('matcher-name') or result.get('template-id', '')})
    elif tool == 'pip-audit':
        for record in records:
            dependencies = (record or {}).get('dependencies', []) if isinstance(record, dict) else []
            for dep in dependencies:
                for vuln in dep.get('vulns', []) or []:
                    aliases = vuln.get('aliases') or []
                    add({'title': f"pip-audit vulnerable dependency: {dep.get('name')} {dep.get('version')} {vuln.get('id')}", 'severity': 'medium', 'confidence': 'scanner', 'package': dep.get('name', ''), 'version': dep.get('version', ''), 'fixed_versions': vuln.get('fix_versions', []), 'cwe': _h.first_cwe(vuln.get('cwe')), 'cve': _h.first_cve(vuln.get('id'), aliases), 'evidence': vuln.get('description', '')})
    elif tool == 'osv':
        for record in records:
            results = (record or {}).get('results', []) if isinstance(record, dict) else []
            for result in results:
                for package in result.get('packages', []) or []:
                    pkg = package.get('package') or {}
                    for vuln in package.get('vulnerabilities', []) or []:
                        add({'title': f"OSV vulnerable dependency: {pkg.get('name', '')} {vuln.get('id', '')}", 'severity': 'medium', 'confidence': 'scanner', 'package': pkg.get('name', ''), 'version': pkg.get('version', ''), 'cwe': _h.first_cwe(vuln.get('database_specific', {}).get('cwe_ids', [])), 'cve': _h.first_cve(vuln.get('id'), vuln.get('aliases', [])), 'evidence': vuln.get('summary') or vuln.get('details', '')})
    elif tool == 'trufflehog':
        for result in records:
            if not isinstance(result, dict):
                continue
            verified = bool(result.get('Verified'))
            add({'title': f"TruffleHog secret finding: {result.get('DetectorName') or result.get('DetectorType') or 'secret'}", 'severity': 'high' if verified else 'medium', 'confidence': 'verified' if verified else 'unverified', 'file': str(result.get('SourceMetadata') or result.get('SourceName') or ''), 'line': '', 'cwe': 'CWE-798', 'cve': 'N/A', 'evidence': 'Secret material redacted; review raw TruffleHog JSON in evidence only.'})
    else:
        raise SystemExit(f'unsupported tool parser: {tool}')
    return findings
