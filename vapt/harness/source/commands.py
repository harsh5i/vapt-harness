"""CLI handlers + helpers for source acquisition, indexing, graph building, semantic graph, taint trace, and surface tests.

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

from atomic_io import dump_yaml, load_yaml, write_text
from core import ROOT, rel, run_path, source_path


_h = sys.modules.get("harness") or sys.modules.get("__main__")
if _h is None or not hasattr(_h, "load_run"):
    import harness as _h  # noqa: E402


def load_surface_config() -> tuple[dict[str, list[str]], dict[str, str]]:
    path = ROOT / 'vapt' / 'harness' / 'config' / 'surfaces.yaml'
    if not path.exists():
        return (_h.PATTERNS, _h.GRAPH_QUERIES)
    config = load_yaml(path) or {}
    surfaces = config.get('surfaces', {})
    fixed = {category: [str(item) for item in values.get('fixed', [])] for category, values in surfaces.items()}
    regexes = {category: str(values.get('regex', '')) for category, values in surfaces.items() if values.get('regex')}
    graph: dict[str, str] = {}
    for alias, value in (config.get('aliases') or {}).items():
        if str(value) in regexes:
            graph[str(alias)] = regexes[str(value)]
        else:
            graph[str(alias)] = str(value)
    for category, regex in regexes.items():
        graph.setdefault(category, regex)
    return (fixed, graph)

def cmd_surfaces_test(args: argparse.Namespace) -> None:
    corpus = run_path(args.corpus)
    expectations_path = run_path(args.expectations)
    expectations = load_yaml(expectations_path) or {'categories': {}}
    results: dict[str, Any] = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'corpus': rel(corpus), 'expectations': rel(expectations_path), 'categories': {}}
    failures = []
    for category, spec in (expectations.get('categories') or {}).items():
        patterns = _h.PATTERNS.get(category, [])
        hits = []
        for pattern in patterns:
            result = _h.run_cmd(['rg', '-n', '-S', '-F', pattern], corpus, timeout=args.timeout)
            if result['returncode'] in (0, 1):
                hits.extend(result['stdout'].splitlines())
        min_hits = int(spec.get('min_hits', 0))
        unique_hits = sorted(set(hits))
        passed = len(unique_hits) >= min_hits
        if not passed:
            failures.append(f'{category}: expected >= {min_hits}, got {len(unique_hits)}')
        results['categories'][category] = {'min_hits': min_hits, 'hit_count': len(unique_hits), 'passed': passed, 'sample_hits': unique_hits[:args.max_hits]}
    out_dir = ROOT / 'vapt' / 'harness' / 'tests' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = out_dir / f'surface_test_{stamp}'
    dump_yaml(results, out.with_suffix('.yaml'))
    md = ['# Surface Pattern Regression', '', f'- Corpus: `{rel(corpus)}`', '']
    for category, item in results['categories'].items():
        md.extend([f'## `{category}`', '', f"- Expected min hits: `{item['min_hits']}`", f"- Actual hits: `{item['hit_count']}`", f"- Passed: `{item['passed']}`", ''])
        for hit in item['sample_hits']:
            md.append(f'- `{hit}`')
        md.append('')
    write_text(out.with_suffix('.md'), '\n'.join(md))
    print(rel(out.with_suffix('.md')))
    if failures:
        print('failures=' + '; '.join(failures))
        raise SystemExit(2)

def cmd_source_graph(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    out_dir = run_dir / 'source_graph'
    out_dir.mkdir(exist_ok=True)
    graph: dict[str, Any] = {'target_id': target['id'], 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'queries': {}}
    for category, pattern in _h.GRAPH_QUERIES.items():
        cmd = ['rg', '-n', '-S', pattern]
        for glob in args.glob or []:
            cmd.extend(['--glob', glob])
        if not args.include_tests:
            for glob in _h.DEFAULT_SOURCE_GRAPH_EXCLUDES:
                cmd.extend(['--glob', glob])
        result = _h.run_cmd(cmd, src, timeout=args.timeout)
        hits = result['stdout'].splitlines()[:args.max_hits] if result['returncode'] in (0, 1) else []
        by_file: dict[str, int] = {}
        for hit in hits:
            file_name = hit.split(':', 1)[0]
            by_file[file_name] = by_file.get(file_name, 0) + 1
        graph['queries'][category] = {'pattern': pattern, 'returncode': result['returncode'], 'timeout': result['timeout'], 'hits_capped': len(hits), 'top_files': dict(sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))[:20]), 'hits': hits, 'stderr': result['stderr'].strip()}
    dump_yaml(graph, out_dir / 'source_graph.yaml')
    md = [f"# Source Graph: {target['id']}", '', f'- Source: `{rel(src)}`', f"- Generated: `{graph['generated_at']}`", '']
    for category, item in graph['queries'].items():
        md.extend([f'## {category}', '', f"- Pattern: `{item['pattern']}`", f"- Hits captured: `{item['hits_capped']}`", '', '### Top Files', ''])
        if item['top_files']:
            for file_name, count in item['top_files'].items():
                md.append(f'- `{file_name}`: {count}')
        else:
            md.append('- No hits')
        md.extend(['', '### Sample Hits', ''])
        for hit in item['hits'][:args.sample_hits]:
            md.append(f'- `{hit}`')
        if not item['hits']:
            md.append('- No hits')
        md.append('')
    write_text(out_dir / 'source_graph.md', '\n'.join(md))
    _h.save_stage(run_dir, state, 'source_graph')
    print(rel(out_dir / 'source_graph.md'))

def _load_source_graph(run_dir: Path) -> dict[str, Any]:
    path = run_dir / 'source_graph' / 'source_graph.yaml'
    if not path.exists():
        raise SystemExit('source graph not found; run `harness.py source-graph <run_dir>` first')
    return load_yaml(path) or {}

def _is_default_excluded(path: str) -> bool:
    parts = Path(path).parts
    if 'vendor' in parts or 'node_modules' in parts or 'testdata' in parts or ('mocks' in parts):
        return True
    if parts and parts[0] == 'tools':
        return True
    if 'spec' in parts:
        return True
    name = Path(path).name
    if name.endswith('_spec.rb') or name.endswith('_test.rb'):
        return True
    return name.endswith('_test.go') or 'test' in name.lower()

def _source_files(src: Path, include_tests: bool, paths: list[str] | None, max_files: int) -> list[Path]:
    if paths:
        raw_files: list[str] = []
        for raw in paths:
            path = src / raw
            if path.is_file():
                raw_files.append(raw)
            elif path.is_dir():
                result = _h.run_cmd(['rg', '--files', raw], src, timeout=60)
                if result['returncode'] == 0:
                    raw_files.extend(result['stdout'].splitlines())
    else:
        result = _h.run_cmd(['rg', '--files'], src, timeout=60)
        raw_files = result['stdout'].splitlines() if result['returncode'] == 0 else []
    files = []
    for raw in raw_files:
        if len(files) >= max_files:
            break
        if not include_tests and _is_default_excluded(raw):
            continue
        path = src / raw
        if path.suffix.lower() in _h.SEMANTIC_SUFFIXES and path.is_file():
            files.append(path)
    return files

def _function_defs(rel_name: str, text: str) -> list[dict[str, Any]]:
    defs: list[dict[str, Any]] = []
    suffix = Path(rel_name).suffix.lower()
    patterns: list[tuple[str, str]] = []
    if suffix == '.go':
        patterns = [('function', '^\\s*func\\s+(?:\\([^)]*\\)\\s*)?([A-Za-z_][A-Za-z0-9_]*)\\s*\\(')]
    elif suffix == '.java':
        patterns = [('class', '^\\s*(?:public|private|protected|abstract|final|static|\\s)*\\s*(?:class|interface|enum)\\s+([A-Za-z_][A-Za-z0-9_]*)\\b'), ('function', '^\\s*(?:public|private|protected|static|final|synchronized|abstract|native|strictfp|\\s)+(?:<[A-Za-z0-9_, ? extends super]+>\\s*)?[A-Za-z_][A-Za-z0-9_<>\\[\\], ?]*\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\(')]
    elif suffix == '.py':
        patterns = [('function', '^\\s*(?:async\\s+)?def\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\('), ('class', '^\\s*class\\s+([A-Za-z_][A-Za-z0-9_]*)\\b')]
    elif suffix in {'.js', '.jsx', '.ts', '.tsx'}:
        patterns = [('function', '^\\s*(?:export\\s+)?(?:async\\s+)?function\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\('), ('function', '^\\s*(?:export\\s+)?(?:const|let|var)\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?:async\\s*)?\\('), ('class', '^\\s*(?:export\\s+)?class\\s+([A-Za-z_][A-Za-z0-9_]*)\\b')]
    elif suffix == '.rb':
        patterns = [('function', '^\\s*def\\s+(?:self\\.)?([A-Za-z_][A-Za-z0-9_]*[!?=]?)'), ('class', '^\\s*class\\s+([A-Za-z_][A-Za-z0-9_:]*)'), ('module', '^\\s*module\\s+([A-Za-z_][A-Za-z0-9_:]*)')]
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        for kind, pattern in patterns:
            match = re.search(pattern, line)
            if match:
                defs.append({'file': rel_name, 'line': index, 'end_line': len(lines), 'name': match.group(1), 'kind': kind, 'signature': line.strip()[:220]})
                break
    for index, item in enumerate(defs):
        if index + 1 < len(defs):
            item['end_line'] = max(item['line'], defs[index + 1]['line'] - 1)
    return defs

def cmd_semantic_graph(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    state, target = _h.load_run(run_dir)
    src = source_path(target)
    out_dir = run_dir / 'semantic_graph'
    out_dir.mkdir(exist_ok=True)
    functions: list[dict[str, Any]] = []
    files = _source_files(src, args.include_tests, args.path, args.max_files)
    for path in files:
        rel_name = rel(path).removeprefix(rel(src) + '/')
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        lines = text.splitlines()
        for fn in _function_defs(rel_name, text):
            body = '\n'.join(lines[fn['line'] - 1:fn['end_line']])
            fn['categories'] = _h._semantic_categories(body)
            fn['calls'] = _h._calls_in_body(body)
            functions.append(fn)
            if len(functions) >= args.max_functions:
                break
        if len(functions) >= args.max_functions:
            break
    name_index: dict[str, list[int]] = {}
    for index, fn in enumerate(functions):
        name_index.setdefault(fn['name'], []).append(index)
    edges = []
    for index, fn in enumerate(functions):
        for call in fn.get('calls', []):
            for target_index in name_index.get(call, [])[:args.max_targets_per_call]:
                if target_index != index:
                    edges.append({'from': index, 'to': target_index, 'call': call, 'from_name': fn['name'], 'to_name': functions[target_index]['name']})
                    break
    by_category: dict[str, list[int]] = {}
    for index, fn in enumerate(functions):
        for category in fn.get('categories', []):
            by_category.setdefault(category, []).append(index)
    graph = {'target_id': target['id'], 'run_id': state.get('run_id'), 'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'file_count_scanned': len(files), 'function_count': len(functions), 'edge_count': len(edges), 'functions': functions, 'edges': edges[:args.max_edges], 'category_index': {key: value[:200] for key, value in by_category.items()}}
    dump_yaml(graph, out_dir / 'semantic_graph.yaml')
    md = [f"# Semantic Graph: {target['id']}", '', f'- Source: `{rel(src)}`', f'- Files scanned: `{len(files)}`', f'- Functions/classes: `{len(functions)}`', f'- Edges captured: `{min(len(edges), args.max_edges)}`', '', '## Categories', '']
    for category, indexes in sorted(by_category.items(), key=lambda item: (-len(item[1]), item[0])):
        md.append(f'- `{category}`: {len(indexes)}')
    md.extend(['', '## High-Signal Functions', ''])
    high_signal = [fn for fn in functions if fn.get('categories')]
    for fn in high_signal[:args.sample_functions]:
        md.extend([f"### `{fn['name']}`", '', f"- File: `{fn['file']}:{fn['line']}`", f"- Categories: `{', '.join(fn.get('categories', []))}`", f"- Calls: `{', '.join(fn.get('calls', [])[:20])}`", f"- Signature: `{fn['signature']}`", ''])
    write_text(out_dir / 'semantic_graph.md', '\n'.join(md))
    _h.save_stage(run_dir, state, 'semantic_graph')
    print(rel(out_dir / 'semantic_graph.md'))

def _load_semantic_graph(run_dir: Path) -> dict[str, Any]:
    path = run_dir / 'semantic_graph' / 'semantic_graph.yaml'
    if not path.exists():
        raise SystemExit('semantic graph not found; run `harness.py semantic-graph <run_dir>` first')
    return load_yaml(path) or {}

def _taint_function(fn: dict[str, Any], lines: list[str], sink_regex: str, source_regex: str) -> list[dict[str, Any]]:
    tainted: set[str] = set()
    shadowed: set[str] = set()
    flows = []
    fn_start = int(fn.get('line', 1))
    signature = str(fn.get('signature', ''))
    for name in re.findall('\\b([A-Za-z_][A-Za-z0-9_]*)\\b', signature):
        if re.search(source_regex, name, flags=re.IGNORECASE):
            tainted.add(name)
    for offset, line in enumerate(lines, start=fn_start):
        is_declaration = offset == fn_start
        stripped = line.strip()
        if stripped.startswith(('//', '#', '/*', '*')):
            continue
        assign = _h.TAINT_ASSIGN_RE.search(line)
        lhs = assign.group(1) if assign else None
        rhs = line[assign.end():] if assign else line
        if re.search(source_regex, line, flags=re.IGNORECASE):
            for name in re.findall('\\b([A-Za-z_][A-Za-z0-9_]*)\\b', line):
                if name == lhs or name in shadowed:
                    continue
                if re.search(source_regex, name, flags=re.IGNORECASE):
                    tainted.add(name)
        if assign:
            rhs_has_source = bool(re.search(source_regex, rhs, flags=re.IGNORECASE))
            rhs_has_taint = any((re.search(f'\\b{re.escape(name)}\\b', rhs) for name in tainted))
            if rhs_has_source or rhs_has_taint:
                tainted.add(lhs)
                shadowed.discard(lhs)
            elif lhs.lower() in _h.WEAK_SOURCE_NAMES:
                tainted.discard(lhs)
                shadowed.add(lhs)
        if not is_declaration and re.search(sink_regex, line, flags=re.IGNORECASE):
            matched = sorted((name for name in tainted if re.search(f'\\b{re.escape(name)}\\b', line)))
            source_line = bool(re.search(_h.STRONG_SOURCE_RE, line))
            if matched or source_line:
                guard = _h._flow_guard(lines, fn_start, offset, matched, line)
                flows.append({'line': offset, 'sink_line': line.strip()[:260], 'tainted_variables': matched, 'source_on_same_line': source_line, 'guard': guard, 'guarded': guard is not None})
    return flows

def cmd_taint_trace(args: argparse.Namespace) -> None:
    run_dir = run_path(args.run_dir)
    _, target = _h.load_run(run_dir)
    src = source_path(target)
    graph = _load_semantic_graph(run_dir)
    functions = graph.get('functions', [])
    sink_categories = args.sink_category or ['process_execution', 'network_clients', 'file_storage', 'deserialization', 'template_injection']
    sink_regex = '|'.join((f'(?:{_h.GRAPH_QUERIES[cat]})' for cat in sink_categories if cat in _h.GRAPH_QUERIES))
    if not sink_regex:
        raise SystemExit('no valid sink categories selected')
    source_regex = args.source_regex or _h.TAINT_SOURCE_RE
    traces = []
    for fn in functions:
        categories = set(fn.get('categories', []))
        if not categories.intersection(sink_categories):
            continue
        flows = _taint_function(fn, _h._function_body(src, fn), sink_regex, source_regex)
        if getattr(args, 'unguarded_only', False):
            flows = [flow for flow in flows if not flow.get('guarded')]
        if flows:
            flows.sort(key=lambda flow: (bool(flow.get('guarded')), int(flow['line'])))
            traces.append({'file': fn.get('file'), 'function': fn.get('name'), 'function_line': fn.get('line'), 'categories': sorted(categories), 'flows': flows, 'unguarded_flows': sum((1 for flow in flows if not flow.get('guarded')))})
    traces.sort(key=lambda item: (item['unguarded_flows'] == 0, str(item['file']), int(item['function_line'] or 0)))
    traces = traces[:args.max_traces]
    out_dir = run_dir / 'taint_traces'
    out_dir.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    artifact = {'generated_at': dt.datetime.now().isoformat(timespec='seconds'), 'source_path': rel(src), 'source_regex': source_regex, 'sink_categories': sink_categories, 'trace_count': len(traces), 'traces': traces}
    dump_yaml(artifact, out_dir / f'taint_trace_{stamp}.yaml')
    md = ['# Taint Trace', '', f'- Source regex: `{source_regex}`', f"- Sink categories: `{', '.join(sink_categories)}`", f'- Traces: `{len(traces)}`', '']
    for item in traces:
        md.extend([f"## `{item['file']}:{item['function_line']} {item['function']}`", '', f"- Categories: `{', '.join(item['categories'])}`", ''])
        for flow in item['flows']:
            guard = f" guard=`{flow['guard']}`" if flow.get('guarded') else ''
            md.append(f"- Line `{flow['line']}` vars=`{', '.join(flow['tainted_variables'])}` same_line=`{flow['source_on_same_line']}`{guard}: `{flow['sink_line']}`")
        md.append('')
    write_text(out_dir / f'taint_trace_{stamp}.md', '\n'.join(md))
    print(rel(out_dir / f'taint_trace_{stamp}.md'))

def cmd_source_acquire(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from source.acquire import acquire
    descriptor = _h.acquire(root=ROOT, repo_url=args.repo_url, commit=args.commit)
    if args.json:
        print(json.dumps(descriptor, indent=2, sort_keys=False))
    else:
        print(f"{descriptor['mode']}: {descriptor['path']} @ {descriptor['commit']}")

def cmd_source_index(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from source.index import index_tree
    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        raise SystemExit(f'missing: {repo_path}')
    idx = _h.index_tree(repo_path, max_files=args.max_files)
    if args.json:
        print(json.dumps(idx, indent=2, sort_keys=False))
    else:
        print(f"indexed={idx['total_indexed']} languages={list(idx['languages'].keys())}")

def cmd_source_probe(args: argparse.Namespace) -> None:
    """Run patch_variant_hunter (or another source-reading probe) against a local repo path."""
    sys.path.insert(0, str(ROOT / 'vapt' / 'harness'))
    from probes.patch_variant_hunter import PatchVariantHunter
    from probes.base import ProbeContext
    knobs: dict[str, Any] = {}
    if args.max_files:
        knobs['max_files'] = args.max_files
    if args.bug_classes:
        knobs['bug_classes'] = args.bug_classes
    target: dict[str, Any] = {}
    if args.local_path:
        target['local_path'] = args.local_path
    if args.repo_url:
        target['repo_url'] = args.repo_url
    if args.commit:
        target['commit'] = args.commit
    if not target:
        raise SystemExit('provide --local-path or --repo-url')
    ctx = ProbeContext(run_dir=Path(args.run_dir or '/tmp'), target=target, candidate={'id': 'SOURCE-PROBE'}, knobs=knobs)
    result = PatchVariantHunter().run(ctx)
    if args.json:
        print(json.dumps(dict(result), indent=2, sort_keys=False))
    else:
        print(f"finding_count={result.get('finding_count')} files={result.get('file_count')} (python={result.get('python_file_count')} ruby={result.get('ruby_file_count')})")
        for f in (result.get('findings') or [])[:args.head]:
            print(f"  {f['file']}:{f['line']}  [{f['bug_class']}]  {f['hypothesis']}")

def load_surface_terms(names: list[str]) -> list[str]:
    terms: list[str] = []
    surfaces, _graph = load_surface_config()
    for name in names:
        fixed = surfaces.get(name, [])
        terms.extend((str(item) for item in fixed))
        if name not in surfaces:
            terms.append(name)
    if not terms:
        terms = _h.SECURITY_DIFF_PATTERNS
    seen = set()
    out = []
    for term in terms:
        if term and term not in seen:
            seen.add(term)
            out.append(term)
    return out
