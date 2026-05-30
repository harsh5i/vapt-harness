"""Mutation catalog + mutation-coverage validation: load_mutation_catalog, _validate_mutation_block, _validate_mutation_artifact, plus the mutation-plan / coverage-check render helpers.

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

from atomic_io import load_yaml, read_json
from core import ROOT, rel


_h = sys.modules.get("harness") or sys.modules.get("__main__")


def mutation_catalog_path() -> Path:
    return ROOT / 'vapt' / 'harness' / 'config' / 'mutation_catalog.yaml'

def load_mutation_catalog() -> dict[str, dict[str, Any]]:
    data = load_yaml(mutation_catalog_path()) or {}
    families = data.get('mutation_families') or []
    if not isinstance(families, list):
        raise SystemExit(f'invalid mutation catalog: {rel(mutation_catalog_path())}')
    return {str(item.get('id')): item for item in families if isinstance(item, dict) and item.get('id')}

def _mutation_plan_markdown(payload: dict[str, Any]) -> str:
    lines = [f"# Mutation Plan: {payload['target_id']}", '', f"- Generated at: `{payload['generated_at']}`", f"- Adapter: `{payload['adapter_manifest']}`", f"- Mutation catalog: `{payload['mutation_catalog']}`", '', '## Modules', '']
    for module in payload['modules']:
        lines.append(f"### `{module['id']}`")
        lines.append('')
        lines.append(f"- Local name: `{module['local_name']}`")
        lines.append(f"- Mutation families: `{len(module['families'])}`")
        lines.append(f"- Variant count: `{module['variant_count']}`")
        lines.append('')
        for family in module['families']:
            lines.append(f"- `{family['id']}`: {family['title']}")
            lines.append(f"  - stop: {family['stop_condition']}")
            lines.append(f"  - variants: {', '.join(family['variants'])}")
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'

def _mutation_artifact_paths(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    paths = []
    for name in ['campaign.json', 'results.json']:
        direct = root / name
        if direct.exists():
            paths.append(direct)
    paths.extend(sorted(root.glob('modules/*/results.json')))
    seen = set()
    out = []
    for path in paths:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out

def _mutation_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None

def _validate_mutation_block(block: Any, catalog: dict[str, dict[str, Any]], artifact: Path, block_path: str, allow_unknown_variants: bool) -> dict[str, Any]:
    errors = []
    warnings = []
    if not isinstance(block, dict):
        return {'path': block_path, 'status': 'fail', 'errors': [f'{block_path}: mutation_coverage must be an object'], 'warnings': [], 'summary': {}}
    module_id = str(block.get('module_id') or '')
    local_name = str(block.get('local_name') or '')
    if not module_id:
        errors.append(f'{block_path}: missing module_id')
    if not local_name:
        errors.append(f'{block_path}: missing local_name')
    families = block.get('families')
    if not isinstance(families, list):
        errors.append(f'{block_path}: families must be a list')
        families = []
    calculated = {'variants_planned': 0, 'variants_executed': 0, 'variants_skipped': 0}
    for family in families:
        if not isinstance(family, dict):
            errors.append(f'{block_path}: family entry must be an object')
            continue
        family_id = str(family.get('id') or '')
        family_path = f"{block_path}.families[{family_id or '<missing>'}]"
        if not family_id:
            errors.append(f'{family_path}: missing id')
            continue
        catalog_family = catalog.get(family_id)
        if not catalog_family:
            errors.append(f'{family_path}: unknown family id')
            catalog_variants: set[str] = set()
            applies_to: set[str] = set()
        else:
            catalog_variants = {str(item) for item in catalog_family.get('variants', [])}
            applies_to = {str(item) for item in catalog_family.get('applies_to', [])}
            if module_id and module_id not in applies_to:
                warnings.append(f'{family_path}: module_id {module_id} is not listed in family applies_to')
        executed = family.get('variants_executed')
        skipped = family.get('variants_skipped')
        if not isinstance(executed, list):
            errors.append(f'{family_path}: variants_executed must be a list')
            executed = []
        if not isinstance(skipped, list):
            errors.append(f'{family_path}: variants_skipped must be a list')
            skipped = []
        executed_ids = []
        for item in executed:
            if not isinstance(item, str) or not item:
                errors.append(f'{family_path}: executed variant must be a non-empty string')
                continue
            executed_ids.append(item)
        skipped_ids = []
        for item in skipped:
            if not isinstance(item, dict):
                errors.append(f'{family_path}: skipped variant must be an object')
                continue
            variant_id = str(item.get('id') or '')
            reason = str(item.get('reason') or '')
            if not variant_id:
                errors.append(f'{family_path}: skipped variant missing id')
                continue
            if not reason:
                errors.append(f'{family_path}.{variant_id}: skipped variant missing reason')
            skipped_ids.append(variant_id)
        duplicate_executed = sorted({item for item in executed_ids if executed_ids.count(item) > 1})
        duplicate_skipped = sorted({item for item in skipped_ids if skipped_ids.count(item) > 1})
        for variant_id in duplicate_executed:
            errors.append(f'{family_path}: duplicate executed variant {variant_id}')
        for variant_id in duplicate_skipped:
            errors.append(f'{family_path}: duplicate skipped variant {variant_id}')
        executed_set = set(executed_ids)
        skipped_set = set(skipped_ids)
        both = sorted(executed_set & skipped_set)
        for variant_id in both:
            errors.append(f'{family_path}: variant appears in both executed and skipped: {variant_id}')
        observed = executed_set | skipped_set
        if catalog_variants:
            missing = sorted(catalog_variants - observed)
            unknown = sorted(observed - catalog_variants)
            for variant_id in missing:
                errors.append(f'{family_path}: catalog variant missing from coverage: {variant_id}')
            for variant_id in unknown:
                msg = f'{family_path}: unknown variant not in catalog: {variant_id}'
                if allow_unknown_variants:
                    warnings.append(msg)
                else:
                    errors.append(msg)
        calculated['variants_executed'] += len(executed_ids)
        calculated['variants_skipped'] += len(skipped_ids)
        calculated['variants_planned'] += len(executed_ids) + len(skipped_ids)
    summary = block.get('summary')
    if not isinstance(summary, dict):
        errors.append(f'{block_path}: summary must be an object')
        summary = {}
    for key, expected in calculated.items():
        value = _mutation_int(summary.get(key))
        if value is None:
            errors.append(f'{block_path}.summary.{key}: must be an integer')
        elif value != expected:
            errors.append(f'{block_path}.summary.{key}: expected {expected}, got {value}')
    return {'path': block_path, 'module_id': module_id, 'local_name': local_name, 'status': 'fail' if errors else 'pass', 'errors': errors, 'warnings': warnings, 'summary': summary}

def _validate_mutation_artifact(path: Path, catalog: dict[str, dict[str, Any]], allow_missing: bool, allow_unknown_variants: bool) -> dict[str, Any]:
    errors = []
    warnings = []
    blocks = []
    try:
        data = read_json(path, {})
    except Exception as exc:
        return {'path': rel(path), 'status': 'fail', 'errors': [f'invalid JSON: {exc}'], 'warnings': [], 'blocks': []}
    coverage = data.get('mutation_coverage')
    if not coverage:
        message = 'missing mutation_coverage'
        if allow_missing:
            warnings.append(message)
            return {'path': rel(path), 'status': 'pass', 'errors': [], 'warnings': warnings, 'blocks': []}
        errors.append(message)
        return {'path': rel(path), 'status': 'fail', 'errors': errors, 'warnings': warnings, 'blocks': []}
    if isinstance(coverage, dict) and isinstance(coverage.get('modules'), list):
        totals = {'variants_planned': 0, 'variants_executed': 0, 'variants_skipped': 0}
        for idx, module_block in enumerate(coverage.get('modules') or []):
            result = _validate_mutation_block(module_block, catalog, path, f'mutation_coverage.modules[{idx}]', allow_unknown_variants)
            blocks.append(result)
            summary = result.get('summary') or {}
            for key in totals:
                totals[key] += int(summary.get(key, 0) or 0)
        summary = coverage.get('summary')
        if not isinstance(summary, dict):
            errors.append('mutation_coverage.summary must be an object')
        else:
            for key, expected in totals.items():
                value = _mutation_int(summary.get(key))
                if value is None:
                    errors.append(f'mutation_coverage.summary.{key}: must be an integer')
                elif value != expected:
                    errors.append(f'mutation_coverage.summary.{key}: expected {expected}, got {value}')
    else:
        blocks.append(_validate_mutation_block(coverage, catalog, path, 'mutation_coverage', allow_unknown_variants))
    for block in blocks:
        errors.extend(block.get('errors', []))
        warnings.extend(block.get('warnings', []))
    return {'path': rel(path), 'status': 'fail' if errors else 'pass', 'errors': errors, 'warnings': warnings, 'blocks': blocks}

def _mutation_coverage_check_markdown(payload: dict[str, Any]) -> str:
    lines = ['# Mutation Coverage Check', '', f"- Generated at: `{payload['generated_at']}`", f"- Passed: `{payload['passed']}`", f"- Root: `{payload['root']}`", f"- Catalog: `{payload['mutation_catalog']}`", f"- Artifacts: `{len(payload['artifacts'])}`", '', '## Artifacts', '']
    for artifact in payload['artifacts']:
        lines.append(f"- `{artifact['path']}` status=`{artifact['status']}`")
        for error_item in artifact['errors']:
            lines.append(f'  - error: {error_item}')
        for warning_item in artifact['warnings']:
            lines.append(f'  - warning: {warning_item}')
        for block in artifact['blocks']:
            summary = block.get('summary') or {}
            lines.append(f"  - block `{block.get('module_id')}`/`{block.get('local_name')}` planned=`{summary.get('variants_planned')}` executed=`{summary.get('variants_executed')}` skipped=`{summary.get('variants_skipped')}` status=`{block.get('status')}`")
    return '\n'.join(lines).rstrip() + '\n'
