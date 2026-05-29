# Harness Mutation Coverage Validator - 2026-05-26

## Purpose

`mutation-plan` describes what a target adapter should test. Runtime
`mutation_coverage` proves what actually executed or was skipped. The
`mutation-coverage-check` command validates that runtime evidence in a
target-agnostic way.

## Command

```sh
.venv-vapt/bin/python vapt/harness/harness.py mutation-coverage-check <run-or-test-dir> --fail
```

Useful options:

- `--allow-missing`: treat legacy artifacts without `mutation_coverage` as
  warnings instead of failures.
- `--allow-unknown-variants`: warn instead of fail when an artifact names a
  variant outside `vapt/harness/config/mutation_catalog.yaml`.
- `--out <path>`: write JSON or Markdown validation output.

## Validation Rules

The command checks:

- `mutation_coverage` exists unless `--allow-missing` is set.
- module-level coverage includes `module_id`, `local_name`, `families`, and
  `summary`.
- family IDs exist in `vapt/harness/config/mutation_catalog.yaml`.
- every catalog variant for an emitted family appears exactly once across
  `variants_executed` or `variants_skipped`.
- skipped variants include a machine-readable reason.
- summary counts match calculated counts.
- campaign-level roll-up counts match module block totals.

The command does not reference target-specific names, endpoints, files, or
objects. It validates only the generic catalog-shaped contract.

## Validation Performed

Passing artifact:

```sh
.venv-vapt/bin/python vapt/harness/harness.py mutation-coverage-check \
  vapt/bug_bounties/grafana-oss/tests/mutation-enforcement-smoke-orchestrator \
  --fail
```

Expected failure for legacy run without mutation evidence:

```sh
.venv-vapt/bin/python vapt/harness/harness.py mutation-coverage-check \
  vapt/bug_bounties/grafana-oss/runs/grafana-oss/2026-05-26-campaign-2 \
  --fail
```

That legacy run exits `2` because its campaign and module JSON files predate
runtime `mutation_coverage`.

Generated target-local report:

- `vapt/bug_bounties/grafana-oss/docs/MUTATION_COVERAGE_CHECK_2026-05-26.md`
