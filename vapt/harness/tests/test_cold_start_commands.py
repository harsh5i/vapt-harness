"""Smoke tests for the cold-start command surface in ONBOARDING.md.

Two regressions slipped past the unit suite after the strangler-fig
decomposition (commit 6e6eb6c):

  * `discovery-list` → `helpers._load_watch_module` called
    `_h.importlib.import_module(...)`; the harness module has no `importlib`
    attribute, so the command exploded on first use.
  * `orient` → `helpers._recommendation_verb` called `shlex.split(...)` without
    `import shlex` at module top.

Neither failure was visible to the unit suite because no test exercised these
operator entrypoints end-to-end. This module exists so any future regression in
a command an operator is expected to run during cold-start surfaces
immediately.
"""
from __future__ import annotations

import argparse

import pytest


def _run(h, argv):
    parser = h.build_parser()
    args = parser.parse_args(argv)
    args.func(args)


def test_tools_capability(h, capsys):
    _run(h, ["tools-capability", "--json"])
    captured = capsys.readouterr()
    assert captured.out, "tools-capability emitted nothing"


def test_tool_health(h, capsys):
    _run(h, ["tool-health", "--json"])
    captured = capsys.readouterr()
    assert captured.out, "tool-health emitted nothing"


def test_discovery_list(h, capsys):
    """Regression for `_h.importlib.import_module` bug."""
    _run(h, ["discovery-list"])
    # Empty output is fine; the regression is an ImportError / AttributeError
    # before the command reaches its output stage.


def test_orient_against_fixture(h, make_run, capsys):
    """Regression for missing `import shlex` in helpers.py.

    `orient` reaches `_recommendation_verb` which calls `shlex.split` on the
    recommended command. Before the fix this raised NameError on first use
    against any run dir.
    """
    run_dir = make_run(candidates=[])
    _run(h, ["orient", str(run_dir), "--json"])
    captured = capsys.readouterr()
    assert captured.out, "orient emitted nothing"


def test_commands_manifest(h, capsys):
    """`commands` exposes the machine-readable manifest the operator may grep
    for available subcommands during cold-start."""
    _run(h, ["commands"])
    captured = capsys.readouterr()
    assert captured.out, "commands emitted nothing"


def test_weights_show(h, capsys):
    """Cold-start often inspects scoring weights to understand the current
    bias of `outcome-tune`."""
    _run(h, ["weights", "show"])
    captured = capsys.readouterr()
    assert captured.out, "weights show emitted nothing"


@pytest.mark.parametrize(
    "subcommand",
    [
        "tools-capability",
        "tool-health",
        "discovery-list",
        "orient",
        "submit",
        "weights",
        "commands",
        "next-action",
        "loop-integrity-check",
        "intent-ordering-check",
    ],
)
def test_subcommand_help_loads(h, subcommand):
    """Every cold-start-relevant subcommand must at least register cleanly.

    Catches import-time failures during parser construction (the failure mode
    we missed for `_h.importlib` / `shlex`).
    """
    parser = h.build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args([subcommand, "--help"])
    # argparse exits 0 on --help.
    assert excinfo.value.code == 0
