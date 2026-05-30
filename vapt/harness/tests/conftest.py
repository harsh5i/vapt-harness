"""Shared test fixtures for the harness unit suite.

Puts the harness package dir on sys.path so `import harness` and
`from gates.authorization import ...` both resolve, and provides a helper to
build a throwaway run directory (target.yaml + state.json + candidates.yaml)
for loop/gate tests without touching the real engagements tree.
"""
import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parents[1]
if str(HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_DIR))

import harness  # noqa: E402


@pytest.fixture
def h():
    return harness


def _all_stages(state):
    state.setdefault("stages", {})
    for stage in ("prepare", "map", "source_graph", "semantic_graph"):
        state["stages"].setdefault(stage, {"completed_at": "2026-05-30T00:00:00"})
    return state


@pytest.fixture
def make_run(tmp_path):
    """Build a run dir. `stages_complete=True` stamps all setup stages so
    recommend_next_action moves straight to candidate triage."""

    def _make(candidates=None, *, target=None, stages_complete=True, target_id="demo"):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        tgt = target or {"id": target_id, "name": target_id, "repo_url": ""}
        harness.dump_yaml(tgt, run_dir / "target.yaml")
        state = {"target_id": target_id, "run_id": "test"}
        if stages_complete:
            _all_stages(state)
        harness.write_json(run_dir / "state.json", state)
        data = {"candidates": [harness._normalize_candidate(c) for c in (candidates or [])]}
        harness.dump_yaml(data, run_dir / "candidates.yaml")
        return run_dir

    return _make
