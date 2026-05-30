"""Atomic JSON/YAML/JSONL persistence. Writes go through a temp file + os.replace
so a crash mid-write can never leave a half-written ledger."""
import json


def test_json_round_trip(h, tmp_path):
    p = tmp_path / "a.json"
    h.write_json(p, {"k": [1, 2, 3], "nested": {"x": True}})
    assert h.read_json(p, None) == {"k": [1, 2, 3], "nested": {"x": True}}


def test_read_json_missing_returns_default(h, tmp_path):
    assert h.read_json(tmp_path / "nope.json", {"d": 1}) == {"d": 1}


def test_jsonl_round_trip(h, tmp_path):
    p = tmp_path / "rows.jsonl"
    rows = [{"a": 1}, {"b": 2}]
    h.write_jsonl(p, rows)
    assert h.read_jsonl(p) == rows


def test_jsonl_skips_blank_and_corrupt_lines(h, tmp_path):
    p = tmp_path / "rows.jsonl"
    p.write_text('{"a": 1}\n\nnot json\n{"b": 2}\n', encoding="utf-8")
    assert h.read_jsonl(p) == [{"a": 1}, {"b": 2}]


def test_jsonl_missing_returns_empty(h, tmp_path):
    assert h.read_jsonl(tmp_path / "nope.jsonl") == []


def test_yaml_round_trip(h, tmp_path):
    p = tmp_path / "c.yaml"
    data = {"candidates": [{"id": "C1", "cwe": "CWE-918"}]}
    h.dump_yaml(data, p)
    assert h.load_yaml(p) == data


def test_write_json_leaves_no_tmp_file(h, tmp_path):
    h.write_json(tmp_path / "x.json", {"a": 1})
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == []


def test_write_json_overwrite_is_atomic_replace(h, tmp_path):
    p = tmp_path / "x.json"
    h.write_json(p, {"v": 1})
    h.write_json(p, {"v": 2})
    assert h.read_json(p, None) == {"v": 2}
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_text_trailing_newline(h, tmp_path):
    p = tmp_path / "n.md"
    h.write_text(p, "line")
    assert p.read_text(encoding="utf-8") == "line"


def test_write_json_creates_parent_dirs(h, tmp_path):
    p = tmp_path / "deep" / "nested" / "x.json"
    h.write_json(p, {"ok": True})
    assert json.loads(p.read_text(encoding="utf-8")) == {"ok": True}
